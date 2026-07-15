import {
    memo,
    useEffect,
    useMemo,
    useRef,
    useState,
    type CSSProperties,
} from 'react';
import {
    accountKeyFromPublicKey,
    encodeSignedTransaction,
    encodeTransactionBatch,
    parseAccountKeyHex,
    parseU64,
    toHex,
} from './codec';
import { submittedTransactionHistoryKey } from './historyKey';
import { type ObservedBlock, subscribeBlocks } from './indexer';
import {
    fetchAccount,
    submitTransactions,
    type AccountView,
    type TxStatus,
} from './mempool';
import {
    fetchAccountTransactionsPage,
    fetchAndVerifyAccountProof,
    fetchAndVerifyTransactionProof,
    fetchAndVerifyTransactionRowProof,
    fetchLatestProofTarget,
    type AccountActivityMode,
    type AccountTransactionRow,
    type LatestProofTarget,
    type VerifiedAccountProof,
    type VerifiedTransactionProof,
} from './qmdb';
import {
    consumeNonce,
    emptyNonceState,
    mergeNonceStates,
    nextAvailableNonce,
    nonceStatesEqual,
    type NonceState,
} from './nonce';
import {
    isMissingAccountProofError,
    isRetryableAccountProofError,
    isRetryableProofError,
} from './proofRetry';
import {
    clearSession,
    createWallet,
    restoreWalletSession,
    signInWithPasskey,
    type ActiveWallet,
} from './wallet';

/** Most recent finalized blocks to keep for the centered throughput histogram. */
const HISTOGRAM_MAX_COLUMNS = 180;
const BLOCK_LOG_MAX = 80;
const HISTOGRAM_MIN_COLUMNS = 48;
const HISTOGRAM_INITIAL_COLUMNS = 120;
const HISTOGRAM_HEIGHT = 18;
const HISTOGRAM_MAX_ROWS = 200;
const HISTOGRAM_MIN_ROWS = 8;
const BLOCK_GLYPHS = ' ▁▂▃▄▅▆▇█';
const BRAILLE_SPINNER = ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏'];
const LIVE_STATUS_TEXT = '>>> live';
const LIVE_STATUS_SYMBOLS = [...LIVE_STATUS_TEXT];
const BLOCK_FLUSH_INTERVAL_MS = 250;

type Status =
    | { kind: 'connecting' }
    | { kind: 'live' }
    | { kind: 'error'; message: string };

// The explorer subscribes to `metadata-indexer` for block rows and queries
// `qmdb-indexer` for submitted-transaction proofs. Defaults match
// `bin/deploy/src/local.rs`; override the VITE_* URLs for non-default deployments.
const DEFAULT_SQL_URL = 'http://127.0.0.1:8091';
const DEFAULT_QMDB_URL = 'http://127.0.0.1:8092';
const DEFAULT_STORE_URL = 'http://127.0.0.1:8090';
const DEFAULT_MEMPOOL_URL = 'http://127.0.0.1:8080';

const indexerUrl = import.meta.env.VITE_SQL_URL ?? DEFAULT_SQL_URL;
const qmdbUrl = import.meta.env.VITE_QMDB_URL ?? DEFAULT_QMDB_URL;
const storeUrl = import.meta.env.VITE_STORE_URL ?? DEFAULT_STORE_URL;
const simplexVerificationMaterial = import.meta.env.VITE_SIMPLEX_VERIFICATION_MATERIAL ?? '';
const mempoolUrl = import.meta.env.VITE_MEMPOOL_URL ?? DEFAULT_MEMPOOL_URL;
const verifyCertificates = parseBooleanEnv(import.meta.env.VITE_VERIFY_CERTIFICATES, true);

function parseBooleanEnv(value: unknown, fallback: boolean): boolean {
    if (typeof value !== 'string') return fallback;
    if (/^(0|false|off|no)$/i.test(value)) return false;
    if (/^(1|true|on|yes)$/i.test(value)) return true;
    return fallback;
}

interface SubmittedTransaction {
    readonly sender: string;
    readonly digest: string;
    readonly to: string;
    readonly value: string;
    readonly nonce: string;
    readonly submittedAt: number;
    readonly finalizedInMs: number | null;
    readonly status: 'pending' | 'finalized' | 'partially_finalized' | 'dropped' | 'error';
    readonly detail: string;
    readonly finalizedHeight: number | null;
    readonly certificate: BlockCertificateState;
    readonly proof: TransactionProofState;
}

type BlockCertificateState =
    | { readonly status: 'waiting'; readonly detail: string }
    | { readonly status: 'fetching'; readonly detail: string }
    | {
          readonly status: 'verified';
          readonly detail: string;
          readonly height: string;
          readonly view: string;
      }
    | { readonly status: 'error'; readonly detail: string };

const WAITING_FINALIZATION_CERTIFICATE = {
    status: 'waiting',
    detail: 'waiting for finalization',
} satisfies BlockCertificateState;
const WAITING_BLOCK_CERTIFICATE = {
    status: 'waiting',
    detail: 'waiting for block certificate',
} satisfies BlockCertificateState;

type TransactionProofState =
    | { readonly status: 'waiting'; readonly detail: string }
    | { readonly status: 'fetching'; readonly detail: string }
    | {
          readonly status: 'verified';
          readonly detail: string;
          readonly location: string;
          readonly tip: string;
          readonly proofSizeBytes: number;
      }
    | { readonly status: 'error'; readonly detail: string };

type AccountProofState =
    | { readonly status: 'waiting'; readonly detail: string }
    | { readonly status: 'fetching'; readonly detail: string }
    | { readonly status: 'missing'; readonly detail: string }
    | ({
          readonly status: 'verified';
          readonly detail: string;
      } & VerifiedAccountProof)
    | { readonly status: 'error'; readonly detail: string };

interface AccountTxWithProof {
    readonly row: AccountTransactionRow;
    readonly proof: TransactionProofState;
}

interface ObservedRateWindow {
    readonly firstBlockAt: number | null;
    readonly latestBlockAt: number | null;
}

export default function App() {
    const [blocks, setBlocks] = useState<ObservedBlock[]>([]);
    // Cumulative counter across every block observed on the stream. Tracked
    // independently of `blocks` so the rate keeps climbing when older entries
    // roll off the histogram buffer.
    const [totalTxObserved, setTotalTxObserved] = useState(0);
    const [totalBlocksObserved, setTotalBlocksObserved] = useState(0);
    const [observedRateWindow, setObservedRateWindow] = useState<ObservedRateWindow>({
        firstBlockAt: null,
        latestBlockAt: null,
    });
    const [status, setStatus] = useState<Status>({ kind: 'connecting' });
    const [isWalletOpen, setIsWalletOpen] = useState(false);
    const [isSearchOpen, setIsSearchOpen] = useState(false);
    const [wallet, setWallet] = useState<ActiveWallet | null>(null);
    const [walletAccountKey, setWalletAccountKey] = useState<string | null>(null);
    const [walletMessage, setWalletMessage] = useState('sign in or create a wallet');
    const [account, setAccount] = useState<AccountView | null>(null);
    const [accountMessage, setAccountMessage] = useState('account metadata unavailable');
    const [toKey, setToKey] = useState('');
    const [value, setValue] = useState('1');
    const [nonce, setNonce] = useState('0');
    const [submitMessage, setSubmitMessage] = useState('');
    const [pendingSubmissionCount, setPendingSubmissionCount] = useState(0);
    const [history, setHistory] = useState<SubmittedTransaction[]>([]);
    const [loadedHistoryKey, setLoadedHistoryKey] = useState<string | null>(null);
    const [lookupAccount, setLookupAccount] = useState(() => accountFromLocation());
    const [accountInput, setAccountInput] = useState(() => accountFromLocation());
    const [accountTarget, setAccountTarget] = useState<LatestProofTarget | null>(null);
    const [accountProof, setAccountProof] = useState<AccountProofState>({
        status: 'waiting',
        detail: 'enter an account',
    });
    const [accountTransactions, setAccountTransactions] = useState<AccountTxWithProof[]>([]);
    const [accountActivityError, setAccountActivityError] = useState('');
    const [accountActivityMode, setAccountActivityMode] = useState<AccountActivityMode>('all');
    const [accountCursorStack, setAccountCursorStack] = useState<(Uint8Array | null)[]>([null]);
    const [accountNextCursor, setAccountNextCursor] = useState<Uint8Array | null>(null);
    const [searchMessage, setSearchMessage] = useState('');
    const [copyToast, setCopyToast] = useState('');
    const nextNonceRef = useRef<NonceState>(emptyNonceState());
    const pendingBlocksRef = useRef<ObservedBlock[]>([]);
    const blockFlushTimeoutRef = useRef<number | null>(null);
    const copyToastTimeoutRef = useRef<number | null>(null);
    const isSubmitting = pendingSubmissionCount > 0;
    const isWalletBusy =
        walletMessage === 'opening passkey prompt' ||
        accountMessage === 'loading account metadata' ||
        isSubmitting;
    const spinner = useBrailleSpinner(status.kind === 'connecting' || isWalletBusy);
    const signedInAccountKey = walletAccountKey;
    const historyKey = submittedTransactionHistoryKey(
        {
            indexerUrl,
            qmdbUrl,
            storeUrl,
            mempoolUrl,
            simplexVerificationMaterial,
        },
        signedInAccountKey,
    );
    const currentAccountCursor = accountCursorStack[accountCursorStack.length - 1] ?? null;

    const setLocalNonceState = (nextNonce: NonceState) => {
        nextNonceRef.current = nextNonce;
        setNonce(nextAvailableNonce(nextNonce).toString());
    };

    const mergeLocalNonceState = (nextNonce: NonceState) => {
        setLocalNonceState(mergeNonceStates(nextNonceRef.current, nextNonce));
    };

    const queueObservedBlocks = (nextBlocks: readonly ObservedBlock[]) => {
        if (nextBlocks.length === 0) return;

        pendingBlocksRef.current.push(...nextBlocks);
        if (blockFlushTimeoutRef.current !== null) return;

        blockFlushTimeoutRef.current = window.setTimeout(() => {
            blockFlushTimeoutRef.current = null;
            const flushed = pendingBlocksRef.current;
            pendingBlocksRef.current = [];
            if (flushed.length === 0) return;

            setBlocks((current) => upsertBoundedBatch(flushed, current));
            setTotalTxObserved(
                (current) =>
                    current + flushed.reduce((total, block) => total + block.txCount, 0),
            );
            setTotalBlocksObserved((current) => current + flushed.length);
            setObservedRateWindow((current) => ({
                firstBlockAt: current.firstBlockAt ?? flushed[0].arrivedAt,
                latestBlockAt: flushed[flushed.length - 1].arrivedAt,
            }));
            setStatus((current) => (current.kind === 'live' ? current : { kind: 'live' }));
        }, BLOCK_FLUSH_INTERVAL_MS);
    };

    useEffect(() => {
        const restoredWallet = restoreWalletSession();
        if (!restoredWallet) return;
        setWallet(restoredWallet);
        setWalletMessage('signed in');
    }, []);

    useEffect(() => {
        const controller = new AbortController();
        let cancelled = false;

        (async () => {
            try {
                for await (const block of subscribeBlocks(indexerUrl, {
                    signal: controller.signal,
                    onNetworkError: (message) =>
                        setStatus({ kind: 'error', message: `network error: ${message}` }),
                    onReconnect: () => setStatus({ kind: 'connecting' }),
                })) {
                    if (cancelled) return;
                    queueObservedBlocks([block]);
                }
            } catch (error) {
                if (cancelled || controller.signal.aborted) return;
                setStatus({
                    kind: 'error',
                    message: error instanceof Error ? error.message : String(error),
                });
            }
        })();

        return () => {
            cancelled = true;
            controller.abort();
        };
    }, []);

    useEffect(() => {
        setHistory(historyKey === null ? [] : readHistory(historyKey));
        setLoadedHistoryKey(historyKey);
    }, [historyKey]);

    useEffect(() => {
        if (!wallet) {
            setWalletAccountKey(null);
            return;
        }

        let cancelled = false;
        accountKeyFromPublicKey(wallet.publicKey)
            .then((accountKey) => {
                if (cancelled) return;
                setWalletAccountKey(toHex(accountKey));
            })
            .catch((error) => {
                if (cancelled) return;
                setWalletAccountKey(null);
                setWalletMessage(error instanceof Error ? error.message : String(error));
            });

        return () => {
            cancelled = true;
        };
    }, [wallet]);

    useEffect(() => {
        if (historyKey === null) return;
        if (loadedHistoryKey !== historyKey) return;
        writeHistory(historyKey, history);
    }, [historyKey, loadedHistoryKey, history]);

    useEffect(() => {
        const onPopState = () => {
            const next = accountFromLocation();
            setLookupAccount(next);
            setAccountInput(next);
            setAccountCursorStack([null]);
        };
        window.addEventListener('popstate', onPopState);
        return () => window.removeEventListener('popstate', onPopState);
    }, []);

    useEffect(() => {
        if (!lookupAccount) {
            setAccountTarget(null);
            setAccountProof({ status: 'waiting', detail: 'enter an account' });
            return;
        }

        const controller = new AbortController();
        setAccountTarget(null);
        setAccountProof({ status: 'fetching', detail: 'fetching account proof' });

        retryAccountPageStep(async () => {
            const target = await fetchLatestProofTarget({
                storeUrl,
                simplexVerificationMaterial,
                signal: controller.signal,
            });
            try {
                const proof = await fetchAndVerifyAccountProof({
                    qmdbUrl,
                    sqlUrl: indexerUrl,
                    account: lookupAccount,
                    target,
                    signal: controller.signal,
                });
                return { target, proof };
            } catch (error) {
                const detail = error instanceof Error ? error.message : String(error);
                if (isMissingAccountProofError(detail)) {
                    return { target, proof: null };
                }
                throw error;
            }
        }, controller.signal)
            .then(({ target, proof }) => {
                if (controller.signal.aborted) return;
                if (proof === null) {
                    setAccountProof({ status: 'missing', detail: 'not yet exists' });
                    setAccountTarget(target);
                    return;
                }
                setAccountProof({
                    status: 'verified',
                    detail: `verified at height ${target.height.toString()}`,
                    ...proof,
                });
                setAccountTarget(target);
            })
            .catch((error) => {
                if (controller.signal.aborted) return;
                setAccountProof({
                    status: 'error',
                    detail: error instanceof Error ? error.message : String(error),
                });
            });

        return () => controller.abort();
    }, [lookupAccount]);

    useEffect(() => {
        if (!lookupAccount) {
            setAccountTransactions([]);
            setAccountNextCursor(null);
            setAccountActivityError('');
            return;
        }

        const controller = new AbortController();
        setAccountTransactions([]);
        setAccountNextCursor(null);
        setAccountActivityError('');

        fetchAccountTransactionsPage({
            sqlUrl: indexerUrl,
            account: lookupAccount,
            cursor: currentAccountCursor,
            mode: accountActivityMode,
        })
            .then(async (page) => {
                if (controller.signal.aborted) return;
                setAccountNextCursor(page.nextCursor);
                setAccountTransactions(page.rows.map((row) => ({
                    row,
                    proof: { status: 'waiting', detail: 'waiting for latest finalization' },
                })));
                if (!accountTarget) return;

                setAccountTransactions(page.rows.map((row) => ({
                    row,
                    proof: { status: 'fetching', detail: 'fetching transaction proof' },
                })));
                const results = await Promise.allSettled(
                    page.rows.map((row) =>
                        retryAccountPageStep(() => fetchAndVerifyTransactionRowProof({
                            qmdbUrl,
                            sqlUrl: indexerUrl,
                            row,
                            target: accountTarget,
                            signal: controller.signal,
                        }), controller.signal),
                    ),
                );
                if (controller.signal.aborted) return;
                setAccountTransactions((current) =>
                    current.map((entry, index) => {
                        const result = results[index];
                        if (!result) return entry;
                        if (result.status === 'fulfilled') {
                            return { ...entry, proof: verifiedProofState(result.value) };
                        }
                        const detail = result.reason instanceof Error ? result.reason.message : String(result.reason);
                        return { ...entry, proof: { status: 'error', detail } };
                    }),
                );
            })
            .catch((error) => {
                if (controller.signal.aborted) return;
                setAccountTransactions([]);
                setAccountNextCursor(null);
                setAccountActivityError(error instanceof Error ? error.message : String(error));
            });

        return () => controller.abort();
    }, [lookupAccount, currentAccountCursor, accountActivityMode, accountTarget]);

    useEffect(() => {
        const signedInSender = signedInAccountKey;
        if (hasFetchingProof(history, signedInSender)) return;

        const tx = history.find((entry) => shouldFetchTransactionProof(entry, signedInSender));
        if (!tx) return;

        setHistory((current) =>
            updateTransactionProof(
                tx.digest,
                { status: 'fetching', detail: 'fetching QMDB proof' },
                current,
            ),
        );
        fetchAndVerifyTransactionProof({
            qmdbUrl,
            storeUrl,
            sqlUrl: indexerUrl,
            simplexVerificationMaterial,
            digest: tx.digest,
            height: tx.finalizedHeight,
            onFinalizationVerified: (target) => {
                const certificate = verifiedBlockCertificateState(target);
                setHistory((current) =>
                    updateBlockCertificateByHeight(Number(target.height), certificate, current),
                );
            },
        })
            .then((proof) => {
                const certificate = verifiedBlockCertificateState(proof);
                setHistory((current) =>
                    updateBlockCertificateByHeight(
                        Number(proof.height),
                        certificate,
                        updateTransactionProof(tx.digest, verifiedProofState(proof), current),
                    ),
                );
            })
            .catch((error) => {
                const detail = error instanceof Error ? error.message : String(error);
                if (isRetryableProofError(detail)) {
                    setHistory((current) =>
                        updateTransactionProof(
                            tx.digest,
                            { status: 'fetching', detail: 'waiting for indexer metadata' },
                            current,
                        ),
                    );
                    window.setTimeout(() => {
                        setHistory((current) =>
                            updateTransactionProof(
                                tx.digest,
                                { status: 'waiting', detail: 'waiting for QMDB proof' },
                                current,
                            ),
                        );
                    }, 1_000);
                    return;
                }
                setHistory((current) =>
                    updateTransactionProof(
                        tx.digest,
                        {
                            status: 'error',
                            detail,
                        },
                        current,
                    ),
                );
            });
    }, [history, signedInAccountKey]);

    useEffect(() => {
        return () => {
            if (blockFlushTimeoutRef.current !== null) {
                window.clearTimeout(blockFlushTimeoutRef.current);
            }
            if (copyToastTimeoutRef.current !== null) {
                window.clearTimeout(copyToastTimeoutRef.current);
            }
        };
    }, []);

    useEffect(() => {
        if (!wallet) {
            setAccount(null);
            setLocalNonceState(emptyNonceState());
            setAccountMessage('account metadata unavailable');
            return;
        }

        let cancelled = false;
        setAccountMessage('loading account metadata');

        fetchAccount(mempoolUrl, wallet.publicKeyHex)
            .then((nextAccount) => {
                if (cancelled) return;
                setAccount(nextAccount);
                mergeLocalNonceState(accountNonceState(nextAccount));
                setAccountMessage(
                    nextAccount
                        ? 'committed account loaded'
                        : 'no committed account yet; default balance applies',
                );
            })
            .catch((error) => {
                if (cancelled) return;
                setAccount(null);
                setAccountMessage(error instanceof Error ? error.message : String(error));
            });

        return () => {
            cancelled = true;
        };
    }, [wallet]);

    const refreshAccount = async () => {
        if (!wallet) return;
        setAccountMessage('loading account metadata');
        try {
            const nextAccount = await fetchAccount(mempoolUrl, wallet.publicKeyHex);
            setAccount(nextAccount);
            mergeLocalNonceState(accountNonceState(nextAccount));
            setAccountMessage(
                nextAccount ? 'committed account loaded' : 'no committed account yet; default balance applies',
            );
        } catch (error) {
            setAccountMessage(error instanceof Error ? error.message : String(error));
        }
    };

    const handleCreateWallet = async () => {
        setWalletMessage('opening passkey prompt');
        try {
            const nextWallet = await createWallet();
            setWallet(nextWallet);
            setWalletMessage('signed in');
        } catch (error) {
            setWalletMessage(error instanceof Error ? error.message : String(error));
        }
    };

    const handleSignIn = async () => {
        setWalletMessage('opening passkey prompt');
        try {
            const nextWallet = await signInWithPasskey();
            setWallet(nextWallet);
            setWalletMessage('signed in');
        } catch (error) {
            setWalletMessage(error instanceof Error ? error.message : String(error));
        }
    };

    const handleSignOut = () => {
        clearSession();
        setWallet(null);
        setWalletMessage('signed out');
    };

    const copyValue = async (value: string) => {
        try {
            await navigator.clipboard.writeText(value);
            if (copyToastTimeoutRef.current !== null) {
                window.clearTimeout(copyToastTimeoutRef.current);
            }

            setCopyToast(`copied "${value}" to clipboard`);
            copyToastTimeoutRef.current = window.setTimeout(() => {
                setCopyToast('');
                copyToastTimeoutRef.current = null;
            }, 1_400);
        } catch (error) {
            if (copyToastTimeoutRef.current !== null) {
                window.clearTimeout(copyToastTimeoutRef.current);
            }
            setCopyToast(error instanceof Error ? error.message : String(error));
            copyToastTimeoutRef.current = window.setTimeout(() => {
                setCopyToast('');
                copyToastTimeoutRef.current = null;
            }, 1_400);
        }
    };

    const openAccountPage = (value: string): boolean => {
        const normalized = normalizeAccountInput(value);
        if (!normalized) return false;

        setSearchMessage('');
        setLookupAccount(normalized);
        setAccountInput(normalized);
        setAccountCursorStack([null]);
        const url = new URL(window.location.href);
        url.searchParams.set('account', normalized);
        const nextLocation = `${url.pathname}${url.search}${url.hash}`;
        if (nextLocation !== `${window.location.pathname}${window.location.search}${window.location.hash}`) {
            window.history.pushState(null, '', nextLocation);
        }
        setIsWalletOpen(false);
        setIsSearchOpen(false);
        return true;
    };

    const submitAccountLookup = () => {
        if (openAccountPage(accountInput)) return;
        setSearchMessage('expected a 32-byte address');
    };

    const clearAccountLookup = () => {
        setLookupAccount('');
        setAccountInput('');
        setAccountCursorStack([null]);
        setSearchMessage('');
        const url = new URL(window.location.href);
        url.searchParams.delete('account');
        const nextLocation = `${url.pathname}${url.search}${url.hash}`;
        if (nextLocation !== `${window.location.pathname}${window.location.search}${window.location.hash}`) {
            window.history.pushState(null, '', nextLocation);
        }
    };

    const nextAccountPage = () => {
        if (!accountNextCursor) return;
        setAccountCursorStack((current) => [...current, accountNextCursor]);
    };

    const previousAccountPage = () => {
        setAccountCursorStack((current) => current.length <= 1 ? current : current.slice(0, -1));
    };

    const changeAccountActivityMode = (mode: AccountActivityMode) => {
        setAccountActivityMode(mode);
        setAccountCursorStack([null]);
        setAccountNextCursor(null);
    };

    const clearSubmittedTransactionHistory = () => {
        setHistory([]);
        if (historyKey !== null) {
            clearHistory(historyKey);
        }
    };

    const submitTransfer = async () => {
        if (!wallet) return;
        if (!walletAccountKey) {
            setSubmitMessage('loading account address');
            return;
        }

        setPendingSubmissionCount((count) => count + 1);
        setSubmitMessage('forming transaction');
        let reservation: { previous: NonceState; next: NonceState } | null = null;
        try {
            const parsedToKey = parseAccountKeyHex(toKey);
            const parsedValue = parseU64(value, 'value');
            const previousNonce = nextNonceRef.current;
            const parsedNonce = nextAvailableNonce(previousNonce);
            const nextNonce = consumeNonce(previousNonce, parsedNonce);
            if (nextNonce === null) {
                throw new Error('nonce must fit in u64');
            }
            setLocalNonceState(nextNonce);
            reservation = { previous: previousNonce, next: nextNonce };

            const encoded = await encodeSignedTransaction(
                {
                    senderPublicKey: wallet.publicKey,
                    toAccountKey: parsedToKey,
                    value: parsedValue,
                    nonce: parsedNonce,
                },
                wallet.sign,
            );
            const pending: SubmittedTransaction = {
                sender: walletAccountKey,
                digest: encoded.digestHex,
                to: toHex(parsedToKey),
                value: parsedValue.toString(),
                nonce: parsedNonce.toString(),
                submittedAt: Date.now(),
                finalizedInMs: null,
                status: 'pending',
                detail: 'submitted to mempool',
                finalizedHeight: null,
                certificate: { status: 'waiting', detail: 'waiting for finalization' },
                proof: { status: 'waiting', detail: 'waiting for finalization' },
            };
            setHistory((current) => prependTransaction(pending, current));
            setSubmitMessage('submitting');

            const txStatus = await submitTransactions(mempoolUrl, encodeTransactionBatch([encoded.bytes]));
            const detail = formatTxStatus(txStatus);
            setHistory((current) =>
                updateTransactionStatus(
                    encoded.digestHex,
                    txStatus,
                    detail,
                    current,
                ),
            );
            setSubmitMessage('');
            await refreshAccount();
        } catch (error) {
            if (reservation !== null && nonceStatesEqual(nextNonceRef.current, reservation.next)) {
                setLocalNonceState(reservation.previous);
            }
            setSubmitMessage(error instanceof Error ? error.message : String(error));
        } finally {
            setPendingSubmissionCount((count) => Math.max(0, count - 1));
        }
    };

    return (
        <div className="app">
            <div className="app__container">
                <header className="app__header">
                    <h1 className="app__title">
                        <span className="accent">constantinople</span> /{' '}
                        <button
                            className="app__title-link"
                            onClick={clearAccountLookup}
                            type="button"
                        >
                            explorer
                        </button>
                    </h1>
                    <div className="app__header-actions">
                        <StatusBadge status={status} spinner={spinner} />
                        <span className="app__header-separator" aria-hidden="true">
                            ⬝
                        </span>
                        <button className="wallet-trigger" onClick={() => setIsSearchOpen(true)}>
                            search
                        </button>
                        <span className="app__header-separator" aria-hidden="true">
                            ⬝
                        </span>
                        <button className="wallet-trigger" onClick={() => setIsWalletOpen(true)}>
                            wallet{walletAccountKey && <span className="wallet-trigger__key"> {shortHex(walletAccountKey)}</span>}
                        </button>
                    </div>
                </header>
                <main className="app__main app__main--minimal">
                    <section className="explorer-stage" aria-label="live transaction throughput">
                        {lookupAccount ? (
                            <AccountPage
                                account={lookupAccount}
                                onCopy={copyValue}
                                onOpenAddress={openAccountPage}
                                pageNumber={accountCursorStack.length}
                                proof={accountProof}
                                target={accountTarget}
                                transactions={accountTransactions}
                                activityError={accountActivityError}
                                activityMode={accountActivityMode}
                                hasPrevious={accountCursorStack.length > 1}
                                hasNext={accountNextCursor !== null}
                                onActivityModeChange={changeAccountActivityMode}
                                onPrevious={previousAccountPage}
                                onNext={nextAccountPage}
                            />
                        ) : (
                            <>
                                <Histogram blocks={blocks} />
                                <ExplorerStats
                                    blocks={blocks}
                                    observedRateWindow={observedRateWindow}
                                    totalBlocksObserved={totalBlocksObserved}
                                    totalTxObserved={totalTxObserved}
                                />
                                <BlockLog blocks={blocks} />
                            </>
                        )}
                    </section>
                </main>
                {isWalletOpen && (
                    <WalletModal onClose={() => setIsWalletOpen(false)}>
                        <WalletPanel
                            wallet={wallet}
                            walletAccountKey={walletAccountKey}
                            walletMessage={walletMessage}
                            account={account}
                            accountMessage={accountMessage}
                            toKey={toKey}
                            value={value}
                            nonce={nonce}
                            submitMessage={submitMessage}
                            isSubmitting={isSubmitting}
                            canClearSubmittedTransactions={history.length > 0}
                            spinner={spinner}
                            onCreateWallet={handleCreateWallet}
                            onSignIn={handleSignIn}
                            onSignOut={handleSignOut}
                            onRefreshAccount={refreshAccount}
                            onClearSubmittedTransactions={clearSubmittedTransactionHistory}
                            onCopy={copyValue}
                            onToKeyChange={setToKey}
                            onValueChange={setValue}
                            onSubmit={submitTransfer}
                        />
                        <TransactionHistory
                            transactions={history}
                            signedInAccountKey={signedInAccountKey}
                            onCopy={copyValue}
                            onOpenAddress={openAccountPage}
                            verifyCertificates={verifyCertificates}
                        />
                    </WalletModal>
                )}
                {isSearchOpen && (
                    <SearchModal onClose={() => setIsSearchOpen(false)}>
                        <AccountSearchPanel
                            accountInput={accountInput}
                            message={searchMessage}
                            onAccountInputChange={(value) => {
                                setAccountInput(value);
                                setSearchMessage('');
                            }}
                            onSubmit={submitAccountLookup}
                        />
                    </SearchModal>
                )}
                {copyToast && <TerminalToast message={copyToast} />}
            </div>
        </div>
    );
}

function AccountPage({
    account,
    onCopy,
    onOpenAddress,
    pageNumber,
    proof,
    target,
    transactions,
    activityError,
    activityMode,
    hasPrevious,
    hasNext,
    onActivityModeChange,
    onPrevious,
    onNext,
}: {
    account: string;
    onCopy: (value: string) => void;
    onOpenAddress: (value: string) => void;
    pageNumber: number;
    proof: AccountProofState;
    target: LatestProofTarget | null;
    transactions: AccountTxWithProof[];
    activityError: string;
    activityMode: AccountActivityMode;
    hasPrevious: boolean;
    hasNext: boolean;
    onActivityModeChange: (mode: AccountActivityMode) => void;
    onPrevious: () => void;
    onNext: () => void;
}) {
    return (
        <section className="account-page" aria-label="account proof">
            <div className="account-page__title">
                <span>account</span>
            </div>
            <div className="account-page__line">
                <span className="account-page__prompt">address</span>
                <CopyableValue value={account} onCopy={onCopy} />
            </div>
            <div className="account-proof-grid">
                <ProofDatum label="cert" value={target ? `h${target.height.toString()} / v${target.view.toString()}` : proof.detail} />
                <ProofDatum label="block" value={target ? shortHex(bytesToHex(target.blockDigest)) : '-'} />
                <ProofDatum
                    label="state"
                    value={
                        proof.status === 'verified'
                            ? `${proof.balance.toString()} / nonce ${proof.nonce.toString()}`
                            : proof.detail
                    }
                />
                <ProofDatum
                    label="state proof"
                    value={
                        proof.status === 'verified'
                            ? `loc ${proof.location.toString()} / ${proof.proofSizeBytes}b`
                            : proof.status === 'missing'
                                ? proof.detail
                                : proof.status
                    }
                />
            </div>
            <div className="account-page__subhead">
                <span>{activityMode} tx page {pageNumber}</span>
                <div className="account-page__modes" role="tablist" aria-label="account transaction filter">
                    {(['all', 'sent', 'received'] as const).map((mode) => (
                        <button
                            key={mode}
                            className={mode === activityMode ? 'account-page__mode account-page__mode--active' : 'account-page__mode'}
                            role="tab"
                            aria-selected={mode === activityMode}
                            onClick={() => onActivityModeChange(mode)}
                            type="button"
                        >
                            {mode}
                        </button>
                    ))}
                </div>
                <div className="account-page__pager">
                    <button disabled={!hasPrevious} onClick={onPrevious}>prev</button>
                    <button disabled={!hasNext} onClick={onNext}>next</button>
                </div>
            </div>
            <div className="account-tx-list">
                {activityError && (
                    <div className="account-tx-row account-tx-row--empty">{activityError}</div>
                )}
                {!activityError && transactions.length === 0 && (
                    <div className="account-tx-row account-tx-row--empty">no transactions indexed</div>
                )}
                {transactions.map(({ row, proof: txProof }) => (
                    <div className="account-tx-row" key={`${row.height.toString()}-${row.blockIndex}`}>
                        <div className="account-tx-row__main">
                            <span className="account-tx-row__height">h{row.height.toString()}:{row.blockIndex}</span>
                            <CopyableValue value={row.digest} onCopy={onCopy} />
                            <span>from</span>
                            <AccountPageAddressValue
                                account={account}
                                value={row.direction === 'sent' ? account : row.counterparty}
                                onCopy={onCopy}
                                onOpenAddress={onOpenAddress}
                            />
                            <span>to</span>
                            <AccountPageAddressValue
                                account={account}
                                value={row.direction === 'sent' ? row.counterparty : account}
                                onCopy={onCopy}
                                onOpenAddress={onOpenAddress}
                            />
                        </div>
                        <div className="account-tx-row__meta">
                            <span>value {row.value.toString()}</span>
                            <span>nonce {row.nonce.toString()}</span>
                            <span>{txProof.status === 'verified' ? `loc ${txProof.location}` : 'loc -'}</span>
                            <span>proof</span>
                            <ProofMark proof={txProof} />
                        </div>
                    </div>
                ))}
            </div>
        </section>
    );
}

function ProofDatum({ label, value }: { label: string; value: string }) {
    return (
        <div className="account-proof-grid__cell">
            <span>{label}</span>
            <strong>{value}</strong>
        </div>
    );
}

function ProofMark({ proof }: { proof: TransactionProofState }) {
    if (proof.status === 'verified') {
        return <span className="tx-proof-check" title={proof.detail}>✓</span>;
    }
    if (proof.status === 'error') {
        return <span className="tx-proof-error" title={proof.detail}>!</span>;
    }
    return <span className="tx-proof-spinner" title={proof.detail} />;
}

function SearchModal({
    children,
    onClose,
}: {
    children: React.ReactNode;
    onClose: () => void;
}) {
    useEffect(() => {
        const closeOnEscape = (event: KeyboardEvent) => {
            if (event.key !== 'Escape') return;
            onClose();
        };
        window.addEventListener('keydown', closeOnEscape);
        return () => window.removeEventListener('keydown', closeOnEscape);
    }, [onClose]);

    return (
        <div
            className="modal"
            role="presentation"
            onMouseDown={(event) => {
                if (event.target === event.currentTarget) onClose();
            }}
        >
            <section className="modal__panel modal__panel--search" role="dialog" aria-modal="true" aria-label="account search">
                <header className="modal__header">
                    <h2>search</h2>
                    <button className="modal__close" onClick={onClose}>
                        close
                    </button>
                </header>
                {children}
            </section>
        </div>
    );
}

function AccountSearchPanel({
    accountInput,
    message,
    onAccountInputChange,
    onSubmit,
}: {
    accountInput: string;
    message: string;
    onAccountInputChange: (value: string) => void;
    onSubmit: () => void;
}) {
    return (
        <section className="account-search">
            <form
                className="account-lookup"
                onSubmit={(event) => {
                    event.preventDefault();
                    onSubmit();
                }}
            >
                <label>
                    <span>account&gt;</span>
                    <input
                        autoFocus
                        value={accountInput}
                        onChange={(event) => onAccountInputChange(event.target.value)}
                        placeholder="address"
                        spellCheck={false}
                    />
                </label>
                <button type="submit">open</button>
            </form>
            {message && <div className="account-search__message">{message}</div>}
        </section>
    );
}

function WalletModal({
    children,
    onClose,
}: {
    children: React.ReactNode;
    onClose: () => void;
}) {
    useEffect(() => {
        const closeOnEscape = (event: KeyboardEvent) => {
            if (event.key !== 'Escape') return;
            onClose();
        };
        window.addEventListener('keydown', closeOnEscape);
        return () => window.removeEventListener('keydown', closeOnEscape);
    }, [onClose]);

    return (
        <div
            className="modal"
            role="presentation"
            onMouseDown={(event) => {
                if (event.target === event.currentTarget) onClose();
            }}
        >
            <section className="modal__panel" role="dialog" aria-modal="true" aria-label="wallet">
                <header className="modal__header">
                    <h2>wallet</h2>
                    <button className="modal__close" onClick={onClose}>
                        close
                    </button>
                </header>
                {children}
            </section>
        </div>
    );
}

function WalletPanel({
    wallet,
    walletAccountKey,
    walletMessage,
    account,
    accountMessage,
    toKey,
    value,
    nonce,
    submitMessage,
    isSubmitting,
    canClearSubmittedTransactions,
    spinner,
    onCreateWallet,
    onSignIn,
    onSignOut,
    onRefreshAccount,
    onClearSubmittedTransactions,
    onCopy,
    onToKeyChange,
    onValueChange,
    onSubmit,
}: {
    wallet: ActiveWallet | null;
    walletAccountKey: string | null;
    walletMessage: string;
    account: AccountView | null;
    accountMessage: string;
    toKey: string;
    value: string;
    nonce: string;
    submitMessage: string;
    isSubmitting: boolean;
    canClearSubmittedTransactions: boolean;
    spinner: string;
    onCreateWallet: () => void;
    onSignIn: () => void;
    onSignOut: () => void;
    onRefreshAccount: () => void;
    onClearSubmittedTransactions: () => void;
    onCopy: (value: string) => void;
    onToKeyChange: (value: string) => void;
    onValueChange: (value: string) => void;
    onSubmit: () => void;
}) {
    const balance = account?.balance ?? 100;
    const isWalletLoading = walletMessage === 'opening passkey prompt';
    const isAccountLoading = accountMessage === 'loading account metadata';
    const walletAccountDisplay = walletAccountKey?.toLowerCase() ?? 'not authenticated';

    return (
        <section className="wallet">
            <div className="wallet__header">
                <div>
                    <div className="wallet__label">status</div>
                    <div className="wallet__status">
                        <SpinnerText active={isWalletLoading} spinner={spinner}>
                            {walletMessage}
                        </SpinnerText>
                    </div>
                </div>
                <div className="wallet__actions">
                    {!wallet && <button onClick={onSignIn}>sign in</button>}
                    {!wallet && <button onClick={onCreateWallet}>new passkey</button>}
                    {wallet && (
                        <button onClick={onRefreshAccount}>
                            <SpinnerText active={isAccountLoading} spinner={spinner}>
                                refresh
                            </SpinnerText>
                        </button>
                    )}
                    {wallet && canClearSubmittedTransactions && (
                        <button onClick={onClearSubmittedTransactions}>reset</button>
                    )}
                    {wallet && <button onClick={onSignOut}>sign out</button>}
                </div>
            </div>
            <div className="wallet__grid">
                <div className="wallet__cell">
                    <span>address</span>
                    <CopyableValue
                        disabled={!walletAccountKey}
                        plain
                        value={walletAccountDisplay}
                        onCopy={onCopy}
                    />
                </div>
                <div className="wallet__cell">
                    <span>balance</span>
                    <strong>{balance.toLocaleString()}</strong>
                </div>
                <div className="wallet__cell">
                    <span>nonce</span>
                    <strong>{nonce}</strong>
                </div>
            </div>
            <form
                className="transfer"
                onSubmit={(event) => {
                    event.preventDefault();
                    onSubmit();
                }}
            >
                <label>
                    <span>to</span>
                    <input
                        value={toKey}
                        onChange={(event) => onToKeyChange(event.target.value)}
                        placeholder="Recipient address"
                        spellCheck={false}
                        disabled={!wallet}
                    />
                </label>
                <label>
                    <span>amount</span>
                    <input
                        value={value}
                        onChange={(event) => onValueChange(event.target.value)}
                        inputMode="numeric"
                        disabled={!wallet}
                    />
                </label>
                <button className="transfer__submit" disabled={!wallet} type="submit">
                    submit
                </button>
            </form>
            {isSubmitting && submitMessage && (
                <div className="wallet__status">
                    <SpinnerText active spinner={spinner}>
                        {submitMessage}
                    </SpinnerText>
                </div>
            )}
        </section>
    );
}

function CopyableValue({
    disabled = false,
    plain = false,
    value,
    onCopy,
}: {
    disabled?: boolean;
    plain?: boolean;
    value: string;
    onCopy: (value: string) => void;
}) {
    const handleClick = () => {
        onCopy(value);
    };

    const className = [
        'copyable',
        plain ? 'copyable--plain' : '',
    ]
        .filter(Boolean)
        .join(' ');

    return (
        <button
            className={className}
            disabled={disabled}
            onClick={handleClick}
            type="button"
        >
            <span className="copyable__value">{value}</span>
        </button>
    );
}

function AddressValue({
    disabled = false,
    plain = false,
    value,
    onOpenAddress,
}: {
    disabled?: boolean;
    plain?: boolean;
    value: string;
    onOpenAddress: (value: string) => void;
}) {
    const className = [
        'copyable',
        'copyable--address',
        plain ? 'copyable--plain' : '',
    ]
        .filter(Boolean)
        .join(' ');

    return (
        <button
            aria-label={`open address ${value}`}
            className={className}
            disabled={disabled}
            onClick={() => onOpenAddress(value)}
            title="open address"
            type="button"
        >
            <span className="copyable__value">{value}</span>
        </button>
    );
}

function AccountPageAddressValue({
    account,
    value,
    onCopy,
    onOpenAddress,
}: {
    account: string;
    value: string;
    onCopy: (value: string) => void;
    onOpenAddress: (value: string) => void;
}) {
    if (normalizeAccountInput(value) === account) {
        return <CopyableValue value={value} onCopy={onCopy} />;
    }
    return <AddressValue value={value} onOpenAddress={onOpenAddress} />;
}

function TerminalToast({ message }: { message: string }) {
    return (
        <div className="terminal-toast" role="status">
            <span className="terminal-toast__prompt">+ </span>
            {message}
        </div>
    );
}

function SpinnerText({
    active,
    children,
    spinner,
}: {
    active: boolean;
    children: React.ReactNode;
    spinner: string;
}) {
    if (!active) return <>{children}</>;
    return (
        <>
            <span className="spinner" aria-hidden="true">
                {spinner}
            </span>{' '}
            {children}
        </>
    );
}

function TransactionHistory({
    transactions,
    signedInAccountKey,
    onCopy,
    onOpenAddress,
    verifyCertificates,
}: {
    transactions: SubmittedTransaction[];
    signedInAccountKey: string | null;
    onCopy: (value: string) => void;
    onOpenAddress: (value: string) => void;
    verifyCertificates: boolean;
}) {
    const formatter = useMemo(
        () =>
            new Intl.DateTimeFormat(undefined, {
                hour: '2-digit',
                minute: '2-digit',
                second: '2-digit',
            }),
        [],
    );

    if (transactions.length === 0) {
        return null;
    }

    return (
        <section className="tx-history">
            <div className="tx-history__title">submitted transactions</div>
            <div className="tx-list">
                {transactions.map((tx) => (
                    <TransactionRecord
                        key={tx.digest}
                        formatter={formatter}
                        onCopy={onCopy}
                        onOpenAddress={onOpenAddress}
                        signedInAccountKey={signedInAccountKey}
                        tx={tx}
                        verifyCertificates={verifyCertificates}
                    />
                ))}
            </div>
        </section>
    );
}

function TransactionRecord({
    formatter,
    onCopy,
    onOpenAddress,
    signedInAccountKey,
    tx,
    verifyCertificates,
}: {
    formatter: Intl.DateTimeFormat;
    onCopy: (value: string) => void;
    onOpenAddress: (value: string) => void;
    signedInAccountKey: string | null;
    tx: SubmittedTransaction;
    verifyCertificates: boolean;
}) {
    const ownsTx = signedInAccountKey !== null && tx.sender === signedInAccountKey;
    return (
        <div className="tx-record">
            <div className="tx-record__primary">
                <span className="tx-record__label">tx</span>
                <CopyableValue value={tx.digest} onCopy={onCopy} />
                <span className="tx-record__label">from</span>
                <AddressValue
                    value={tx.sender}
                    onOpenAddress={onOpenAddress}
                />
                <span className="tx-record__arrow" aria-hidden="true">→</span>
                <span className="tx-record__label">to</span>
                <AddressValue
                    value={tx.to}
                    onOpenAddress={onOpenAddress}
                />
                <span className="tx-record__nonce">value {tx.value}</span>
                <span className="tx-record__nonce">nonce {tx.nonce}</span>
                <span className="tx-record__time">{formatter.format(tx.submittedAt)}</span>
            </div>
            <div className="tx-record__secondary">
                <span className="tx-record__detail">{tx.detail}</span>
                {verifyCertificates && (
                    <>
                        <span className="tx-sep" aria-hidden="true">·</span>
                        <span className="tx-label">cert</span>
                        <CertificateCell
                            certificate={tx.certificate}
                            finalizedHeight={tx.finalizedHeight}
                            verifyCertificates={verifyCertificates}
                        />
                    </>
                )}
                <span className="tx-sep" aria-hidden="true">·</span>
                <span className="tx-label">proof</span>
                <ProofCell ownsTx={ownsTx} proof={tx.proof} />
                {tx.finalizedInMs !== null && (
                    <>
                        <span className="tx-sep" aria-hidden="true">·</span>
                        <span className="tx-label">e2e latency</span>
                        <span>{tx.finalizedInMs}ms</span>
                    </>
                )}
            </div>
        </div>
    );
}

function CertificateCell({
    certificate,
    finalizedHeight,
    verifyCertificates,
}: {
    certificate: BlockCertificateState;
    finalizedHeight: number | null;
    verifyCertificates: boolean;
}) {
    if (!verifyCertificates) {
        return (
            <span
                className="tx-proof-muted"
                aria-label="block certificate verification disabled"
                title="block certificate verification disabled"
            >
                -
            </span>
        );
    }
    if (certificate.status === 'verified') {
        return (
            <span
                className="tx-proof-check"
                aria-label="block certificate verified"
                title="block certificate verified"
            >
                ✓
            </span>
        );
    }
    if (certificate.status === 'error') {
        return (
            <span className="tx-proof-error" aria-label={certificate.detail} title={certificate.detail}>
                !
            </span>
        );
    }
    if (finalizedHeight === null) {
        return (
            <span className="tx-proof-muted" aria-label={certificate.detail} title={certificate.detail}>
                -
            </span>
        );
    }
    return (
        <span className="tx-proof-spinner" aria-label={certificate.detail} title={certificate.detail} />
    );
}

function ProofCell({
    ownsTx,
    proof,
}: {
    ownsTx: boolean;
    proof: TransactionProofState;
}) {
    if (!ownsTx) {
        return (
            <span className="tx-proof-muted" aria-label="QMDB proof not requested" title="QMDB proof not requested">
                -
            </span>
        );
    }
    if (proof.status === 'verified') {
        return (
            <span className="tx-proof-check" aria-label="QMDB proof verified" title="QMDB proof verified">
                ✓
            </span>
        );
    }
    if (proof.status === 'error') {
        return (
            <>
                <span className="tx-proof-error" aria-label={proof.detail} title={proof.detail}>
                    !
                </span>
                <span className="tx-proof-error-detail">{proof.detail}</span>
            </>
        );
    }
    return (
        <span className="tx-proof-spinner" aria-label={proof.detail} title={proof.detail} />
    );
}


function upsertBoundedBatch(
    blocks: readonly ObservedBlock[],
    current: ObservedBlock[],
): ObservedBlock[] {
    const byHeight = new Map(current.map((entry) => [entry.height.toString(), entry]));
    for (const block of blocks) {
        byHeight.set(block.height.toString(), block);
    }

    const next = Array.from(byHeight.values());
    next.sort((a, b) => compareBlockHeightDesc(a.height, b.height));
    if (next.length > HISTOGRAM_MAX_COLUMNS) {
        next.length = HISTOGRAM_MAX_COLUMNS;
    }
    return next;
}

function compareBlockHeightDesc(a: bigint, b: bigint): number {
    if (a > b) return -1;
    if (a < b) return 1;
    return 0;
}

function prependTransaction(
    transaction: SubmittedTransaction,
    current: SubmittedTransaction[],
): SubmittedTransaction[] {
    return [transaction, ...current.filter((item) => item.digest !== transaction.digest)].slice(0, 100);
}

function updateTransactionStatus(
    digest: string,
    status: TxStatus,
    detail: string,
    current: SubmittedTransaction[],
): SubmittedTransaction[] {
    return current.map((tx) => {
        if (tx.digest !== digest) return tx;
        const finalizedHeight = statusHasHeight(status) ? status.height : tx.finalizedHeight;
        return {
            ...tx,
            status: status.status,
            detail,
            finalizedInMs: Date.now() - tx.submittedAt,
            finalizedHeight,
            certificate: nextBlockCertificateState(status),
            proof: nextProofState(status),
        };
    });
}

function updateTransactionProof(
    digest: string,
    proof: TransactionProofState,
    current: SubmittedTransaction[],
): SubmittedTransaction[] {
    return current.map((tx) => (tx.digest === digest ? { ...tx, proof } : tx));
}

function updateBlockCertificateByHeight(
    height: number,
    certificate: BlockCertificateState,
    current: SubmittedTransaction[],
): SubmittedTransaction[] {
    let changed = false;
    const next = current.map((tx) => {
        if (tx.finalizedHeight !== height) return tx;
        if (sameBlockCertificate(tx.certificate, certificate)) return tx;
        changed = true;
        return { ...tx, certificate };
    });
    return changed ? next : current;
}

function sameBlockCertificate(
    left: BlockCertificateState,
    right: BlockCertificateState,
): boolean {
    if (left.status !== right.status || left.detail !== right.detail) return false;
    if (left.status !== 'verified' || right.status !== 'verified') return true;
    return left.height === right.height && left.view === right.view;
}

function shouldFetchTransactionProof(
    tx: SubmittedTransaction,
    signedInSender: string | null,
): tx is SubmittedTransaction & { readonly finalizedHeight: number } {
    return (
        signedInSender !== null &&
        tx.sender === signedInSender &&
        tx.finalizedHeight !== null &&
        (tx.status === 'finalized' ||
            (tx.status === 'partially_finalized' && tx.proof.detail !== 'not included')) &&
        (tx.proof.status === 'waiting' ||
            (tx.proof.status === 'error' && isRetryableProofError(tx.proof.detail)))
    );
}

function hasFetchingProof(
    transactions: SubmittedTransaction[],
    signedInSender: string | null,
): boolean {
    if (signedInSender === null) return false;
    return transactions.some(
        (tx) => tx.sender === signedInSender && tx.proof.status === 'fetching',
    );
}

function nextBlockCertificateState(status: TxStatus): BlockCertificateState {
    if (status.status === 'dropped') {
        return { status: 'waiting', detail: 'not finalized' };
    }
    return { status: 'waiting', detail: 'waiting for block certificate' };
}

function nextProofState(status: TxStatus): TransactionProofState {
    if (status.status === 'dropped') {
        return { status: 'waiting', detail: 'not finalized' };
    }
    if (status.status === 'partially_finalized' && status.included === 0) {
        return { status: 'waiting', detail: 'not included' };
    }
    return { status: 'waiting', detail: 'waiting for QMDB proof' };
}

function statusHasHeight(status: TxStatus): status is Extract<TxStatus, { readonly height: number }> {
    return status.status === 'finalized' || status.status === 'partially_finalized';
}

function verifiedProofState(proof: VerifiedTransactionProof): TransactionProofState {
    return {
        status: 'verified',
        detail: `verified at height ${proof.height.toString()}`,
        location: proof.location.toString(),
        tip: proof.tip.toString(),
        proofSizeBytes: proof.proofSizeBytes,
    };
}

function verifiedBlockCertificateState(certificate: {
    readonly height: bigint;
    readonly view: bigint;
}): BlockCertificateState {
    return {
        status: 'verified',
        detail: `verified at height ${certificate.height.toString()}`,
        height: certificate.height.toString(),
        view: certificate.view.toString(),
    };
}

async function retryAccountPageStep<T>(
    run: () => Promise<T>,
    signal: AbortSignal,
): Promise<T> {
    let lastError: unknown;
    for (let attempt = 0; attempt < 12; attempt++) {
        if (signal.aborted) {
            throw new Error('account lookup cancelled');
        }
        try {
            return await run();
        } catch (error) {
            lastError = error;
            const detail = error instanceof Error ? error.message : String(error);
            if (!isRetryableAccountProofError(detail)) {
                throw error;
            }
            await sleep(350 + attempt * 150);
        }
    }
    throw lastError instanceof Error ? lastError : new Error(String(lastError));
}

function formatTxStatus(status: TxStatus): string {
    if (status.status === 'finalized') {
        return `finalized at ${status.height}`;
    }
    if (status.status === 'partially_finalized') {
        return `partial at ${status.height}: ${status.included} included, ${status.filtered} filtered`;
    }
    return status.status;
}

function sleep(ms: number): Promise<void> {
    return new Promise((resolve) => window.setTimeout(resolve, ms));
}

function shortHex(value: string): string {
    return value.length <= 18 ? value : `${value.slice(0, 10)}…${value.slice(-8)}`;
}

function bytesToHex(bytes: Uint8Array): string {
    return [...bytes].map((byte) => byte.toString(16).padStart(2, '0')).join('');
}

function normalizeAccountInput(value: string): string | null {
    const normalized = value.trim().replace(/^0x/i, '').toLowerCase();
    if (isAccountKeyHex(normalized)) {
        return normalized;
    }
    return null;
}

function accountNonceState(account: AccountView | null): NonceState {
    if (account === null) {
        return emptyNonceState();
    }

    return {
        base: BigInt(account.nonce.base),
        bitmap: BigInt(account.nonce.bitmap),
    };
}

function accountFromLocation(): string {
    const url = new URL(window.location.href);
    const queryAccount = url.searchParams.get('account');
    const fromQuery = queryAccount?.trim().replace(/^0x/i, '').toLowerCase();
    if (fromQuery && isAccountKeyHex(fromQuery)) return fromQuery;

    const pathMatch = /^\/account\/([0-9a-fA-F]{64})$/.exec(url.pathname);
    return pathMatch ? pathMatch[1].toLowerCase() : '';
}

function readHistory(key: string): SubmittedTransaction[] {
    const raw = window.localStorage.getItem(key);
    if (!raw) return [];

    try {
        const parsed = JSON.parse(raw);
        return Array.isArray(parsed)
            ? parsed.reduce<SubmittedTransaction[]>((transactions, item) => {
                  const transaction = normalizeSubmittedTransaction(item);
                  if (transaction) transactions.push(transaction);
                  return transactions;
              }, [])
            : [];
    } catch {
        return [];
    }
}

function writeHistory(key: string, history: SubmittedTransaction[]) {
    window.localStorage.setItem(key, JSON.stringify(history));
}

function clearHistory(key: string) {
    window.localStorage.removeItem(key);
}

function useBrailleSpinner(active: boolean): string {
    const [index, setIndex] = useState(0);

    useEffect(() => {
        if (!active) return;
        const interval = window.setInterval(() => {
            setIndex((current) => (current + 1) % BRAILLE_SPINNER.length);
        }, 80);
        return () => window.clearInterval(interval);
    }, [active]);

    return BRAILLE_SPINNER[index];
}

function normalizeSubmittedTransaction(value: unknown): SubmittedTransaction | null {
    if (typeof value !== 'object' || value === null) {
        return null;
    }

    const transaction = value as Record<string, unknown>;
    if (
        typeof transaction.sender !== 'string' ||
        !isAccountKeyHex(transaction.sender) ||
        typeof transaction.digest !== 'string' ||
        typeof transaction.to !== 'string' ||
        !isAccountKeyHex(transaction.to) ||
        typeof transaction.value !== 'string' ||
        typeof transaction.nonce !== 'string' ||
        typeof transaction.submittedAt !== 'number' ||
        typeof transaction.status !== 'string' ||
        typeof transaction.detail !== 'string'
    ) {
        return null;
    }

    const finalizedInMs =
        typeof transaction.finalizedInMs === 'number' ? transaction.finalizedInMs : null;
    const finalizedHeight =
        typeof transaction.finalizedHeight === 'number' ? transaction.finalizedHeight : null;

    return {
        digest: transaction.digest,
        sender: transaction.sender,
        to: transaction.to,
        value: transaction.value,
        nonce: transaction.nonce,
        submittedAt: transaction.submittedAt,
        finalizedInMs,
        status: transaction.status as SubmittedTransaction['status'],
        detail: transaction.detail,
        finalizedHeight,
        certificate: normalizeBlockCertificate(transaction.certificate, finalizedHeight),
        proof: normalizeTransactionProof(transaction.proof),
    };
}

function isAccountKeyHex(value: string): boolean {
    return /^[0-9a-f]{64}$/.test(value);
}

function normalizeBlockCertificate(
    value: unknown,
    finalizedHeight: number | null,
): BlockCertificateState {
    if (typeof value !== 'object' || value === null) {
        return defaultBlockCertificate(finalizedHeight);
    }
    const certificate = value as Record<string, unknown>;
    if (
        certificate.status === 'verified' &&
        typeof certificate.detail === 'string' &&
        typeof certificate.height === 'string' &&
        typeof certificate.view === 'string'
    ) {
        return {
            status: 'verified',
            detail: certificate.detail,
            height: certificate.height,
            view: certificate.view,
        };
    }
    if (
        (certificate.status === 'waiting' || certificate.status === 'error') &&
        typeof certificate.detail === 'string'
    ) {
        return { status: certificate.status, detail: certificate.detail };
    }
    return defaultBlockCertificate(finalizedHeight);
}

function defaultBlockCertificate(finalizedHeight: number | null): BlockCertificateState {
    if (finalizedHeight === null) {
        return WAITING_FINALIZATION_CERTIFICATE;
    }
    return WAITING_BLOCK_CERTIFICATE;
}

function normalizeTransactionProof(value: unknown): TransactionProofState {
    if (typeof value !== 'object' || value === null) {
        return { status: 'waiting', detail: 'waiting for finalization' };
    }
    const proof = value as Record<string, unknown>;
    if (proof.status === 'verified' && typeof proof.detail === 'string') {
        return {
            status: 'verified',
            detail: proof.detail,
            location: typeof proof.location === 'string' ? proof.location : '',
            tip: typeof proof.tip === 'string' ? proof.tip : '',
            proofSizeBytes: typeof proof.proofSizeBytes === 'number' ? proof.proofSizeBytes : 0,
        };
    }
    if (proof.status === 'waiting' && typeof proof.detail === 'string') {
        return { status: 'waiting', detail: proof.detail };
    }
    if (proof.status === 'error') {
        return { status: 'waiting', detail: 'retrying QMDB proof' };
    }
    return { status: 'waiting', detail: 'waiting for finalization' };
}

function StatusBadge({ status, spinner }: { status: Status; spinner: string }) {
    if (status.kind === 'connecting') {
        return (
            <span className="app__status">
                <span className="spinner" aria-hidden="true">
                    {spinner}
                </span>
                connecting
            </span>
        );
    }
    if (status.kind === 'error') {
        return (
            <span className="app__status error">
                <span className="dot" />
                {status.message}
            </span>
        );
    }
    return (
        <span className="app__status live">
            <span className="app__live-text" aria-hidden="true">
                {LIVE_STATUS_SYMBOLS.map((symbol, index) => (
                    <span className="app__live-symbol" key={index}>
                        {symbol}
                    </span>
                ))}
            </span>
            <span className="visually-hidden">live</span>
        </span>
    );
}

const ExplorerStats = memo(function ExplorerStats({
    blocks,
    totalBlocksObserved,
    totalTxObserved,
    observedRateWindow,
}: {
    blocks: ObservedBlock[];
    totalBlocksObserved: number;
    totalTxObserved: number;
    observedRateWindow: ObservedRateWindow;
}) {
    const stats = useMemo(
        () => buildExplorerStats(blocks, totalBlocksObserved, totalTxObserved),
        [blocks, totalBlocksObserved, totalTxObserved],
    );
    return (
        <dl className="observed-stats" aria-label="explorer statistics">
            <ExplorerStat label="latest height" value={stats.latestHeight} />
            <ExplorerStat
                label="observed tx/sec"
                value={formatObservedTxPerSecond(totalTxObserved, observedRateWindow)}
            />
            <ExplorerStat label="total txs observed" value={stats.totalTxObserved} />
            <ExplorerStat label="peak tx/block" value={stats.peakTxPerBlock} />
            <ExplorerStat label="avg tx/block" value={stats.avgTxPerBlock} />
        </dl>
    );
});

function ExplorerStat({ label, value }: { label: string; value: string }) {
    return (
        <div className="observed-stat">
            <dt className="observed-stat__label">{label}</dt>
            <dd className="observed-stat__value">{value}</dd>
        </div>
    );
}

function buildExplorerStats(
    blocks: ObservedBlock[],
    totalBlocksObserved: number,
    totalTxObserved: number,
): {
    latestHeight: string;
    totalTxObserved: string;
    peakTxPerBlock: string;
    avgTxPerBlock: string;
} {
    let latest: bigint | null = null;
    let peak = 0;
    for (const block of blocks) {
        if (latest === null || block.height > latest) {
            latest = block.height;
        }
        if (block.txCount > peak) {
            peak = block.txCount;
        }
    }

    const avg = totalBlocksObserved === 0 ? 0 : totalTxObserved / totalBlocksObserved;
    return {
        latestHeight: latest?.toString() ?? '—',
        totalTxObserved: totalTxObserved === 0 ? '—' : totalTxObserved.toLocaleString(),
        peakTxPerBlock: peak === 0 ? '—' : peak.toLocaleString(),
        avgTxPerBlock: totalBlocksObserved === 0 ? '—' : Math.round(avg).toLocaleString(),
    };
}

function formatObservedTxPerSecond(
    totalTxObserved: number,
    observedRateWindow: ObservedRateWindow,
): string {
    const { firstBlockAt, latestBlockAt } = observedRateWindow;
    if (firstBlockAt === null || latestBlockAt === null) {
        return '—';
    }
    const elapsedSeconds = (latestBlockAt - firstBlockAt) / 1000;
    if (elapsedSeconds <= 0) {
        return '—';
    }

    const txPerSecond = totalTxObserved / elapsedSeconds;
    if (txPerSecond >= 100) {
        return Math.round(txPerSecond).toLocaleString();
    }
    return txPerSecond.toLocaleString(undefined, {
        maximumFractionDigits: 1,
    });
}

const Histogram = memo(function Histogram({ blocks }: { blocks: ObservedBlock[] }) {
    const frameRef = useRef<HTMLDivElement>(null);
    const measureRef = useRef<HTMLSpanElement>(null);
    const [columns, setColumns] = useState(HISTOGRAM_INITIAL_COLUMNS);
    const [rows, setRows] = useState(HISTOGRAM_HEIGHT);

    useEffect(() => {
        const frame = frameRef.current;
        const measure = measureRef.current;
        if (!frame || !measure) return;

        const recompute = () => {
            const { width: charWidth, height: charHeight } = measure.getBoundingClientRect();
            if (charWidth <= 0 || charHeight <= 0) return;

            const availableColumns = Math.floor(frame.clientWidth / charWidth);
            const nextColumns = Math.max(
                HISTOGRAM_MIN_COLUMNS,
                Math.min(HISTOGRAM_MAX_COLUMNS, availableColumns),
            );
            setColumns((current) => (current === nextColumns ? current : nextColumns));

            const rawRows = Math.floor(frame.clientHeight / charHeight);
            const isMobile = window.matchMedia('(max-width: 760px)').matches;
            const availableRows = isMobile ? rawRows : Math.floor(rawRows / 2);
            const nextRows = Math.max(
                HISTOGRAM_MIN_ROWS,
                Math.min(HISTOGRAM_MAX_ROWS, availableRows),
            );
            setRows((current) => (current === nextRows ? current : nextRows));
        };

        recompute();
        const observer = new ResizeObserver(recompute);
        observer.observe(frame);
        window.addEventListener('resize', recompute);
        return () => {
            observer.disconnect();
            window.removeEventListener('resize', recompute);
        };
    }, []);

    const { lines, placeholderCount } = useMemo(
        () => buildHistogram(blocks, columns, rows),
        [blocks, columns, rows],
    );
    return (
        <div className="histogram-frame" ref={frameRef}>
            <pre className="histogram" aria-label="recent block transaction count histogram">
                <span className="histogram__measure" ref={measureRef} aria-hidden="true">
                    █
                </span>
                {lines.map((line, index) => (
                    <span
                        className="histogram__line"
                        key={index}
                        style={histogramLineStyle(index, rows)}
                    >
                        {placeholderCount > 0 && (
                            <span style={HISTOGRAM_PLACEHOLDER_STYLE}>
                                {line.slice(0, placeholderCount)}
                            </span>
                        )}
                        {line.slice(placeholderCount)}
                    </span>
                ))}
            </pre>
        </div>
    );
});

const BlockLog = memo(function BlockLog({ blocks }: { blocks: ObservedBlock[] }) {
    const recent = blocks.slice(0, BLOCK_LOG_MAX);
    const formatter = useMemo(
        () =>
            new Intl.DateTimeFormat(undefined, {
                hour: '2-digit',
                minute: '2-digit',
                second: '2-digit',
                fractionalSecondDigits: 3,
            }),
        [],
    );

    if (recent.length === 0) return null;

    return (
        <section className="block-log" aria-label="recent finalized blocks">
            <div className="block-log__header" aria-hidden="true">
                <span>height</span>
                <span>block hash</span>
                <span># txs</span>
                <span>timestamp</span>
            </div>
            <div className="block-log__list">
                {recent.map((block) => (
                    <BlockLogRow key={block.height.toString()} block={block} formatter={formatter} />
                ))}
            </div>
        </section>
    );
});

const BlockLogRow = memo(function BlockLogRow({
    block,
    formatter,
}: {
    block: ObservedBlock;
    formatter: Intl.DateTimeFormat;
}) {
    const hash = useMemo(() => bytesToHex(block.digest), [block.digest]);
    return (
        <div className="block-row">
            <span className="block-row__height">{block.height.toString()}</span>
            <span className="block-row__hash" title={hash}>
                {shortHex(hash)}
            </span>
            <span className="block-row__txcount">{block.txCount.toLocaleString()}</span>
            <span className="block-row__time">{formatter.format(block.arrivedAt)}</span>
        </div>
    );
});

const HISTOGRAM_PLACEHOLDER_STYLE: CSSProperties = { color: '#383838' };

function buildHistogram(
    blocks: ObservedBlock[],
    width: number,
    rows: number,
): { lines: string[]; placeholderCount: number } {
    const recent = blocks.slice(0, width).reverse();
    const placeholderCount = Math.max(0, width - recent.length);
    let peak = 0;
    for (const block of recent) {
        if (block.txCount > peak) peak = block.txCount;
    }

    const ramp = BLOCK_GLYPHS.length - 1;
    const stepsPerColumn = rows * ramp;
    const placeholderSteps = Math.round(stepsPerColumn * 0.5);

    const columnSteps: number[] = [];
    for (let i = 0; i < placeholderCount; i++) {
        columnSteps.push(placeholderSteps);
    }
    if (peak === 0) {
        for (let i = 0; i < recent.length; i++) {
            columnSteps.push(0);
        }
    } else {
        for (const block of recent) {
            const scaledSteps = Math.round((block.txCount / peak) * stepsPerColumn);
            columnSteps.push(Math.min(stepsPerColumn, Math.max(1, scaledSteps)));
        }
    }

    const lines: string[] = [];
    for (let row = 0; row < rows; row++) {
        const rowsBelow = rows - 1 - row;
        let line = '';
        for (const steps of columnSteps) {
            const glyphIndex = Math.max(0, Math.min(ramp, steps - rowsBelow * ramp));
            line += BLOCK_GLYPHS[glyphIndex];
        }
        lines.push(line);
    }
    return { lines, placeholderCount };
}

function histogramLineStyle(rowIndex: number, rows: number): CSSProperties {
    const ratio = 1 - rowIndex / Math.max(1, rows - 1);
    return { color: histogramLineColor(ratio) };
}

function histogramLineColor(ratio: number): string {
    const start = [32, 34, 36];
    const end = [255, 178, 0];
    const mix = Math.max(0, Math.min(1, ratio));
    const channels = start.map((value, index) =>
        Math.round(value + (end[index] - value) * mix),
    );
    return `rgb(${channels[0]}, ${channels[1]}, ${channels[2]})`;
}
