import {
    memo,
    useCallback,
    useEffect,
    useMemo,
    useRef,
    useState,
    type CSSProperties,
} from 'react';
import { AddressValue } from './AddressValue';
import {
    accountKeyFromPublicKey,
    channelAddress,
    encodeSignedMintTransaction,
    encodeSignedOpenChannelTransaction,
    encodeSignedTimeoutChannelTransaction,
    encodeSignedTransaction,
    encodeTransactionBatch,
    fromHex,
    normalizeAccountKeyHex,
    parseAccountKeyHex,
    parseU64,
    toHex,
    type EncodedTransaction,
} from './codec';
import { submittedTransactionHistoryKey } from './historyKey';
import { type BlockKindCounts, type ObservedBlock, subscribeBlocks } from './indexer';
import { fetchStats } from './operatorClient';
import {
    fetchAccount,
    statusHasHeight,
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
    type TransactionKind,
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
import {
    PaidStreamPage,
    type OpenStreamChannelRequest,
    type ReclaimStreamChannelRequest,
} from './PaidStreamPage';
import { errorMessage, shortHex, sleep } from './util';

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
const TEST_MINT_AMOUNT = 1_000n;

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
// Optional: the channel operator's HTTP base. When set, the stats strip shows
// the off-chain voucher count next to the on-chain settlement count.
const operatorUrl: string = import.meta.env.VITE_OPERATOR_URL ?? '';
const verifyCertificates = parseBooleanEnv(import.meta.env.VITE_VERIFY_CERTIFICATES, true);

function parseBooleanEnv(value: unknown, fallback: boolean): boolean {
    if (typeof value !== 'string') return fallback;
    if (/^(0|false|off|no)$/i.test(value)) return false;
    if (/^(1|true|on|yes)$/i.test(value)) return true;
    return fallback;
}

/** How often to refresh the operator's self-reported counters. */
const OPERATOR_STATS_POLL_MS = 2_000;

/** Trailing debounce for persisting submitted-transaction history. */
const HISTORY_WRITE_DEBOUNCE_MS = 250;

// Display labels per transaction kind, in stats-row order. The exhaustive
// Record ties the list to `BlockKindCounts`, so the zero record, the
// accumulator, and the expanded stats row all follow a new kind from here.
const KIND_LABELS: Record<keyof BlockKindCounts, string> = {
    transfers: 'transfers',
    channelOpens: 'channel opens',
    channelCloses: 'channel closes',
    channelTimeouts: 'channel timeouts',
    mints: 'mints',
};
const KIND_KEYS = Object.keys(KIND_LABELS) as ReadonlyArray<keyof BlockKindCounts>;

function buildKindCounts(count: (key: keyof BlockKindCounts) => number): BlockKindCounts {
    return {
        transfers: count('transfers'),
        channelOpens: count('channelOpens'),
        channelCloses: count('channelCloses'),
        channelTimeouts: count('channelTimeouts'),
        mints: count('mints'),
    };
}

const ZERO_KIND_COUNTS = buildKindCounts(() => 0);

function addKindCounts(total: BlockKindCounts, block: ObservedBlock): BlockKindCounts {
    return buildKindCounts((key) => total[key] + block.kinds[key]);
}

/// A stable identity over the freshest closure: the wrapped function may be
/// rebuilt every render, but memoized consumers of the returned one don't
/// re-render for that.
function useStableCallback<Args extends unknown[], Result>(
    latest: (...args: Args) => Result,
): (...args: Args) => Result {
    const ref = useRef(latest);
    ref.current = latest;
    return useCallback((...args: Args) => ref.current(...args), []);
}

interface SubmittedTransaction {
    readonly sender: string;
    readonly digest: string;
    // What the wallet submitted; history stored before this field existed
    // only held transfers, so absent normalizes to 'transfer'.
    readonly kind: TransactionKind;
    readonly to: string;
    readonly value: string;
    readonly nonce: string;
    readonly submittedAt: number;
    readonly resolvedInMs: number | null;
    readonly status: 'pending' | 'finalized' | 'partially_finalized' | 'dropped' | 'error';
    readonly detail: string;
    /// Whether the mempool rejected (filtered) this transaction. Stored as
    /// structured data so the UI never has to parse `detail`.
    readonly rejected: boolean;
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

/// Machine-readable wallet lifecycle; `walletMessage` is display-only.
type WalletStatus = 'idle' | 'busy' | 'signed-in' | 'error';
/// Machine-readable account-metadata lifecycle; `accountMessage` is
/// display-only.
type AccountStatus = 'idle' | 'loading' | 'loaded' | 'error';

export default function App() {
    const [blocks, setBlocks] = useState<ObservedBlock[]>([]);
    // Cumulative counter across every block observed on the stream. Tracked
    // independently of `blocks` so the rate keeps climbing when older entries
    // roll off the histogram buffer.
    const [totalTxObserved, setTotalTxObserved] = useState(0);
    const [totalBlocksObserved, setTotalBlocksObserved] = useState(0);
    const [totalKinds, setTotalKinds] = useState<BlockKindCounts>(ZERO_KIND_COUNTS);
    // Vouchers served since this page loaded, so the stat is comparable with
    // the (equally session-scoped) transaction counters. The operator reports
    // lifetime totals; the first poll sets the baseline.
    const [sessionVouchers, setSessionVouchers] = useState<number | null>(null);
    const voucherBaselineRef = useRef<number | null>(null);
    const [observedRateWindow, setObservedRateWindow] = useState<ObservedRateWindow>({
        firstBlockAt: null,
        latestBlockAt: null,
    });
    const [status, setStatus] = useState<Status>({ kind: 'connecting' });
    const [isWalletOpen, setIsWalletOpen] = useState(false);
    const [isSearchOpen, setIsSearchOpen] = useState(false);
    const [wallet, setWallet] = useState<ActiveWallet | null>(null);
    /// Render-synced mirror so async wallet work can detect a switch that
    /// happened while it awaited (its closed-over `wallet` is stale).
    const walletRef = useRef<ActiveWallet | null>(null);
    walletRef.current = wallet;
    const [walletAccountKey, setWalletAccountKey] = useState<string | null>(null);
    /// Bumped to re-run the account-key derivation after a failure (the only
    /// other recovery is signing out and back in).
    const [walletKeyAttempt, setWalletKeyAttempt] = useState(0);
    const [walletStatus, setWalletStatus] = useState<WalletStatus>('idle');
    const [walletMessage, setWalletMessage] = useState('sign in or create a wallet');
    const [account, setAccount] = useState<AccountView | null>(null);
    const [accountStatus, setAccountStatus] = useState<AccountStatus>('idle');
    const [accountMessage, setAccountMessage] = useState('account metadata unavailable');
    const [toKey, setToKey] = useState('');
    const [value, setValue] = useState('1');
    const [nonce, setNonce] = useState('0');
    const [submitMessage, setSubmitMessage] = useState('');
    const [pendingSubmissionCount, setPendingSubmissionCount] = useState(0);
    const [history, setHistory] = useState<SubmittedTransaction[]>([]);
    const [lookupAccount, setLookupAccount] = useState(() => accountFromLocation());
    const [isStreamOpen, setIsStreamOpen] = useState(false);
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
    const [toast, setToast] = useState('');
    const nextNonceRef = useRef<NonceState>(emptyNonceState());
    const pendingBlocksRef = useRef<ObservedBlock[]>([]);
    const blockFlushTimeoutRef = useRef<number | null>(null);
    const toastTimeoutRef = useRef<number | null>(null);
    /// Which key the current `history` state was loaded from; gates the
    /// write-back effect so it never writes one key's history to another.
    const loadedHistoryKeyRef = useRef<string | null>(null);
    /// Set by the load effect, consumed by the write effect's next run
    /// (which still closes over the pre-load `history`).
    const historyJustLoadedRef = useRef(false);
    const pendingHistoryWriteRef = useRef<{
        timer: number;
        key: string;
        history: SubmittedTransaction[];
    } | null>(null);
    const flushPendingHistoryWrite = () => {
        const pending = pendingHistoryWriteRef.current;
        if (pending === null) return;
        pendingHistoryWriteRef.current = null;
        window.clearTimeout(pending.timer);
        writeHistory(pending.key, pending.history);
    };
    const isSubmitting = pendingSubmissionCount > 0;
    const historyKey = useMemo(
        () =>
            submittedTransactionHistoryKey(
                {
                    indexerUrl,
                    qmdbUrl,
                    storeUrl,
                    mempoolUrl,
                    simplexVerificationMaterial,
                },
                walletAccountKey,
            ),
        [walletAccountKey],
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
            setTotalKinds((current) => flushed.reduce(addKindCounts, current));
            setTotalBlocksObserved((current) => current + flushed.length);
            setObservedRateWindow((current) => ({
                firstBlockAt: current.firstBlockAt ?? flushed[0].arrivedAt,
                latestBlockAt: flushed[flushed.length - 1].arrivedAt,
            }));
            setStatus((current) => (current.kind === 'live' ? current : { kind: 'live' }));
        }, BLOCK_FLUSH_INTERVAL_MS);
    };

    // Poll the operator's self-reported counters; unlike everything else on
    // the page they are not proof-verified, and the strip labels them so.
    // A self-re-arming timeout (rather than an interval) means polls never
    // overlap, and hidden tabs skip the fetch until they are visible again.
    useEffect(() => {
        if (!operatorUrl) return;
        let cancelled = false;
        let timer: number | null = null;

        const poll = async () => {
            try {
                const vouchers = Number((await fetchStats(operatorUrl)).vouchers);
                if (cancelled) return;
                const baseline = voucherBaselineRef.current;
                if (baseline === null) {
                    voucherBaselineRef.current = vouchers;
                } else if (vouchers < baseline) {
                    // The operator restarted (its lifetime count reset);
                    // restart the session count with it.
                    voucherBaselineRef.current = 0;
                }
                setSessionVouchers(vouchers - (voucherBaselineRef.current ?? 0));
            } catch {
                // Operator not up yet (or between restarts); keep polling.
            }
        };

        const loop = async () => {
            timer = null;
            if (!document.hidden) {
                await poll();
                if (cancelled) return;
            }
            timer = window.setTimeout(() => void loop(), OPERATOR_STATS_POLL_MS);
        };

        void loop();
        const onVisibilityChange = () => {
            if (cancelled || document.hidden) return;
            // Back in the foreground: poll now instead of waiting out the
            // idle re-arm timer.
            if (timer !== null) window.clearTimeout(timer);
            void loop();
        };
        document.addEventListener('visibilitychange', onVisibilityChange);
        return () => {
            cancelled = true;
            if (timer !== null) window.clearTimeout(timer);
            document.removeEventListener('visibilitychange', onVisibilityChange);
        };
    }, []);

    useEffect(() => {
        const restoredWallet = restoreWalletSession();
        if (!restoredWallet) return;
        setWallet(restoredWallet);
        setWalletStatus('signed-in');
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
                    message: errorMessage(error),
                });
            }
        })();

        return () => {
            cancelled = true;
            controller.abort();
        };
    }, []);

    useEffect(() => {
        // A pending debounced write always belongs to the previous key;
        // flush it before this key's history replaces the state it captured.
        flushPendingHistoryWrite();
        setHistory(historyKey === null ? [] : readHistory(historyKey));
        loadedHistoryKeyRef.current = historyKey;
        historyJustLoadedRef.current = true;
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
                setWalletStatus('error');
                setWalletMessage(errorMessage(error));
            });

        return () => {
            cancelled = true;
        };
    }, [wallet, walletKeyAttempt]);

    useEffect(() => {
        if (historyKey === null) return;
        if (loadedHistoryKeyRef.current !== historyKey) return;
        // The run in the same commit as a load still closes over the
        // previous key's history; skip it (the post-load run re-arms with
        // the freshly loaded state).
        if (historyJustLoadedRef.current) {
            historyJustLoadedRef.current = false;
            return;
        }
        // Debounce: history changes in bursts while a submission resolves,
        // and localStorage writes are synchronous.
        const pending = pendingHistoryWriteRef.current;
        if (pending !== null) window.clearTimeout(pending.timer);
        const timer = window.setTimeout(() => {
            pendingHistoryWriteRef.current = null;
            writeHistory(historyKey, history);
        }, HISTORY_WRITE_DEBOUNCE_MS);
        pendingHistoryWriteRef.current = { timer, key: historyKey, history };
    }, [historyKey, history]);

    // Flush any pending debounced history write on unmount.
    useEffect(() => () => flushPendingHistoryWrite(), []);

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
                const detail = errorMessage(error);
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
                    detail: errorMessage(error),
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
                    proof: { status: 'fetching', detail: 'fetching transaction proof' },
                })));

                // Verify rows against a certified target fetched with the
                // page, not the one pinned when the account was first looked
                // up: rows indexed after that pin would read as beyond its
                // finalized range until a full page reload.
                const target = await retryAccountPageStep(
                    () => fetchLatestProofTarget({
                        storeUrl,
                        simplexVerificationMaterial,
                        signal: controller.signal,
                    }),
                    controller.signal,
                );
                if (controller.signal.aborted) return;
                const results = await Promise.allSettled(
                    page.rows.map((row) =>
                        retryAccountPageStep(() => fetchAndVerifyTransactionRowProof({
                            qmdbUrl,
                            sqlUrl: indexerUrl,
                            row,
                            target,
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
                        const detail = errorMessage(result.reason);
                        return { ...entry, proof: { status: 'error', detail } };
                    }),
                );
            })
            .catch((error) => {
                if (controller.signal.aborted) return;
                setAccountTransactions([]);
                setAccountNextCursor(null);
                setAccountActivityError(errorMessage(error));
            });

        return () => controller.abort();
    }, [lookupAccount, currentAccountCursor, accountActivityMode]);

    useEffect(() => {
        const signedInSender = walletAccountKey;
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
                const detail = errorMessage(error);
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
    }, [history, walletAccountKey]);

    useEffect(() => {
        return () => {
            if (blockFlushTimeoutRef.current !== null) {
                window.clearTimeout(blockFlushTimeoutRef.current);
            }
            if (toastTimeoutRef.current !== null) {
                window.clearTimeout(toastTimeoutRef.current);
            }
        };
    }, []);

    const refreshAccount = async () => {
        if (!wallet) return;
        const key = wallet.publicKeyHex;
        // If the wallet was switched while the fetch was in flight, merging
        // the old wallet's nonce state would poison the new one's local
        // nonce window.
        const superseded = () => walletRef.current?.publicKeyHex !== key;
        setAccountStatus('loading');
        setAccountMessage('loading account metadata');
        try {
            const nextAccount = await fetchAccount(mempoolUrl, key);
            if (superseded()) return;
            setAccount(nextAccount);
            mergeLocalNonceState(accountNonceState(nextAccount));
            setAccountStatus('loaded');
            setAccountMessage(
                nextAccount ? 'committed account loaded' : 'no committed account yet; mint to fund it',
            );
        } catch (error) {
            if (superseded()) return;
            setAccountStatus('error');
            setAccountMessage(errorMessage(error));
        }
    };

    useEffect(() => {
        if (!wallet) {
            setAccount(null);
            setLocalNonceState(emptyNonceState());
            setAccountStatus('idle');
            setAccountMessage('account metadata unavailable');
            return;
        }
        // refreshAccount's `superseded()` guard (via walletRef) already
        // discards responses for a wallet that changed mid-flight.
        void refreshAccount();
        // eslint-disable-next-line react-hooks/exhaustive-deps
    }, [wallet]);

    const connectWallet = async (open: () => Promise<ActiveWallet>) => {
        setWalletStatus('busy');
        setWalletMessage('opening passkey prompt');
        try {
            const nextWallet = await open();
            setWallet(nextWallet);
            setWalletStatus('signed-in');
            setWalletMessage('signed in');
        } catch (error) {
            setWalletStatus('error');
            setWalletMessage(errorMessage(error));
        }
    };

    const handleCreateWallet = () => connectWallet(createWallet);
    const handleSignIn = () => connectWallet(signInWithPasskey);

    const handleSignOut = () => {
        clearSession();
        setWallet(null);
        setWalletStatus('idle');
        setWalletMessage('signed out');
    };

    const showToast = useCallback((message: string, duration = 2_800) => {
        if (toastTimeoutRef.current !== null) {
            window.clearTimeout(toastTimeoutRef.current);
        }
        setToast(message);
        toastTimeoutRef.current = window.setTimeout(() => {
            setToast('');
            toastTimeoutRef.current = null;
        }, duration);
    }, []);

    // Stable: referential stability is what lets the memoized PaidStreamPage
    // skip App's dashboard ticks.
    const copyValue = useCallback(async (value: string) => {
        try {
            await navigator.clipboard.writeText(value);
            showToast('copied', 1_400);
        } catch (error) {
            showToast(errorMessage(error), 1_400);
        }
    }, [showToast]);

    const openAccountPage = useCallback((value: string): boolean => {
        const normalized = normalizeAccountKeyHex(value);
        if (!normalized) return false;

        setSearchMessage('');
        setLookupAccount(normalized);
        setAccountInput(normalized);
        setAccountCursorStack([null]);
        pushAccountLocation(normalized);
        setIsWalletOpen(false);
        setIsSearchOpen(false);
        return true;
    }, []);

    // Opening the wallet dialog also refreshes the account snapshot it shows.
    const openWalletDialog = useStableCallback(() => {
        setIsWalletOpen(true);
        if (wallet) void refreshAccount();
    });
    const closeWalletDialog = useCallback(() => setIsWalletOpen(false), []);
    const closeSearchDialog = useCallback(() => setIsSearchOpen(false), []);

    const submitAccountLookup = () => {
        if (openAccountPage(accountInput)) return;
        setSearchMessage('enter a 32-byte account address');
    };

    const clearAccountLookup = () => {
        setLookupAccount('');
        setAccountInput('');
        setAccountCursorStack([null]);
        setSearchMessage('');
        pushAccountLocation(null);
    };

    const nextAccountPage = useStableCallback(() => {
        if (!accountNextCursor) return;
        setAccountCursorStack((current) => [...current, accountNextCursor]);
    });

    const previousAccountPage = useCallback(() => {
        setAccountCursorStack((current) => current.length <= 1 ? current : current.slice(0, -1));
    }, []);

    const changeAccountActivityMode = useCallback((mode: AccountActivityMode) => {
        setAccountActivityMode(mode);
        setAccountCursorStack([null]);
        setAccountNextCursor(null);
    }, []);

    /**
     * Shared submit flow: reserve the next nonce (rolled back if nothing was
     * submitted), let `form` parse the inputs and sign the transaction, then
     * record it in history and submit it to the mempool. `form` receives the
     * reserved nonce plus the active wallet and its account key (narrowed —
     * the guards below already ran) and returns the encoded transaction plus
     * the recipient/value to show in history.
     */
    const submitSigned = async (
        formingMessage: string,
        form: (
            nonce: bigint,
            activeWallet: ActiveWallet,
            senderAccountKey: string,
        ) => Promise<{
            encoded: EncodedTransaction;
            kind: TransactionKind;
            to: string;
            value: bigint;
        }>,
    ): Promise<TxStatus | null> => {
        if (!wallet) return null;
        if (!walletAccountKey) {
            setSubmitMessage('loading account address');
            return null;
        }

        setPendingSubmissionCount((count) => count + 1);
        setSubmitMessage(formingMessage);
        let reservation: { previous: NonceState; next: NonceState } | null = null;
        try {
            const previousNonce = nextNonceRef.current;
            const parsedNonce = nextAvailableNonce(previousNonce);
            const nextNonce = consumeNonce(previousNonce, parsedNonce);
            if (nextNonce === null) {
                throw new Error('nonce must fit in u64');
            }
            setLocalNonceState(nextNonce);
            reservation = { previous: previousNonce, next: nextNonce };

            const { encoded, kind, to, value: sentValue } = await form(parsedNonce, wallet, walletAccountKey);
            const pending: SubmittedTransaction = {
                sender: walletAccountKey,
                digest: encoded.digestHex,
                kind,
                to,
                value: sentValue.toString(),
                nonce: parsedNonce.toString(),
                submittedAt: Date.now(),
                resolvedInMs: null,
                status: 'pending',
                detail: 'submitted to mempool',
                rejected: false,
                finalizedHeight: null,
                certificate: WAITING_FINALIZATION_CERTIFICATE,
                proof: WAITING_FINALIZATION_CERTIFICATE,
            };
            setHistory((current) => prependTransaction(pending, current));
            setSubmitMessage('submitting');

            const txStatus = await submitTransactions(mempoolUrl, encodeTransactionBatch([encoded.bytes]));
            const detail = formatTxStatus(txStatus, encoded.digestHex);
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
            return txStatus;
        } catch (error) {
            if (reservation !== null && nonceStatesEqual(nextNonceRef.current, reservation.next)) {
                setLocalNonceState(reservation.previous);
            }
            setSubmitMessage(errorMessage(error));
            return null;
        } finally {
            setPendingSubmissionCount((count) => Math.max(0, count - 1));
        }
    };

    /// Parses the form inputs inside the builder so bad input surfaces
    /// through `submitSigned`'s catch.
    const submitTransfer = () =>
        submitSigned('forming transaction', async (nonce, activeWallet) => {
            const toAccountKey = parseAccountKeyHex(toKey);
            const transferValue = parseU64(value, 'value');
            const encoded = await encodeSignedTransaction(
                {
                    senderPublicKey: activeWallet.publicKey,
                    toAccountKey,
                    value: transferValue,
                    nonce,
                },
                activeWallet.sign,
            );
            return { encoded, kind: 'transfer' as const, to: toHex(toAccountKey), value: transferValue };
        });

    /// Signs and submits the paid stream's OpenChannel from the passkey
    /// wallet (payee-run topology: the operator is also the receiver).
    /// `request.persist` runs after signing and BEFORE submission, so a lost
    /// response can never orphan the escrow — the stream page persists the
    /// pending record there.
    const openStreamChannelNow = (request: OpenStreamChannelRequest): Promise<TxStatus | null> =>
        submitSigned('opening stream channel', async (nonce, activeWallet, senderAccountKey) => {
            const operatorAccount = parseAccountKeyHex(request.operatorHex);
            const voucherPublicKey = fromHex(request.voucherPublicKeyHex);
            const encoded = await encodeSignedOpenChannelTransaction(
                {
                    senderPublicKey: activeWallet.publicKey,
                    receiverAccountKey: operatorAccount,
                    operatorAccountKey: operatorAccount,
                    voucherPublicKey,
                    deposit: request.deposit,
                    expiry: request.expiry,
                    nonce,
                },
                activeWallet.sign,
            );
            const channel = await channelAddress(
                parseAccountKeyHex(senderAccountKey),
                operatorAccount,
                operatorAccount,
                voucherPublicKey,
                nonce,
            );
            const channelHex = toHex(channel);
            request.persist({
                channelHex,
                payerHex: senderAccountKey,
                openNonce: nonce.toString(),
                openTxDigestHex: encoded.digestHex,
                signedOpenTxHex: toHex(encoded.bytes),
            });
            return { encoded, kind: 'channel-open' as const, to: channelHex, value: request.deposit };
        });
    /// Signs and submits a post-expiry TimeoutChannel reclaiming a stream
    /// channel's escrow for the wallet.
    const reclaimStreamChannelNow = (
        request: ReclaimStreamChannelRequest,
    ): Promise<TxStatus | null> =>
        submitSigned('reclaiming stream deposit', async (nonce, activeWallet) => {
            const operatorAccount = parseAccountKeyHex(request.operatorHex);
            const encoded = await encodeSignedTimeoutChannelTransaction(
                {
                    senderPublicKey: activeWallet.publicKey,
                    receiverAccountKey: operatorAccount,
                    operatorAccountKey: operatorAccount,
                    voucherPublicKey: fromHex(request.voucherPublicKeyHex),
                    openNonce: BigInt(request.openNonce),
                    nonce,
                },
                activeWallet.sign,
            );
            return {
                encoded,
                kind: 'channel-timeout' as const,
                to: request.channelHex,
                value: 0n,
            };
        });
    // Stable identities over the freshest closures: `submitSigned` (and so
    // both builders above) is rebuilt every render, but the memoized
    // PaidStreamPage must not re-render for that.
    const openStreamChannel = useStableCallback(openStreamChannelNow);
    const reclaimStreamChannel = useStableCallback(reclaimStreamChannelNow);

    const submitMint = () =>
        submitSigned('forming mint', async (nonce, activeWallet, senderAccountKey) => {
            const encoded = await encodeSignedMintTransaction(
                {
                    senderPublicKey: activeWallet.publicKey,
                    amount: TEST_MINT_AMOUNT,
                    nonce,
                },
                activeWallet.sign,
            );
            // A mint credits the wallet itself; record it as self-addressed.
            return {
                encoded,
                kind: 'mint' as const,
                to: senderAccountKey,
                value: TEST_MINT_AMOUNT,
            };
        });

    return (
        <div className="app">
            <div className="app__container">
                <header className="app__header">
                    <h1 className="app__title">
                        <span className="accent">constantinople</span>
                    </h1>
                    <div className="app__header-actions">
                        <StatusBadge status={status} />
                        <span className="app__header-separator" aria-hidden="true">
                            ⬝
                        </span>
                        <button
                            aria-current={!isStreamOpen || lookupAccount ? 'page' : undefined}
                            className={
                                !isStreamOpen || lookupAccount
                                    ? 'wallet-trigger app__nav-link app__nav-link--active'
                                    : 'wallet-trigger app__nav-link'
                            }
                            onClick={() => {
                                clearAccountLookup();
                                setIsStreamOpen(false);
                            }}
                            type="button"
                        >
                            explorer
                        </button>
                        {operatorUrl && (
                            <>
                                <span className="app__header-separator" aria-hidden="true">
                                    ⬝
                                </span>
                                <button
                                    aria-current={isStreamOpen && !lookupAccount ? 'page' : undefined}
                                    className={
                                        isStreamOpen && !lookupAccount
                                            ? 'wallet-trigger app__nav-link app__nav-link--active'
                                            : 'wallet-trigger app__nav-link'
                                    }
                                    onClick={() => {
                                        clearAccountLookup();
                                        setIsStreamOpen(true);
                                    }}
                                    type="button"
                                >
                                    stream
                                </button>
                            </>
                        )}
                        <span className="app__header-separator" aria-hidden="true">
                            ⬝
                        </span>
                        <button className="wallet-trigger" onClick={() => setIsSearchOpen(true)}>
                            search
                        </button>
                        <span className="app__header-separator" aria-hidden="true">
                            ⬝
                        </span>
                        <button className="wallet-trigger" onClick={openWalletDialog}>
                            {walletAccountKey ? 'wallet' : 'sign in'}
                        </button>
                    </div>
                </header>
                <main className="app__main app__main--minimal">
                    <section className="explorer-stage" aria-label="live transaction throughput">
                        {isStreamOpen && !lookupAccount ? (
                            <PaidStreamPage
                                operatorUrl={operatorUrl}
                                mempoolUrl={mempoolUrl}
                                sqlUrl={indexerUrl}
                                chainHeight={blocks[0]?.height ?? null}
                                walletReady={wallet !== null && walletAccountKey !== null}
                                walletAccountHex={walletAccountKey}
                                walletBalance={account?.balance ?? null}
                                onOpenChannel={openStreamChannel}
                                onReclaimChannel={reclaimStreamChannel}
                                onOpenWallet={openWalletDialog}
                                onOpenAddress={openAccountPage}
                                onNotify={showToast}
                            />
                        ) : lookupAccount ? (
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
                                    totalKinds={totalKinds}
                                    sessionVouchers={sessionVouchers}
                                />
                                <BlockLog blocks={blocks} />
                            </>
                        )}
                    </section>
                </main>
                {isWalletOpen && (
                    <Modal title="wallet" ariaLabel="wallet" onClose={closeWalletDialog}>
                        <WalletPanel
                            wallet={wallet}
                            walletAccountKey={walletAccountKey}
                            walletStatus={walletStatus}
                            walletMessage={walletMessage}
                            account={account}
                            accountStatus={accountStatus}
                            accountMessage={accountMessage}
                            toKey={toKey}
                            value={value}
                            nonce={nonce}
                            submitMessage={submitMessage}
                            isSubmitting={isSubmitting}
                            onCreateWallet={handleCreateWallet}
                            onSignIn={handleSignIn}
                            onSignOut={handleSignOut}
                            onRefreshAccount={refreshAccount}
                            onRetryWalletKey={() => setWalletKeyAttempt((n) => n + 1)}
                            onCopy={copyValue}
                            onToKeyChange={setToKey}
                            onValueChange={setValue}
                            onSubmit={submitTransfer}
                            onMint={submitMint}
                        />
                        <TransactionHistory
                            transactions={history}
                            signedInAccountKey={walletAccountKey}
                            onCopy={copyValue}
                            onOpenAddress={openAccountPage}
                            verifyCertificates={verifyCertificates}
                        />
                    </Modal>
                )}
                {isSearchOpen && (
                    <Modal
                        title="search"
                        ariaLabel="account search"
                        panelClassName="modal__panel--search"
                        onClose={closeSearchDialog}
                    >
                        <AccountSearchPanel
                            accountInput={accountInput}
                            message={searchMessage}
                            onAccountInputChange={(value) => {
                                setAccountInput(value);
                                setSearchMessage('');
                            }}
                            onSubmit={submitAccountLookup}
                        />
                    </Modal>
                )}
                {toast && <TerminalToast message={toast} />}
            </div>
        </div>
    );
}

const AccountPage = memo(function AccountPage({
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
                <ProofDatum
                    label="finalized"
                    value={
                        target
                            ? `block ${target.height.toString()} · view ${target.view.toString()}`
                            : proof.detail
                    }
                />
                <ProofDatum
                    label="block hash"
                    value={target ? shortHex(toHex(target.blockDigest)) : '—'}
                />
                <ProofDatum
                    label="balance / nonce"
                    value={
                        proof.status === 'verified'
                            ? `${proof.balance.toString()} / ${proof.nonce.toString()}`
                            : proof.status === 'missing'
                              ? proof.detail
                              : '—'
                    }
                />
                <ProofDatum
                    label="proof"
                    value={
                        proof.status === 'verified'
                            ? `location ${proof.location.toString()} · ${proof.proofSizeBytes} B`
                            : proof.status === 'missing'
                                ? 'not available'
                                : '—'
                    }
                />
            </div>
            <div className="account-page__subhead">
                <span>transactions · page {pageNumber}</span>
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
                    <div className="account-tx-row account-tx-row--empty">no transactions</div>
                )}
                {transactions.map(({ row, proof: txProof }) => {
                    // Direction drives the row color; a channel open is a
                    // provisional reservation and a timeout releases one (the
                    // reclaimed amount lives in state, not the transaction),
                    // so both are dimmed instead.
                    const tone =
                        row.kind === 'channel-open' || row.kind === 'channel-timeout'
                            ? 'reservation'
                            : row.direction === 'received'
                              ? 'in'
                              : 'out';
                    return (
                    <div className={`account-tx-row account-tx-row--${tone}`} key={`${row.height.toString()}-${row.blockIndex}`}>
                        <div className="account-tx-row__main">
                            <span className={`account-tx-row__kind account-tx-row__kind--${row.kind}`}>
                                {row.kind.replace('-', ' ')}
                            </span>
                            <span className="account-tx-row__height">
                                block {row.height.toString()} · index {row.blockIndex}
                            </span>
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
                            <span className="account-tx-row__value">{txValueText(row.kind, row.value)}</span>
                            <span>nonce {row.nonce.toString()}</span>
                            <span>
                                {txProof.status === 'verified'
                                    ? `location ${txProof.location}`
                                    : 'location -'}
                            </span>
                            <span>proof</span>
                            <ProofMark proof={txProof} />
                        </div>
                    </div>
                    );
                })}
            </div>
        </section>
    );
});

// The value column means different things per kind: a transfer's amount, the
// escrow a channel open reserves, or the amount a channel close pays out. A
// timeout's reclaimed amount lives in state, not the transaction (the indexer
// stores 0), so it renders as intent rather than a bogus number.
function txValueText(kind: TransactionKind, value: bigint): string {
    switch (kind) {
        case 'channel-open':
            return `reserve ${value.toString()}`;
        case 'channel-close':
            return `settle ${value.toString()}`;
        case 'channel-timeout':
            return 'reclaims escrow';
        case 'mint':
            return `mint ${value.toString()}`;
        default:
            return `transfer ${value.toString()}`;
    }
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

function Modal({
    title,
    ariaLabel,
    panelClassName,
    onClose,
    children,
}: {
    title: string;
    ariaLabel: string;
    panelClassName?: string;
    onClose: () => void;
    children: React.ReactNode;
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
            <section
                className={panelClassName ? `modal__panel ${panelClassName}` : 'modal__panel'}
                role="dialog"
                aria-modal="true"
                aria-label={ariaLabel}
            >
                <header className="modal__header">
                    <h2>{title}</h2>
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
                <button type="submit">view account</button>
            </form>
            {message && <div className="account-search__message">{message}</div>}
        </section>
    );
}

function WalletPanel({
    wallet,
    walletAccountKey,
    walletStatus,
    walletMessage,
    account,
    accountStatus,
    accountMessage,
    toKey,
    value,
    nonce,
    submitMessage,
    isSubmitting,
    onCreateWallet,
    onSignIn,
    onSignOut,
    onRefreshAccount,
    onRetryWalletKey,
    onCopy,
    onToKeyChange,
    onValueChange,
    onSubmit,
    onMint,
}: {
    wallet: ActiveWallet | null;
    walletAccountKey: string | null;
    walletStatus: WalletStatus;
    walletMessage: string;
    account: AccountView | null;
    accountStatus: AccountStatus;
    accountMessage: string;
    toKey: string;
    value: string;
    nonce: string;
    submitMessage: string;
    isSubmitting: boolean;
    onCreateWallet: () => void;
    onSignIn: () => void;
    onSignOut: () => void;
    onRefreshAccount: () => void;
    onRetryWalletKey: () => void;
    onCopy: (value: string) => void;
    onToKeyChange: (value: string) => void;
    onValueChange: (value: string) => void;
    onSubmit: () => void;
    onMint: () => void;
}) {
    const balance = account?.balance ?? 0;
    const isWalletLoading = walletStatus === 'busy';
    const isAccountLoading = accountStatus === 'loading';
    const accountLoadFailed = accountStatus === 'error';
    // 'idle' covers the onboarding prompt and 'signed out' — neither is
    // worth echoing back.
    const showWalletMessage = walletStatus !== 'idle';
    const walletKeyFailed = walletAccountKey === null && walletStatus !== 'signed-in';

    if (!wallet) {
        return (
            <section className="wallet wallet--onboarding">
                <div className="wallet__onboarding">
                    <h3>sign in to transact</h3>
                    <p>sign in with a passkey, or create one. you'll approve each transaction.</p>
                    {showWalletMessage && (
                        <div className="wallet__status" role="status">
                            <SpinnerText active={isWalletLoading}>
                                {walletMessage}
                            </SpinnerText>
                        </div>
                    )}
                    <div className="wallet__actions">
                        <button
                            className="action-button action-button--primary"
                            onClick={onSignIn}
                        >
                            sign in
                        </button>
                        <button
                            className="action-button action-button--secondary"
                            onClick={onCreateWallet}
                        >
                            create passkey
                        </button>
                    </div>
                </div>
            </section>
        );
    }

    return (
        <section className="wallet">
            <div className="wallet__header">
                <div>
                    <div
                        className={
                            walletAccountKey
                                ? 'wallet__label wallet__label--connected'
                                : 'wallet__label'
                        }
                    >
                        {walletAccountKey
                            ? 'connected wallet'
                            : walletKeyFailed
                              ? 'wallet unavailable'
                              : 'connecting wallet'}
                    </div>
                    {walletKeyFailed && (
                        <div className="wallet__account-status">
                            <div className="wallet__status" role="alert">
                                {walletMessage}
                            </div>
                            <button className="wallet__retry" onClick={onRetryWalletKey} type="button">
                                retry
                            </button>
                        </div>
                    )}
                    {!walletKeyFailed && (isAccountLoading || accountLoadFailed) && (
                        <div className="wallet__account-status">
                            <div className="wallet__status" role="status">
                                <SpinnerText active={isAccountLoading}>
                                    {isAccountLoading ? 'updating…' : accountMessage}
                                </SpinnerText>
                            </div>
                            {accountLoadFailed && (
                                <button className="wallet__retry" onClick={onRefreshAccount} type="button">
                                    retry
                                </button>
                            )}
                        </div>
                    )}
                </div>
                <div className="wallet__actions">
                    <button className="action-button action-button--danger" onClick={onSignOut}>
                        sign out
                    </button>
                </div>
            </div>
            <div className="wallet__grid">
                <div className="wallet__cell">
                    <span>address</span>
                    <CopyableValue
                        disabled={!walletAccountKey}
                        plain
                        value={walletAccountKey?.toLowerCase() ?? 'loading…'}
                        onCopy={onCopy}
                    />
                </div>
                <div className="wallet__cell">
                    <span>balance</span>
                    <div className="wallet__balance">
                        <strong>{balance.toLocaleString()}</strong>
                        <button
                            className="action-button action-button--secondary wallet__mint"
                            disabled={!walletAccountKey || isSubmitting}
                            onClick={onMint}
                            title="mint 1,000 test funds to this wallet"
                            type="button"
                        >
                            + mint 1,000
                        </button>
                    </div>
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
                        disabled={!walletAccountKey || isSubmitting}
                        value={toKey}
                        onChange={(event) => onToKeyChange(event.target.value)}
                        placeholder="recipient address"
                        spellCheck={false}
                    />
                </label>
                <label>
                    <span>amount</span>
                    <input
                        disabled={!walletAccountKey || isSubmitting}
                        value={value}
                        onChange={(event) => onValueChange(event.target.value)}
                        inputMode="numeric"
                    />
                </label>
                <button
                    className="action-button action-button--primary transfer__submit"
                    disabled={!walletAccountKey || isSubmitting}
                    type="submit"
                >
                    send
                </button>
            </form>
            {submitMessage && (
                <div className="wallet__activity" role="status">
                    <SpinnerText active={isSubmitting}>
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
    if (normalizeAccountKeyHex(value) === account) {
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
}: {
    active: boolean;
    children: React.ReactNode;
}) {
    // Ticking lives here, in a leaf, so an active spinner never re-renders
    // anything but itself.
    const spinner = useBrailleSpinner(active);
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

const TransactionRecord = memo(function TransactionRecord({
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
    const included = submittedTransactionWasIncluded(tx.status, tx.rejected);
    const outcome =
        tx.finalizedHeight !== null
            ? `${tx.rejected ? 'rejected · ' : ''}block ${tx.finalizedHeight}`
            : null;
    const showDetail = tx.status === 'pending' || tx.status === 'error';
    const showVerification = tx.status === 'pending' || included;
    const dropped = tx.status === 'dropped';
    const showSecondary = showDetail || showVerification || dropped;

    return (
        <div className="tx-record">
            <div className="tx-record__primary">
                <span className="tx-record__label">tx</span>
                <CopyableValue value={tx.digest} onCopy={onCopy} />
                <span className="tx-record__label">from</span>
                <AddressValue value={tx.sender} onOpenAddress={onOpenAddress} />
                <span className="tx-record__label">to</span>
                <AddressValue
                    value={tx.to}
                    onOpenAddress={onOpenAddress}
                />
                <span className="tx-record__nonce">{txValueText(tx.kind, BigInt(tx.value))}</span>
                <span className="tx-record__nonce">nonce {tx.nonce}</span>
            </div>
            <div className="tx-record__time">
                <time dateTime={new Date(tx.submittedAt).toISOString()}>
                    {formatter.format(tx.submittedAt)}
                </time>
                {outcome && <span>{outcome}</span>}
            </div>
            {showSecondary && (
                <div className="tx-record__secondary">
                    {dropped && (
                        <span>
                            dropped <span className="tx-record__outcome-mark" aria-hidden="true">×</span>
                        </span>
                    )}
                    {showDetail && <span className="tx-record__detail">{tx.detail}</span>}
                    {showVerification && verifyCertificates && (
                        <>
                            {showDetail && <span className="tx-sep" aria-hidden="true">·</span>}
                            <span className="tx-label">finalized</span>
                            <CertificateCell
                                certificate={tx.certificate}
                                finalizedHeight={tx.finalizedHeight}
                                verifyCertificates={verifyCertificates}
                            />
                        </>
                    )}
                    {showVerification && (showDetail || verifyCertificates) && (
                        <span className="tx-sep" aria-hidden="true">·</span>
                    )}
                    {showVerification && (
                        <>
                            <span className="tx-label">proof</span>
                            <ProofCell ownsTx={ownsTx} proof={tx.proof} />
                        </>
                    )}
                    {(included || dropped) && tx.resolvedInMs !== null && (
                        <>
                            <span className="tx-sep" aria-hidden="true">·</span>
                            <span>took {tx.resolvedInMs}ms</span>
                        </>
                    )}
                </div>
            )}
        </div>
    );
});

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
        const finalizedHeight = statusHasHeight(status) ? status.height : null;
        return {
            ...tx,
            status: status.status,
            detail,
            // Structured, so nothing downstream has to parse `detail`.
            rejected:
                status.status === 'partially_finalized' && status.filtered.includes(digest),
            resolvedInMs: Date.now() - tx.submittedAt,
            finalizedHeight,
            certificate: nextBlockCertificateState(status),
            proof: nextProofState(status, digest),
        };
    });
}

function submittedTransactionWasIncluded(
    status: SubmittedTransaction['status'],
    rejected: boolean,
): boolean {
    return status === 'finalized' || (status === 'partially_finalized' && !rejected);
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
        submittedTransactionWasIncluded(tx.status, tx.rejected) &&
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
    return WAITING_BLOCK_CERTIFICATE;
}

function nextProofState(
    status: TxStatus,
    digest: string,
): TransactionProofState {
    if (status.status === 'dropped') {
        return { status: 'waiting', detail: 'not finalized' };
    }
    if (status.status === 'partially_finalized' && status.filtered.includes(digest)) {
        return { status: 'waiting', detail: 'not included' };
    }
    return { status: 'waiting', detail: 'waiting for QMDB proof' };
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
            const detail = errorMessage(error);
            if (!isRetryableAccountProofError(detail)) {
                throw error;
            }
            await sleep(350 + attempt * 150);
        }
    }
    throw lastError instanceof Error ? lastError : new Error(String(lastError));
}

function formatTxStatus(status: TxStatus, digest: string): string {
    if (status.status === 'finalized') {
        return `finalized at ${status.height}`;
    }
    if (status.status === 'partially_finalized') {
        if (status.filtered.includes(digest)) {
            return `rejected at ${status.height}: filtered ${shortHex(digest)}`;
        }
        return `partial at ${status.height}: filtered ${status.filtered.map(shortHex).join(', ')}`;
    }
    return status.status;
}

/// Builds the explorer location for `account` (null clears the lookup) and
/// pushes it when it differs from the current one.
function pushAccountLocation(account: string | null) {
    const url = new URL(window.location.href);
    if (account === null) {
        url.searchParams.delete('account');
    } else {
        url.searchParams.set('account', account);
    }
    const nextLocation = `${url.pathname}${url.search}${url.hash}`;
    if (nextLocation !== `${window.location.pathname}${window.location.search}${window.location.hash}`) {
        window.history.pushState(null, '', nextLocation);
    }
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
    const fromQuery = queryAccount === null ? null : normalizeAccountKeyHex(queryAccount);
    if (fromQuery) return fromQuery;

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

    const status = normalizeSubmittedTransactionStatus(transaction.status);
    if (status === null) return null;
    const hasOutcome =
        status === 'finalized' || status === 'partially_finalized' || status === 'dropped';
    const storedResolution =
        typeof transaction.resolvedInMs === 'number'
            ? transaction.resolvedInMs
            : transaction.finalizedInMs;
    const resolvedInMs =
        hasOutcome && typeof storedResolution === 'number' ? storedResolution : null;
    const finalizedHeight =
        status !== 'dropped' && typeof transaction.finalizedHeight === 'number'
            ? transaction.finalizedHeight
            : null;
    // Legacy migration: records persisted before the explicit `rejected`
    // flag encoded rejection only in the display string.
    const rejected =
        typeof transaction.rejected === 'boolean'
            ? transaction.rejected
            : status === 'partially_finalized' && transaction.detail.startsWith('rejected');

    return {
        digest: transaction.digest,
        sender: transaction.sender,
        kind: normalizeTransactionKind(transaction.kind),
        to: transaction.to,
        value: transaction.value,
        nonce: transaction.nonce,
        submittedAt: transaction.submittedAt,
        resolvedInMs,
        status,
        detail: transaction.detail,
        rejected,
        finalizedHeight,
        certificate: normalizeBlockCertificate(transaction.certificate, finalizedHeight),
        proof: normalizeTransactionProof(transaction.proof),
    };
}

function normalizeSubmittedTransactionStatus(
    value: unknown,
): SubmittedTransaction['status'] | null {
    switch (value) {
        case 'pending':
        case 'finalized':
        case 'partially_finalized':
        case 'dropped':
        case 'error':
            return value;
        default:
            return null;
    }
}

// History stored before the kind field existed only held transfers.
function normalizeTransactionKind(value: unknown): TransactionKind {
    switch (value) {
        case 'channel-open':
        case 'channel-close':
        case 'channel-timeout':
        case 'mint':
            return value;
        default:
            return 'transfer';
    }
}

/// Whether `value` is an already-normalized account key (exactly 32 bytes
/// of lowercase hex, no `0x`, no padding) — the form persisted records use.
function isAccountKeyHex(value: string): boolean {
    return normalizeAccountKeyHex(value) === value;
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
        return WAITING_FINALIZATION_CERTIFICATE;
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
    return WAITING_FINALIZATION_CERTIFICATE;
}

function StatusBadge({ status }: { status: Status }) {
    if (status.kind === 'connecting') {
        return (
            <span className="app__status">
                <SpinnerText active>connecting</SpinnerText>
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
    totalKinds,
    sessionVouchers,
    observedRateWindow,
}: {
    blocks: ObservedBlock[];
    totalBlocksObserved: number;
    totalTxObserved: number;
    totalKinds: BlockKindCounts;
    sessionVouchers: number | null;
    observedRateWindow: ObservedRateWindow;
}) {
    const stats = useMemo(
        () => buildExplorerStats(blocks, totalBlocksObserved, totalTxObserved),
        [blocks, totalBlocksObserved, totalTxObserved],
    );
    const [kindsOpen, setKindsOpen] = useState(false);
    const count = (value: number) => (totalTxObserved === 0 ? '—' : value.toLocaleString());
    return (
        <>
            <dl className="observed-stats" aria-label="explorer statistics">
                <ExplorerStat label="height" value={stats.latestHeight} />
                <ExplorerStat
                    label="tx/sec"
                    value={formatObservedTxPerSecond(totalTxObserved, observedRateWindow)}
                />
                <div className="observed-stat">
                    <dt className="observed-stat__label">
                        <button
                            className="observed-stat__toggle"
                            type="button"
                            aria-expanded={kindsOpen}
                            title="break down by transaction kind"
                            onClick={() => setKindsOpen((open) => !open)}
                        >
                            tx seen {kindsOpen ? '▾' : '▸'}
                        </button>
                    </dt>
                    <dd className="observed-stat__value">{stats.totalTxObserved}</dd>
                </div>
                <ExplorerStat label="tx/block" value={stats.avgTxPerBlock} />
                {sessionVouchers !== null && (
                    <ExplorerStat
                        label="vouchers*"
                        value={sessionVouchers.toLocaleString()}
                        title={OPERATOR_REPORTED_NOTE}
                    />
                )}
            </dl>
            {kindsOpen && (
                <dl
                    className="observed-stats observed-stats--kinds"
                    aria-label="transactions by kind"
                >
                    {KIND_KEYS.map((key) => (
                        <ExplorerStat
                            key={key}
                            label={KIND_LABELS[key]}
                            value={count(totalKinds[key])}
                        />
                    ))}
                </dl>
            )}
        </>
    );
});

// Hover text for the operator-reported stats — the one pair of numbers on
// the page that is not proof-verified.
const OPERATOR_REPORTED_NOTE =
    'off-chain vouchers reported by the operator since this page loaded.';

function ExplorerStat({ label, value, title }: { label: string; value: string; title?: string }) {
    return (
        <div className="observed-stat" title={title}>
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
    avgTxPerBlock: string;
} {
    let latest: bigint | null = null;
    for (const block of blocks) {
        if (latest === null || block.height > latest) {
            latest = block.height;
        }
    }

    const avg = totalBlocksObserved === 0 ? 0 : totalTxObserved / totalBlocksObserved;
    return {
        latestHeight: latest?.toString() ?? '—',
        totalTxObserved: totalTxObserved === 0 ? '—' : totalTxObserved.toLocaleString(),
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
    const hash = useMemo(() => toHex(block.digest), [block.digest]);
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
