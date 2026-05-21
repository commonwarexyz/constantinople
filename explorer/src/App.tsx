import { useEffect, useMemo, useRef, useState } from 'react';
import {
    encodeSignedTransaction,
    encodeTransactionBatch,
    parsePublicKeyHex,
    parseU64,
} from './codec';
import {
    configureCertificateVerification,
    requestCertificateVerification,
    subscribeCertificateVerification,
} from './certificateClient';
import { type ObservedBlock, subscribeBlocks } from './indexer';
import {
    fetchAccount,
    fetchTransactionStatus,
    submitTransactions,
    type AccountView,
    type SubmitResponse,
    type TxStatus,
} from './mempool';
import {
    fetchAndVerifyTransactionProof,
    type VerifiedTransactionProof,
} from './qmdb';
import {
    clearSession,
    createWallet,
    signInWithPasskey,
    type ActiveWallet,
} from './wallet';

/** Most recent batches to keep in the live feed. Old entries fall off the table. */
const MAX_ROWS = 200;
/** Height (rows) of the throughput histogram at the top of the page. */
const HISTOGRAM_HEIGHT = 8;
/**
 * Upper bound on the responsive histogram column count. We measure the
 * container width and divide by 1ch to derive the actual column count, but
 * keep an absolute ceiling so each column still represents a meaningful
 * slice of recent history on ultra-wide displays.
 */
const HISTOGRAM_MAX_COLUMNS = 400;
/** Initial column count used before the ResizeObserver fires its first measurement. */
const HISTOGRAM_INITIAL_COLUMNS = 80;
/** 8-step unicode block ramp; index 0 is empty so unused cells stay blank. */
const BLOCK_GLYPHS = ' ▁▂▃▄▅▆▇█';
const BRAILLE_SPINNER = ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏'];
const LIVE_STATUS_TEXT = '>>> live';
const LIVE_STATUS_STAGGER_MS = 50;
const LIVE_STATUS_BLANK_MS = 100;
const LIVE_STATUS_PAUSE_MS = 550;
const BLOCK_FLUSH_INTERVAL_MS = 50;
const CERTIFICATE_FLUSH_INTERVAL_MS = 100;
const MAX_CERTIFICATE_CACHE = 1_000;

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
const LOCAL_HISTORY_KEY = 'constantinople.submitted-transactions.v1';

const indexerUrl = import.meta.env.VITE_SQL_URL ?? DEFAULT_SQL_URL;
const qmdbUrl = import.meta.env.VITE_QMDB_URL ?? DEFAULT_QMDB_URL;
const storeUrl = import.meta.env.VITE_STORE_URL ?? DEFAULT_STORE_URL;
const simplexVerificationMaterial = import.meta.env.VITE_SIMPLEX_VERIFICATION_MATERIAL ?? '';
const mempoolUrl = import.meta.env.VITE_MEMPOOL_URL ?? DEFAULT_MEMPOOL_URL;

interface SubmittedTransaction {
    readonly sender: string | null;
    readonly digest: string;
    readonly to: string;
    readonly value: string;
    readonly nonce: string;
    readonly submittedAt: number;
    readonly finalizedInMs: number | null;
    readonly status: 'pending' | 'accepted' | 'finalized' | 'partially_finalized' | 'dropped' | 'error';
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

interface ObservedRateWindow {
    readonly firstBlockAt: number | null;
    readonly latestBlockAt: number | null;
}

type BlockCertificateByHeight = Record<string, BlockCertificateState>;

interface CertificateUpdate {
    readonly height: number;
    readonly certificate: BlockCertificateState;
}

export default function App() {
    const [blocks, setBlocks] = useState<ObservedBlock[]>([]);
    // Cumulative counters across every block we've ever observed on the
    // stream. Tracked independently of `blocks` so the "observed" stats
    // keep climbing when older entries roll off the MAX_ROWS buffer.
    const [blocksObserved, setBlocksObserved] = useState(0);
    const [totalTxObserved, setTotalTxObserved] = useState(0);
    const [observedRateWindow, setObservedRateWindow] = useState<ObservedRateWindow>({
        firstBlockAt: null,
        latestBlockAt: null,
    });
    const [status, setStatus] = useState<Status>({ kind: 'connecting' });
    const [blockCertificates, setBlockCertificates] = useState<BlockCertificateByHeight>({});
    const [isWalletOpen, setIsWalletOpen] = useState(false);
    const [wallet, setWallet] = useState<ActiveWallet | null>(null);
    const [walletMessage, setWalletMessage] = useState('sign in or create a wallet');
    const [account, setAccount] = useState<AccountView | null>(null);
    const [accountMessage, setAccountMessage] = useState('account metadata unavailable');
    const [toKey, setToKey] = useState('');
    const [value, setValue] = useState('1');
    const [nonce, setNonce] = useState('0');
    const [submitMessage, setSubmitMessage] = useState('');
    const [isSubmitting, setIsSubmitting] = useState(false);
    const [history, setHistory] = useState<SubmittedTransaction[]>(() => readHistory());
    const [copiedValue, setCopiedValue] = useState('');
    const [copyToast, setCopyToast] = useState('');
    const pendingBlocksRef = useRef<ObservedBlock[]>([]);
    const blockFlushTimeoutRef = useRef<number | null>(null);
    const pendingCertificatesRef = useRef<CertificateUpdate[]>([]);
    const certificateFlushTimeoutRef = useRef<number | null>(null);
    const copiedValueTimeoutRef = useRef<number | null>(null);
    const copyToastTimeoutRef = useRef<number | null>(null);
    const isWalletBusy =
        walletMessage === 'opening passkey prompt' ||
        accountMessage === 'loading account metadata' ||
        isSubmitting;
    const spinner = useBrailleSpinner(status.kind === 'connecting' || isWalletBusy);
    const signedInPublicKey = wallet?.publicKeyHex ?? null;

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
            setBlocksObserved((current) => current + flushed.length);
            setTotalTxObserved(
                (current) =>
                    current + flushed.reduce((total, block) => total + block.txCount, 0),
            );
            setObservedRateWindow((current) => ({
                firstBlockAt: current.firstBlockAt ?? flushed[0].arrivedAt,
                latestBlockAt: flushed[flushed.length - 1].arrivedAt,
            }));
            setStatus({ kind: 'live' });
        }, BLOCK_FLUSH_INTERVAL_MS);
    };

    const queueCertificateUpdate = (update: CertificateUpdate) => {
        pendingCertificatesRef.current.push(update);
        if (certificateFlushTimeoutRef.current !== null) return;

        certificateFlushTimeoutRef.current = window.setTimeout(() => {
            certificateFlushTimeoutRef.current = null;
            const flushed = pendingCertificatesRef.current;
            pendingCertificatesRef.current = [];
            if (flushed.length === 0) return;

            setBlockCertificates((current) =>
                flushed.reduce(
                    (certificates, entry) =>
                        updateObservedBlockCertificate(
                            entry.height,
                            entry.certificate,
                            certificates,
                        ),
                    current,
                ),
            );
        }, CERTIFICATE_FLUSH_INTERVAL_MS);
    };

    useEffect(() => {
        configureCertificateVerification({
            storeUrl,
            simplexVerificationMaterial,
        });
    }, []);

    useEffect(() => {
        requestCertificateVerification(certificateVerificationHeights(blocks, history, blockCertificates));
    }, [blocks, history, blockCertificates]);

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
        writeHistory(history);
    }, [history]);

    useEffect(() => {
        setBlockCertificates((current) => pruneBlockCertificates(blocks, current));
    }, [blocks]);

    useEffect(() => {
        return subscribeCertificateVerification((response) => {
            if (response.height === 0) return;
            if (response.kind === 'verified') {
                queueCertificateUpdate({
                    height: response.height,
                    certificate: {
                        status: 'verified',
                        detail: `verified at height ${response.height}`,
                        height: String(response.height),
                        view: response.view,
                    },
                });
                return;
            }
            queueCertificateUpdate({
                height: response.height,
                certificate: { status: 'error', detail: response.detail },
            });
        });
    }, []);

    useEffect(() => {
        const signedInSender = wallet?.publicKeyHex ?? null;
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
            simplexVerificationMaterial,
            digest: tx.digest,
            height: tx.finalizedHeight,
        })
            .then((proof) => {
                setHistory((current) =>
                    updateBlockCertificateByHeight(
                        Number(proof.height),
                        verifiedBlockCertificateState(proof),
                        updateTransactionProof(tx.digest, verifiedProofState(proof), current),
                    ),
                );
                setBlockCertificates((current) =>
                    updateObservedBlockCertificate(
                        Number(proof.height),
                        verifiedBlockCertificateState(proof),
                        current,
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
    }, [history, wallet]);

    useEffect(() => {
        return () => {
            if (blockFlushTimeoutRef.current !== null) {
                window.clearTimeout(blockFlushTimeoutRef.current);
            }
            if (certificateFlushTimeoutRef.current !== null) {
                window.clearTimeout(certificateFlushTimeoutRef.current);
            }
            if (copiedValueTimeoutRef.current !== null) {
                window.clearTimeout(copiedValueTimeoutRef.current);
            }
            if (copyToastTimeoutRef.current !== null) {
                window.clearTimeout(copyToastTimeoutRef.current);
            }
        };
    }, []);

    useEffect(() => {
        if (!wallet) {
            setAccount(null);
            setAccountMessage('account metadata unavailable');
            return;
        }

        let cancelled = false;
        setAccountMessage('loading account metadata');

        fetchAccount(mempoolUrl, wallet.publicKeyHex)
            .then((nextAccount) => {
                if (cancelled) return;
                setAccount(nextAccount);
                const nextNonce = nextAccount?.nonce ?? 0;
                setNonce(String(nextNonce));
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
            setNonce(String(nextAccount?.nonce ?? 0));
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
            setWalletMessage('wallet created');
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
            if (copiedValueTimeoutRef.current !== null) {
                window.clearTimeout(copiedValueTimeoutRef.current);
            }
            if (copyToastTimeoutRef.current !== null) {
                window.clearTimeout(copyToastTimeoutRef.current);
            }

            setCopiedValue(value);
            setCopyToast(`copied "${value}" to clipboard`);
            copiedValueTimeoutRef.current = window.setTimeout(() => {
                setCopiedValue((current) => (current === value ? '' : current));
                copiedValueTimeoutRef.current = null;
            }, 1_000);
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

    const submitTransfer = async () => {
        if (!wallet || isSubmitting) return;

        setIsSubmitting(true);
        setSubmitMessage('forming transaction');
        try {
            const parsedToKey = parsePublicKeyHex(toKey);
            const parsedValue = parseU64(value, 'value');
            const parsedNonce = parseU64(nonce, 'nonce');
            const encoded = await encodeSignedTransaction(
                {
                    senderPublicKey: wallet.publicKey,
                    toPublicKey: parsedToKey,
                    value: parsedValue,
                    nonce: parsedNonce,
                },
                wallet.sign,
            );
            const pending: SubmittedTransaction = {
                sender: wallet.publicKeyHex,
                digest: encoded.digestHex,
                to: toKey.trim().replace(/^0x/i, '').toLowerCase(),
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

            const submitResponse = await submitTransactions(mempoolUrl, encodeTransactionBatch([encoded.bytes]));
            let txStatus: TxStatus;
            if ('batch_id' in submitResponse) {
                const accepted: TxStatus = { status: 'accepted', digests: submitResponse.digests };
                setHistory((current) =>
                    updateTransactionStatus(encoded.digestHex, accepted, 'accepted by relayer', current),
                );
                setSubmitMessage('accepted by relayer');
                txStatus = await pollTransactionStatus(mempoolUrl, submitResponse);
            } else {
                txStatus = submitResponse;
            }
            const detail = formatTxStatus(txStatus, encoded.digestHex);
            setHistory((current) => updateTransactionStatus(encoded.digestHex, txStatus, detail, current));
            setSubmitMessage(detail);
            await refreshAccount();
        } catch (error) {
            setSubmitMessage(error instanceof Error ? error.message : String(error));
        } finally {
            setIsSubmitting(false);
        }
    };

    return (
        <div className="app">
            <div className="app__container">
                <header className="app__header">
                    <h1 className="app__title">
                        <span className="accent">constantinople</span> / explorer
                    </h1>
                    <div className="app__header-actions">
                        <StatusBadge status={status} spinner={spinner} />
                        <span className="app__header-separator" aria-hidden="true">
                            ⬝
                        </span>
                        <button className="wallet-trigger" onClick={() => setIsWalletOpen(true)}>
                            {wallet ? `wallet ${shortHex(wallet.publicKeyHex)}` : 'wallet'}
                        </button>
                    </div>
                </header>
                <SummaryPanel
                    blocks={blocks}
                    blocksObserved={blocksObserved}
                    totalTxObserved={totalTxObserved}
                    observedRateWindow={observedRateWindow}
                />
                <Histogram blocks={blocks} />
                <main className="app__main">
                    <BlockTable blocks={blocks} certificates={blockCertificates} />
                </main>
                {isWalletOpen && (
                    <WalletModal onClose={() => setIsWalletOpen(false)}>
                        <WalletPanel
                            wallet={wallet}
                            walletMessage={walletMessage}
                            account={account}
                            accountMessage={accountMessage}
                            toKey={toKey}
                            value={value}
                            nonce={nonce}
                            submitMessage={submitMessage}
                            isSubmitting={isSubmitting}
                            spinner={spinner}
                            copiedValue={copiedValue}
                            onCreateWallet={handleCreateWallet}
                            onSignIn={handleSignIn}
                            onSignOut={handleSignOut}
                            onRefreshAccount={refreshAccount}
                            onCopy={copyValue}
                            onToKeyChange={setToKey}
                            onValueChange={setValue}
                            onSubmit={submitTransfer}
                        />
                        <TransactionHistory
                            transactions={history}
                            signedInPublicKey={signedInPublicKey}
                            copiedValue={copiedValue}
                            onCopy={copyValue}
                        />
                    </WalletModal>
                )}
                {copyToast && <TerminalToast message={copyToast} />}
            </div>
        </div>
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
    walletMessage,
    account,
    accountMessage,
    toKey,
    value,
    nonce,
    submitMessage,
    isSubmitting,
    spinner,
    copiedValue,
    onCreateWallet,
    onSignIn,
    onSignOut,
    onRefreshAccount,
    onCopy,
    onToKeyChange,
    onValueChange,
    onSubmit,
}: {
    wallet: ActiveWallet | null;
    walletMessage: string;
    account: AccountView | null;
    accountMessage: string;
    toKey: string;
    value: string;
    nonce: string;
    submitMessage: string;
    isSubmitting: boolean;
    spinner: string;
    copiedValue: string;
    onCreateWallet: () => void;
    onSignIn: () => void;
    onSignOut: () => void;
    onRefreshAccount: () => void;
    onCopy: (value: string) => void;
    onToKeyChange: (value: string) => void;
    onValueChange: (value: string) => void;
    onSubmit: () => void;
}) {
    const balance = account?.balance ?? 100;
    const isWalletLoading = walletMessage === 'opening passkey prompt';
    const isAccountLoading = accountMessage === 'loading account metadata';

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
                    {wallet && <button onClick={onSignOut}>sign out</button>}
                </div>
            </div>
            <div className="wallet__grid">
                <div className="wallet__cell span-2">
                    <span>account</span>
                    <CopyableValue
                        disabled={!wallet}
                        plain
                        flashOnCopy
                        copiedValue={copiedValue}
                        value={wallet?.publicKeyHex ?? 'not authenticated'}
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
                        placeholder="Public key of recipient"
                        spellCheck={false}
                        disabled={!wallet || isSubmitting}
                    />
                </label>
                <label>
                    <span>amount</span>
                    <input
                        value={value}
                        onChange={(event) => onValueChange(event.target.value)}
                        inputMode="numeric"
                        disabled={!wallet || isSubmitting}
                    />
                </label>
                <button className="transfer__submit" disabled={!wallet || isSubmitting} type="submit">
                    {isSubmitting ? 'submitting' : 'submit'}
                </button>
            </form>
            {submitMessage && (
                <div className="wallet__status">
                    <SpinnerText active={isSubmitting} spinner={spinner}>
                        {submitMessage}
                    </SpinnerText>
                </div>
            )}
        </section>
    );
}

function CopyableValue({
    disabled = false,
    flashOnCopy = true,
    plain = false,
    copiedValue,
    value,
    onCopy,
}: {
    disabled?: boolean;
    flashOnCopy?: boolean;
    plain?: boolean;
    copiedValue: string;
    value: string;
    onCopy: (value: string) => void;
}) {
    const isCopied = flashOnCopy && copiedValue === value;
    const className = [
        'copyable',
        plain ? 'copyable--plain' : '',
        isCopied ? 'is-copied' : '',
    ]
        .filter(Boolean)
        .join(' ');

    return (
        <button
            className={className}
            disabled={disabled}
            onClick={() => onCopy(value)}
            type="button"
        >
            <span className="copyable__value">{value}</span>
        </button>
    );
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
    signedInPublicKey,
    copiedValue,
    onCopy,
}: {
    transactions: SubmittedTransaction[];
    signedInPublicKey: string | null;
    copiedValue: string;
    onCopy: (value: string) => void;
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
        return <section className="tx-history empty">no submitted transactions for this browser</section>;
    }

    return (
        <section className="tx-history">
            <div className="tx-history__title">submitted transactions</div>
            <table className="tx-table">
                <thead>
                    <tr>
                        <th className="tx-col-digest">digest</th>
                        <th className="tx-col-to">to</th>
                        <th className="tx-col-amount">amount</th>
                        <th className="tx-col-nonce">nonce</th>
                        <th className="tx-col-status">status</th>
                        <th className="tx-col-cert">cert</th>
                        <th className="tx-col-proof">proof</th>
                        <th className="tx-col-latency">
                            <AsciiTooltip
                                tooltip="delta between finalization response and submission timestamp"
                            >
                                finalization latency
                            </AsciiTooltip>
                        </th>
                        <th className="tx-col-time">time</th>
                    </tr>
                </thead>
                <tbody>
                    {transactions.map((tx) => (
                        <TransactionRow
                            key={tx.digest}
                            copiedValue={copiedValue}
                            formatter={formatter}
                            onCopy={onCopy}
                            signedInPublicKey={signedInPublicKey}
                            tx={tx}
                        />
                    ))}
                </tbody>
            </table>
        </section>
    );
}

function TransactionRow({
    copiedValue,
    formatter,
    onCopy,
    signedInPublicKey,
    tx,
}: {
    copiedValue: string;
    formatter: Intl.DateTimeFormat;
    onCopy: (value: string) => void;
    signedInPublicKey: string | null;
    tx: SubmittedTransaction;
}) {
    const ownsTx = tx.sender !== null && tx.sender === signedInPublicKey;
    return (
        <tr>
            <td>
                <CopyableValue copiedValue={copiedValue} value={tx.digest} onCopy={onCopy} />
            </td>
            <td>
                <CopyableValue copiedValue={copiedValue} value={tx.to} onCopy={onCopy} />
            </td>
            <td>{tx.value}</td>
            <td>{tx.nonce}</td>
            <td>{tx.detail}</td>
            <td>
                <CertificateCell certificate={tx.certificate} finalizedHeight={tx.finalizedHeight} />
            </td>
            <td>
                <ProofCell ownsTx={ownsTx} proof={tx.proof} />
            </td>
            <td>{tx.finalizedInMs === null ? 'pending' : `${tx.finalizedInMs}ms`}</td>
            <td>{formatter.format(tx.submittedAt)}</td>
        </tr>
    );
}

function CertificateCell({
    certificate,
    finalizedHeight,
}: {
    certificate: BlockCertificateState;
    finalizedHeight: number | null;
}) {
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
            <span className="tx-proof-error" aria-label={proof.detail} title={proof.detail}>
                !
            </span>
        );
    }
    return (
        <span className="tx-proof-spinner" aria-label={proof.detail} title={proof.detail} />
    );
}

function AsciiTooltip({
    children,
    tooltip,
}: {
    children: React.ReactNode;
    tooltip: string;
}) {
    return (
        <span className="ascii-tooltip">
            <span className="ascii-tooltip__hint" aria-hidden="true">
                ?{' '}
            </span>
            {children}
            <span className="ascii-tooltip__box" role="tooltip">
                <span className="ascii-tooltip__corner">+ </span>
                <span>{tooltip}</span>
            </span>
        </span>
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
    if (next.length > MAX_ROWS) {
        next.length = MAX_ROWS;
    }
    return next;
}

function compareBlockHeightDesc(a: bigint, b: bigint): number {
    if (a > b) return -1;
    if (a < b) return 1;
    return 0;
}

function blockCertificateForHeight(
    height: bigint,
    certificates: BlockCertificateByHeight,
): BlockCertificateState {
    return certificates[height.toString()] ?? defaultBlockCertificate(Number(height));
}

function pruneBlockCertificates(
    blocks: ObservedBlock[],
    certificates: BlockCertificateByHeight,
): BlockCertificateByHeight {
    const visibleHeights = new Set(blocks.map((block) => block.height.toString()));
    const entries = Object.entries(certificates)
        .filter(([height]) => visibleHeights.has(height))
        .concat(recentCertificateEntries(certificates, visibleHeights));
    if (entries.length === Object.keys(certificates).length) {
        return certificates;
    }
    return Object.fromEntries(entries);
}

function recentCertificateEntries(
    certificates: BlockCertificateByHeight,
    visibleHeights: Set<string>,
): [string, BlockCertificateState][] {
    return Object.entries(certificates)
        .filter(([height]) => !visibleHeights.has(height))
        .sort(([a], [b]) => Number(b) - Number(a))
        .slice(0, MAX_CERTIFICATE_CACHE);
}

function updateObservedBlockCertificate(
    height: number,
    certificate: BlockCertificateState,
    certificates: BlockCertificateByHeight,
): BlockCertificateByHeight {
    return {
        ...certificates,
        [String(height)]: certificate,
    };
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
        return {
            ...tx,
            status: status.status,
            detail,
            finalizedInMs: status.status === 'accepted' ? null : Date.now() - tx.submittedAt,
            finalizedHeight: statusHasHeight(status) ? status.height : tx.finalizedHeight,
            certificate: nextBlockCertificateState(status, tx.certificate),
            proof: nextProofState(status, digest, tx.proof),
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
    return current.map((tx) => (tx.finalizedHeight === height ? { ...tx, certificate } : tx));
}

function certificateVerificationHeights(
    blocks: readonly ObservedBlock[],
    history: readonly SubmittedTransaction[],
    certificates: BlockCertificateByHeight,
): number[] {
    const heights = new Set<number>();
    for (const block of blocks) {
        const height = Number(block.height);
        if (!Number.isSafeInteger(height)) continue;
        if (shouldVerifyCertificate(blockCertificateForHeight(block.height, certificates))) {
            heights.add(height);
        }
    }
    for (const tx of history) {
        if (tx.finalizedHeight === null) continue;
        if (shouldVerifyCertificate(tx.certificate)) {
            heights.add(tx.finalizedHeight);
        }
    }
    return [...heights].sort((left, right) => right - left);
}

function shouldVerifyCertificate(certificate: BlockCertificateState): boolean {
    return (
        certificate.status === 'waiting' ||
        certificate.status === 'fetching' ||
        (certificate.status === 'error' && isRetryableCertificateError(certificate.detail))
    );
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
            (tx.status === 'partially_finalized' && !tx.detail.startsWith('rejected'))) &&
        (tx.proof.status === 'waiting' ||
            (tx.proof.status === 'error' && isRetryableProofError(tx.proof.detail)))
    );
}

function hasFetchingProof(
    transactions: SubmittedTransaction[],
    signedInSender: string | null,
): boolean {
    if (signedInSender === null) return false;
    return transactions.some((tx) => tx.sender === signedInSender && tx.proof.status === 'fetching');
}

function isRetryableProofError(detail: string): boolean {
    return /tx_meta missing|finalization missing|QMDB transaction proof response missing|failed to decode Simplex identity|failed to decode Simplex verification material|Simplex verification material contains trailing bytes|out_of_range|unavailable|fetch/i.test(
        detail,
    );
}

function isRetryableCertificateError(detail: string): boolean {
    return /finalization missing|not found|missing proof|failed to decode Simplex identity|failed to decode Simplex verification material|Simplex verification material contains trailing bytes|out_of_range|unavailable|fetch/i.test(
        detail,
    );
}

function nextBlockCertificateState(
    status: TxStatus,
    current: BlockCertificateState,
): BlockCertificateState {
    if (status.status === 'accepted') return current;
    if (status.status === 'dropped') {
        return { status: 'waiting', detail: 'not finalized' };
    }
    return { status: 'waiting', detail: 'waiting for block certificate' };
}

function nextProofState(
    status: TxStatus,
    digest: string,
    current: TransactionProofState,
): TransactionProofState {
    if (status.status === 'accepted') return current;
    if (status.status === 'dropped') {
        return { status: 'waiting', detail: 'not finalized' };
    }
    if (status.status === 'partially_finalized' && status.filtered.includes(digest)) {
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

async function pollTransactionStatus(baseUrl: string, submission: SubmitResponse): Promise<TxStatus> {
    for (;;) {
        await sleep(1_000);
        const status = await fetchTransactionStatus(baseUrl, submission.batch_id);
        if (status === null || status.status === 'accepted') {
            continue;
        }
        return status;
    }
}

function formatTxStatus(status: TxStatus, digest: string): string {
    if (status.status === 'accepted') {
        return 'accepted';
    }
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

function sleep(ms: number): Promise<void> {
    return new Promise((resolve) => window.setTimeout(resolve, ms));
}

function shortHex(value: string): string {
    return value.length <= 18 ? value : `${value.slice(0, 10)}…${value.slice(-8)}`;
}

function readHistory(): SubmittedTransaction[] {
    const raw = window.localStorage.getItem(LOCAL_HISTORY_KEY);
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

function writeHistory(history: SubmittedTransaction[]) {
    window.localStorage.setItem(LOCAL_HISTORY_KEY, JSON.stringify(history));
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

function useLiveStatusText(active: boolean): string[] {
    const [symbols, setSymbols] = useState(() => [...LIVE_STATUS_TEXT]);

    useEffect(() => {
        if (!active) {
            setSymbols([...LIVE_STATUS_TEXT]);
            return;
        }

        const timeouts: number[] = [];
        const pulseIndexes = [...LIVE_STATUS_TEXT]
            .map((symbol, index) => (symbol === ' ' ? -1 : index))
            .filter((index) => index >= 0);

        const pulseSymbol = (index: number) => {
            setSymbols((current) => current.map((symbol, symbolIndex) => (symbolIndex === index ? ' ' : symbol)));
            timeouts.push(
                window.setTimeout(() => {
                    setSymbols((current) =>
                        current.map((symbol, symbolIndex) =>
                            symbolIndex === index ? LIVE_STATUS_TEXT[index] : symbol,
                        ),
                    );
                }, LIVE_STATUS_BLANK_MS),
            );
        };

        const animate = () => {
            for (let groupIndex = 0; groupIndex < pulseIndexes.length; groupIndex++) {
                const symbolIndex = pulseIndexes[groupIndex];
                timeouts.push(window.setTimeout(() => pulseSymbol(symbolIndex), groupIndex * LIVE_STATUS_STAGGER_MS));
            }

            const totalTime = (pulseIndexes.length - 1) * LIVE_STATUS_STAGGER_MS + LIVE_STATUS_BLANK_MS;
            timeouts.push(window.setTimeout(animate, totalTime + LIVE_STATUS_PAUSE_MS));
        };

        animate();
        return () => {
            for (const timeout of timeouts) {
                window.clearTimeout(timeout);
            }
        };
    }, [active]);

    return symbols;
}

function normalizeSubmittedTransaction(value: unknown): SubmittedTransaction | null {
    if (typeof value !== 'object' || value === null) {
        return null;
    }

    const transaction = value as Record<string, unknown>;
    if (
        typeof transaction.digest !== 'string' ||
        typeof transaction.to !== 'string' ||
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
        sender: typeof transaction.sender === 'string' ? transaction.sender : null,
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
        (certificate.status === 'waiting' ||
            certificate.status === 'fetching' ||
            certificate.status === 'error') &&
        typeof certificate.detail === 'string'
    ) {
        return { status: certificate.status, detail: certificate.detail };
    }
    return defaultBlockCertificate(finalizedHeight);
}

function defaultBlockCertificate(finalizedHeight: number | null): BlockCertificateState {
    if (finalizedHeight === null) {
        return { status: 'waiting', detail: 'waiting for finalization' };
    }
    return { status: 'waiting', detail: 'waiting for block certificate' };
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
    if (
        (proof.status === 'waiting' || proof.status === 'fetching' || proof.status === 'error') &&
        typeof proof.detail === 'string'
    ) {
        return { status: proof.status, detail: proof.detail };
    }
    return { status: 'waiting', detail: 'waiting for finalization' };
}

function StatusBadge({ status, spinner }: { status: Status; spinner: string }) {
    const liveStatusText = useLiveStatusText(status.kind === 'live');

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
                {liveStatusText.map((symbol, index) => (
                    <span className="app__live-symbol" key={index}>
                        {symbol}
                    </span>
                ))}
            </span>
            <span className="visually-hidden">live</span>
        </span>
    );
}

function SummaryPanel({
    blocks,
    blocksObserved,
    totalTxObserved,
    observedRateWindow,
}: {
    blocks: ObservedBlock[];
    blocksObserved: number;
    totalTxObserved: number;
    observedRateWindow: ObservedRateWindow;
}) {
    const stats = useMemo(() => computeStats(blocks), [blocks]);
    const observedTxPerSecond = formatObservedTxPerSecond(totalTxObserved, observedRateWindow);
    return (
        <section className="summary">
            <Stat label="latest height" value={stats.latestHeight ?? '—'} />
            <Stat label="blocks observed" value={blocksObserved.toLocaleString()} />
            <Stat label="total txs observed" value={totalTxObserved.toLocaleString()} />
            <Stat label="observed tx/sec" value={observedTxPerSecond} />
            <Stat label="peak txs/block" value={stats.peakTx.toLocaleString()} />
            <Stat label="avg txs/block" value={stats.avgTx.toLocaleString()} />
        </section>
    );
}

function Stat({ label, value }: { label: string; value: React.ReactNode }) {
    return (
        <div className="summary__stat">
            <div className="summary__label">{label}</div>
            <div className="summary__value">{value}</div>
        </div>
    );
}

interface DerivedStats {
    latestHeight: string | null;
    peakTx: number;
    avgTx: number;
}

function computeStats(blocks: ObservedBlock[]): DerivedStats {
    if (blocks.length === 0) {
        return { latestHeight: null, peakTx: 0, avgTx: 0 };
    }
    let totalTx = 0;
    let peakTx = 0;
    let maxHeight = blocks[0].height;
    for (const block of blocks) {
        totalTx += block.txCount;
        if (block.txCount > peakTx) peakTx = block.txCount;
        if (block.height > maxHeight) maxHeight = block.height;
    }
    return {
        latestHeight: maxHeight.toString(),
        peakTx,
        avgTx: Math.round(totalTx / blocks.length),
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

/**
 * ASCII histogram of `txCount` for the most recent blocks. Each column is
 * one block (oldest left → newest right) and uses an 8-step vertical block
 * ramp so a column can be partially filled with sub-row resolution.
 *
 * The column count is responsive: we measure 1ch in the chart's font via a
 * hidden `<span>x</span>` and divide the chart's content width by it on
 * mount and on every resize, so the histogram always fills the available
 * width without changing the monospace cell aesthetic.
 *
 * The y-axis is auto-scaled to the peak in the visible window so a quiet
 * stretch of empty blocks doesn't compress later activity into the baseline.
 */
function Histogram({ blocks }: { blocks: ObservedBlock[] }) {
    const chartRef = useRef<HTMLPreElement>(null);
    const measureRef = useRef<HTMLSpanElement>(null);
    const [columns, setColumns] = useState<number>(HISTOGRAM_INITIAL_COLUMNS);

    useEffect(() => {
        const chart = chartRef.current;
        const measure = measureRef.current;
        if (!chart || !measure) return;

        const recompute = () => {
            const chWidth = measure.getBoundingClientRect().width;
            if (chWidth <= 0) return;
            const style = window.getComputedStyle(chart);
            const padLeft = parseFloat(style.paddingLeft) || 0;
            const padRight = parseFloat(style.paddingRight) || 0;
            const contentWidth = chart.clientWidth - padLeft - padRight;
            if (contentWidth <= 0) return;
            const cols = Math.max(
                1,
                Math.min(HISTOGRAM_MAX_COLUMNS, Math.floor(contentWidth / chWidth)),
            );
            setColumns((prev) => (prev === cols ? prev : cols));
        };

        recompute();
        const observer = new ResizeObserver(recompute);
        observer.observe(chart);
        return () => observer.disconnect();
    }, []);

    const { lines, peak } = useMemo(
        () => buildHistogram(blocks, columns),
        [blocks, columns],
    );
    return (
        <section className="histogram">
            <div className="histogram__y-axis">
                <span>{peak > 0 ? peak.toLocaleString() : ''}</span>
                <span>0</span>
            </div>
            <pre
                ref={chartRef}
                className="histogram__chart"
                aria-label="recent block tx count histogram"
            >
                <span ref={measureRef} className="histogram__measure" aria-hidden="true">
                    x
                </span>
                {lines.join('\n')}
            </pre>
            <div className="histogram__caption">
                tx count per block · last {Math.min(blocks.length, columns)} blocks ·
                oldest → newest
            </div>
        </section>
    );
}

function buildHistogram(
    blocks: ObservedBlock[],
    width: number,
): { lines: string[]; peak: number } {
    // Newest-first → oldest-first so the histogram reads left=old, right=new.
    const recent = blocks.slice(0, width).reverse();
    let peak = 0;
    for (const block of recent) {
        if (block.txCount > peak) peak = block.txCount;
    }
    if (peak === 0) {
        const blank = ' '.repeat(width);
        return { lines: Array.from({ length: HISTOGRAM_HEIGHT }, () => blank), peak };
    }

    // Total fill in 1/8th steps for the entire HISTOGRAM_HEIGHT-tall column.
    const ramp = BLOCK_GLYPHS.length - 1; // 8
    const eighthsPerColumn = HISTOGRAM_HEIGHT * ramp;

    const columnEighths = recent.map((block) =>
        Math.min(eighthsPerColumn, Math.max(1, Math.round((block.txCount / peak) * eighthsPerColumn))),
    );
    // Pad the left side with empty columns when we don't have enough history.
    while (columnEighths.length < width) {
        columnEighths.unshift(0);
    }

    // Render top-to-bottom. For each row (top=0, bottom=HEIGHT-1), the slot
    // for column j gets the 1/8 step left after subtracting the rows below it.
    const lines: string[] = [];
    for (let row = 0; row < HISTOGRAM_HEIGHT; row++) {
        const rowsBelow = HISTOGRAM_HEIGHT - 1 - row;
        let line = '';
        for (const eighths of columnEighths) {
            const remainingForThisRow = Math.max(0, Math.min(ramp, eighths - rowsBelow * ramp));
            line += BLOCK_GLYPHS[remainingForThisRow];
        }
        lines.push(line);
    }
    return { lines, peak };
}

function BlockTable({
    blocks,
    certificates,
}: {
    blocks: ObservedBlock[];
    certificates: BlockCertificateByHeight;
}) {
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

    if (blocks.length === 0) {
        return (
            <div className="empty">
                waiting for blocks… (start the spammer to see them stream in)
            </div>
        );
    }
    return (
        <table className="block-table">
            <thead>
                <tr>
                    <th className="col-height">height</th>
                    <th className="col-txs">txs</th>
                    <th className="col-cert">cert</th>
                    <th className="col-time">arrived</th>
                </tr>
            </thead>
            <tbody>
                {blocks.map((block, index) => {
                    const isFresh = index === 0;
                    return (
                        <tr key={block.height.toString()} className={isFresh ? 'is-fresh' : undefined}>
                            <td className="col-height">{block.height.toString()}</td>
                            <td className="col-txs">{block.txCount.toLocaleString()}</td>
                            <td className="col-cert">
                                <CertificateCell
                                    certificate={blockCertificateForHeight(
                                        block.height,
                                        certificates,
                                    )}
                                    finalizedHeight={Number(block.height)}
                                />
                            </td>
                            <td className="col-time">{formatter.format(block.arrivedAt)}</td>
                        </tr>
                    );
                })}
            </tbody>
        </table>
    );
}
