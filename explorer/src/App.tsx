import {
    memo,
    useCallback,
    useEffect,
    useMemo,
    useRef,
    useState,
} from 'react';
import { Age } from './Age';
import { formatClock } from './time';
import { SearchForm, type SearchHandle } from './SearchForm';
import {
    accountKeyFromPublicKey,
    encodeSignedTransaction,
    encodeTransactionBatch,
    parseAccountKeyHex,
    parseU64,
    toHex,
} from './codec';
import { submittedTransactionHistoryKey } from './historyKey';
import { AccountHistorySession, accountHistoryContextKey } from './accountHistory';
import { readStoredHistory } from './historyStorage';
import { buildHistogram, formatAverageTxPerBlock } from './histogram';
import { type VerifiedBlock, subscribeBlocks } from './indexer';
import { appendVerifiedBatch, EMPTY_FEED, shownCount, shownFeed, type FeedState } from './feedState';
import { submitTransactions } from './mempool';
import {
    loadAccountBundle,
    loadBlockBundle,
    loadTransactionBundle,
    prewarmProofVerification,
    verifyTransactionEvidence,
} from './proofBundle';
import {
    TransactionSubmissionError,
    isDeterministicSubmissionRejection,
    singleTransactionOutcome,
} from './submissionResponse';
import {
    type AccountTransactionRow,
    DEFAULT_ACCOUNT_BALANCE,
    type LatestProofTarget,
    type VerifiedAccountProof,
    type VerifiedTransactionProof,
} from './qmdb';
import {
    consumeNonce,
    emptyNonceState,
    mergeNonceStates,
    nextAvailableNonce,
    reserveNonces,
    type NonceState,
} from './nonce';
import {
    accountLookupFailure,
    accountRetryReason,
    errorMessage,
    isRetryableAccountProofError,
    isRetryableProofError,
    retryAccountWork,
    waitForRetry,
} from './proofRetry';
import {
    clearSession,
    createWallet,
    restoreWalletSession,
    signInWithPasskey,
    type ActiveWallet,
} from './wallet';
import {
    WAITING_FINALIZATION_CERTIFICATE,
    WAITING_FINALIZATION_PROOF,
    assignReconciliationOrder,
    isAccountKeyHex,
    markReconciliationError,
    markReconciliationFetching,
    markReconciliationWaiting,
    markSubmissionReconciling,
    markSubmissionRejected,
    markTransactionFinalized,
    submissionTimeline,
    markValidatorFinalizationObserved,
    prependTransaction,
    reconciliationRetryDelay,
    selectReconciliations,
    shouldReconcileTransaction,
    type SubmittedTransaction,
} from './submissionHistory';

const HISTOGRAM_MAX_COLUMNS = 180;
const BLOCK_LOG_MAX = 80;
const HISTOGRAM_MIN_COLUMNS = 48;
const HISTOGRAM_INITIAL_COLUMNS = 120;

/** Shortest row fade worth showing. A quicker one only blanks the newest row for its first frame. */
const MIN_ROW_FADE_MS = 64;

const BRAILLE_SPINNER = ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏'];

type Status =
    | { kind: 'connecting' }
    | { kind: 'live' }
    | { kind: 'error'; message: string };

const indexerUrl = import.meta.env.VITE_INDEXER_URL ?? 'http://127.0.0.1:8092';
const simplexVerificationMaterial = import.meta.env.VITE_SIMPLEX_VERIFICATION_MATERIAL ?? '';

type AccountProofState =
    | { readonly status: 'waiting'; readonly detail: string }
    | { readonly status: 'fetching'; readonly detail: string }
    | { readonly status: 'not-found' }
    | ({
          readonly status: 'verified';
          readonly detail: string;
      } & VerifiedAccountProof)
    | { readonly status: 'error'; readonly detail: string };

interface WalletAccountIdentity {
    readonly wallet: ActiveWallet;
    readonly accountKey: string;
    readonly snapshot: Pick<LatestProofTarget, 'height' | 'view' | 'timestampMs'>;
}

/** Account state at a certified snapshot, bound to the requesting wallet. */
type WalletAccountView = WalletAccountIdentity & {
    readonly status: 'verified';
    readonly balance: bigint;
    readonly nonce: { readonly base: bigint; readonly bitmap: bigint };
    readonly location: bigint;
    readonly txCount: bigint;
    readonly writeHeight: bigint;
    readonly timestampMs: bigint;
};

/**
 * The wallet's account as last read, either verified state or the indexer's unauthenticated
 * answer that the account has no update.
 */
type WalletAccountState = WalletAccountView | {
    readonly status: 'not-found';
    readonly wallet: ActiveWallet;
    readonly accountKey: string;
};

/** A verified block page and its position in the pagination history. */
type BlockBundle = Awaited<ReturnType<typeof loadBlockBundle>> & {
    readonly offset: bigint;
    readonly pageNumber: number;
};

/** The certified target and account version shared by every page of a history. */
interface AccountSnapshot {
    readonly contextKey: string;
    readonly target: { readonly height: bigint; readonly blockDigest: Uint8Array };
    readonly accountLocation: bigint;
    readonly expectedTxCount: bigint;
}

/** One in-flight account update read, shared by requests for the same wallet. */
interface WalletRefresh {
    readonly wallet: ActiveWallet;
    readonly accountKey: string;
    readonly controller: AbortController;
    promise: Promise<void>;

    /** Set when a finalization arrives mid-read, so one more read follows the current one. */
    again: boolean;
}

interface AccountPageData {
    readonly key: string;
    readonly account: string;
    readonly pageNumber: number;
    readonly target: LatestProofTarget;
    readonly proof: AccountProofState;
    readonly transactionProofs: readonly VerifiedTransactionProof[];
    readonly transactions: AccountTransactionRow[];
    readonly nextCursor: Uint8Array | null;
}

interface PageRequest {
    readonly key: string;
    readonly loading: boolean;
    readonly message: string;
    readonly notFound?: boolean;
}

interface ObservedRateWindow {
    readonly firstBlockAt: number | null;
    readonly latestBlockAt: number | null;
}

interface TransactionReconciliation {
    readonly controller: AbortController;
    timer: number | null;
}

function disposeReconciliation(reconciliation: TransactionReconciliation) {
    reconciliation.controller.abort();
    if (reconciliation.timer !== null) window.clearTimeout(reconciliation.timer);
}

const MAX_CONCURRENT_RECONCILIATIONS = 3;

export default function App() {
    const [feed, setFeed] = useState(EMPTY_FEED);
    const { blocks } = feed;
    const [status, setStatus] = useState<Status>({ kind: 'connecting' });
    const [isWalletOpen, setIsWalletOpen] = useState(false);
    const searchRef = useRef<SearchHandle>(null);
    const [wallet, setWallet] = useState<ActiveWallet | null>(null);

    // The address is tagged with its wallet so a late derivation cannot label a newer wallet.
    const [walletAddress, setWalletAddress] = useState<{ wallet: ActiveWallet; key: string } | null>(null);
    const walletAccountKey = walletAddress && walletAddress.wallet === wallet ? walletAddress.key : null;

    const [walletMessage, setWalletMessage] = useState('sign in or create a wallet');
    const [account, setAccount] = useState<WalletAccountState | null>(null);
    const [accountMessage, setAccountMessage] = useState('account metadata unavailable');

    // Height of the newest block in which the wallet verified a transaction that the shown
    // account state may predate, or zero. It stands until account state certified at or above it
    // is shown, and `isAccountBehind` mirrors it for rendering.
    const accountFloorRef = useRef(0n);
    const [isAccountBehind, setIsAccountBehind] = useState(false);
    const [toKey, setToKey] = useState('');
    const [value, setValue] = useState('1');
    const [nonce, setNonce] = useState('0');
    const [submitMessage, setSubmitMessage] = useState('');
    const [pendingSubmissionCount, setPendingSubmissionCount] = useState(0);
    const [history, setHistory] = useState<SubmittedTransaction[]>([]);
    const [loadedHistoryKey, setLoadedHistoryKey] = useState<string | null>(null);
    const [lookupAccount, setLookupAccount] = useState(() => accountFromLocation());
    const [lookupBlock, setLookupBlock] = useState(() => blockFromLocation());
    const [lookupTransaction, setLookupTransaction] = useState(() => transactionFromLocation());
    const [transactionBundle, setTransactionBundle] = useState<Awaited<ReturnType<typeof loadTransactionBundle>> | null>(null);
    const [transactionRequest, setTransactionRequest] = useState<PageRequest>({ key: '', loading: false, message: '' });
    const [blockOffsets, setBlockOffsets] = useState<bigint[]>([0n]);
    const [blockBundle, setBlockBundle] = useState<BlockBundle | null>(null);
    const [blockMessage, setBlockMessage] = useState('');
    const [blockLoading, setBlockLoading] = useState(false);
    const [accountRefresh, setAccountRefresh] = useState(0);

    // An account view keeps its certified snapshot across pages until the account changes or the
    // user refreshes.
    const accountSnapshotRef = useRef<AccountSnapshot | null>(null);
    const [accountHistorySession] = useState(() => new AccountHistorySession());
    const [walletHistorySession] = useState(() => new AccountHistorySession());

    // Asynchronous wallet reads compare against the latest wallet and address before publishing.
    const walletRefreshRef = useRef<WalletRefresh | null>(null);
    const activeWalletRef = useRef(wallet);
    const activeWalletKeyRef = useRef(walletAccountKey);
    activeWalletRef.current = wallet;
    activeWalletKeyRef.current = walletAccountKey;

    const [accountPageData, setAccountPageData] = useState<AccountPageData | null>(null);
    const [accountRequest, setAccountRequest] = useState<PageRequest>({ key: '', loading: false, message: '' });
    const [accountCursorStack, setAccountCursorStack] = useState<(Uint8Array | null)[]>([null]);
    const [copyToast, setCopyToast] = useState('');
    const [storageError, setStorageError] = useState('');
    const nextNonceRef = useRef<NonceState>(emptyNonceState());
    const committedNonceRef = useRef<NonceState>(emptyNonceState());
    const reservedNoncesRef = useRef(new Set<bigint>());
    const submissionInProgressRef = useRef(false);
    const copyToastTimeoutRef = useRef<number | null>(null);
    const isSubmitting = pendingSubmissionCount > 0;
    const isWalletBusy =
        walletMessage === 'opening passkey prompt' ||
        accountMessage === 'loading account proof' ||
        isAccountBehind ||
        isSubmitting;
    const spinner = useBrailleSpinner(status.kind === 'connecting' || isWalletBusy);
    const signedInAccountKey = walletAccountKey;
    const historyKey = submittedTransactionHistoryKey(
        {
            indexerUrl,
            simplexVerificationMaterial,
        },
        signedInAccountKey,
    );
    const activeHistoryKeyRef = useRef<string | null>(historyKey);
    const loadedHistoryKeyRef = useRef<string | null>(loadedHistoryKey);
    const reconciliationsRef = useRef(new Map<string, TransactionReconciliation>());
    const reconciliationOrderRef = useRef(new Map<string, number>());
    const reconciliationFailuresRef = useRef(new Map<string, number>());
    const reconciliationSequenceRef = useRef(0);
    const foregroundSubmissionsRef = useRef(new Set<string>());
    activeHistoryKeyRef.current = historyKey;
    loadedHistoryKeyRef.current = loadedHistoryKey;
    const currentAccountCursor = accountCursorStack[accountCursorStack.length - 1] ?? null;
    const accountContext = { indexerUrl, simplexVerificationMaterial, account: lookupAccount };
    const accountContextKey = accountHistoryContextKey(accountContext);
    const currentAccountViewKey = JSON.stringify([
        accountContextKey, accountRefresh,
        currentAccountCursor ? bytesToHex(currentAccountCursor) : null,
    ]);
    const pinnedAccount = accountSnapshotRef.current;

    // A pending page keeps the previous rows and their proof together under the same snapshot.
    const displayedAccount = accountPageData && (
        accountPageData.key === currentAccountViewKey || (
            accountPageData.account === lookupAccount && pinnedAccount?.contextKey === accountContextKey &&
            accountPageData.target.height === pinnedAccount.target.height &&
            bytesToHex(accountPageData.target.blockDigest) === bytesToHex(pinnedAccount.target.blockDigest)
        )
    ) ? accountPageData : null;
    const accountRequestMatches = accountRequest.key === currentAccountViewKey;
    const accountNotFound = accountRequestMatches && accountRequest.notFound === true;
    const accountLoading = !accountRequestMatches || accountRequest.loading;
    const accountNextCursor = displayedAccount?.nextCursor ?? null;
    const accountPaginationReady = !accountLoading && displayedAccount?.key === currentAccountViewKey &&
        pinnedAccount?.contextKey === accountContextKey;
    const walletAccount = account?.wallet === wallet && account.accountKey === walletAccountKey ? account : null;
    const currentBlockOffset = blockOffsets[blockOffsets.length - 1] ?? 0n;

    const setLocalNonceState = (nextNonce: NonceState) => {
        nextNonceRef.current = nextNonce;
        setNonce(nextAvailableNonce(nextNonce).toString());
    };

    const applyLocalNonceReservations = () => {
        setLocalNonceState(
            reserveNonces(committedNonceRef.current, reservedNoncesRef.current),
        );
    };

    const setCommittedNonceState = (nextNonce: NonceState) => {
        committedNonceRef.current = mergeNonceStates(committedNonceRef.current, nextNonce);
        applyLocalNonceReservations();
    };

    useEffect(() => {
        try {
            const restoredWallet = restoreWalletSession();
            if (!restoredWallet) return;
            setWallet(restoredWallet);
            setWalletMessage('signed in');
        } catch (error) {
            setStorageError(storageErrorMessage(error));
            setWalletMessage('wallet session unavailable');
        }
    }, []);

    useEffect(() => {
        const controller = new AbortController();
        const failed = (error: unknown) => {
            if (controller.signal.aborted) return;
            setStatus({
                kind: 'error',
                message: error instanceof Error ? error.message : String(error),
            });
        };

        (async () => {
            for await (const batch of subscribeBlocks(indexerUrl, {
                simplexVerificationMaterial,
                signal: controller.signal,
                onError: (message) =>
                    setStatus({ kind: 'error', message: `backend error: ${message}` }),
                onReconnect: () => setStatus({ kind: 'connecting' }),
            })) {
                if (controller.signal.aborted) return;
                setFeed((current) => appendVerifiedBatch(current, batch));
                setStatus({ kind: 'live' });
            }
        })().catch(failed);

        return () => controller.abort();
    }, []);

    useEffect(() => {
        let restored: SubmittedTransaction[];
        try {
            restored = historyKey === null ? [] : readStoredHistory(historyKey, window.localStorage);
        } catch (error) {
            setStorageError(storageErrorMessage(error));
            setLoadedHistoryKey(null);
            return;
        }
        reservedNoncesRef.current = new Set(
            restored
                .filter(
                    (transaction) =>
                        transaction.sender === signedInAccountKey &&
                        transaction.status !== 'rejected',
                )
                .map((transaction) => BigInt(transaction.nonce)),
        );
        applyLocalNonceReservations();
        setHistory(restored);
        setLoadedHistoryKey(historyKey);
    }, [historyKey]);

    useEffect(() => {
        if (!wallet) {
            setWalletAddress(null);
            return;
        }

        let cancelled = false;
        accountKeyFromPublicKey(wallet.publicKey)
            .then((accountKey) => {
                if (cancelled) return;
                setWalletAddress({ wallet, key: toHex(accountKey) });
            })
            .catch((error) => {
                if (cancelled) return;
                setWalletAddress(null);
                setWalletMessage(error instanceof Error ? error.message : String(error));
            });

        return () => {
            cancelled = true;
        };
    }, [wallet]);

    useEffect(() => {
        if (historyKey === null) return;
        if (loadedHistoryKey !== historyKey) return;
        const error = writeHistory(historyKey, history);
        if (error) setStorageError(error);
    }, [historyKey, loadedHistoryKey, history]);

    useEffect(() => {
        const onPopState = () => {
            searchRef.current?.cancel();
            accountHistorySession.invalidate();
            const next = accountFromLocation();
            setLookupAccount(next);
            accountSnapshotRef.current = null;
            setAccountCursorStack([null]);
            setAccountRefresh((current) => current + 1);
            setLookupBlock(blockFromLocation());
            setLookupTransaction(transactionFromLocation());
            setBlockOffsets([0n]);
        };
        window.addEventListener('popstate', onPopState);
        return () => window.removeEventListener('popstate', onPopState);
    }, []);

    // Start verifier initialization at load so the first proof does not wait for WebAssembly. A
    // failure surfaces again when a proof load initializes the verifier.
    useEffect(() => {
        void prewarmProofVerification(simplexVerificationMaterial).catch(() => {});
    }, []);

    // Publish each verified page atomically. Pagination retains the preceding page until then.
    useEffect(() => {
        const controller = new AbortController();
        if (!lookupAccount) {
            setAccountPageData(null);
            setAccountRequest({ key: currentAccountViewKey, loading: false, message: '' });
            return;
        }

        const retained = accountSnapshotRef.current;
        const snapshot = retained?.contextKey === accountContextKey ? retained : undefined;
        const request = accountHistorySession.begin(accountContext, controller.signal);
        setAccountRequest({ key: currentAccountViewKey, loading: true, message: '' });
        retryAccountWork(() => loadAccountBundle({
            indexerUrl,
            simplexVerificationMaterial,
            account: lookupAccount,
            cursor: currentAccountCursor ?? undefined,
            at: snapshot?.target,
            accountLocation: snapshot?.accountLocation,
            expectedTxCount: snapshot?.expectedTxCount,
            signal: controller.signal,
        }), controller.signal, isRetryableAccountProofError, {
            onRetry: (error) => {
                if (!accountHistorySession.isCurrent(request)) return;
                setAccountRequest({
                    key: currentAccountViewKey, loading: true,
                    message: accountRetryReason(error) ?? errorMessage(error),
                });
            },
        }).then((bundle) => {
            if (!accountHistorySession.isCurrent(request)) return;
            if (!accountHistorySession.observe(request, bundle.account)) return;

            // Keep the page, cursor and certificate bound to one verified snapshot.
            accountSnapshotRef.current = {
                contextKey: accountContextKey, target: bundle.target,
                accountLocation: bundle.account.location, expectedTxCount: bundle.account.txCount,
            };
            setAccountPageData({
                key: currentAccountViewKey,
                account: lookupAccount,
                pageNumber: accountCursorStack.length,
                target: bundle.target,
                proof: {
                    status: 'verified', detail: `account version included at height ${bundle.account.writeHeight}`, ...bundle.account,
                },
                transactionProofs: bundle.transactionProofs,
                transactions: bundle.page.rows,
                nextCursor: bundle.page.nextCursor,
            });
            setAccountRequest({ key: currentAccountViewKey, loading: false, message: '' });
        }).catch((error) => {
            if (!accountHistorySession.isCurrent(request)) return;
            setAccountRequest({ key: currentAccountViewKey, loading: false, ...accountLookupFailure(error) });
        });
        return () => controller.abort();
    }, [currentAccountViewKey, accountRefresh]);

    // Load one verified block page. The block's certificate stays visible while another page of the
    // same block loads.
    useEffect(() => {
        const controller = new AbortController();
        setBlockBundle((current) => current?.block.height === lookupBlock ? current : null);
        setBlockMessage('');
        if (lookupBlock === null) {
            setBlockLoading(false);
            return;
        }
        setBlockLoading(true);
        retryAccountWork(() => loadBlockBundle({
            indexerUrl, simplexVerificationMaterial, height: lookupBlock,
            offset: currentBlockOffset, signal: controller.signal,
        }), controller.signal, isRetryableAccountProofError, {
            onRetry: (error) => setBlockMessage(accountRetryReason(error) ?? errorMessage(error)),
        }).then((bundle) => {
            if (controller.signal.aborted) return;
            setBlockBundle({ ...bundle, offset: currentBlockOffset, pageNumber: blockOffsets.length });
            setBlockMessage('');
            setBlockLoading(false);
        }).catch((error) => {
            if (controller.signal.aborted) return;
            setBlockMessage(errorMessage(error));
            setBlockLoading(false);
        });
        return () => controller.abort();
    }, [lookupBlock, currentBlockOffset]);

    useEffect(() => {
        const controller = new AbortController();
        setTransactionBundle((current) => current?.transaction.digest === lookupTransaction ? current : null);
        if (!lookupTransaction) {
            setTransactionRequest({ key: '', loading: false, message: '' });
            return;
        }
        setTransactionRequest({ key: lookupTransaction, loading: true, message: '' });
        retryAccountWork(() => loadTransactionBundle({
            indexerUrl, simplexVerificationMaterial, digest: lookupTransaction,
            signal: controller.signal,
        }), controller.signal, isRetryableProofError, {
            onRetry: (error) => setTransactionRequest({
                key: lookupTransaction, loading: true,
                message: accountRetryReason(error) ?? errorMessage(error),
            }),
        }).then((bundle) => {
            if (controller.signal.aborted) return;
            setTransactionBundle(bundle);
            setTransactionRequest({ key: lookupTransaction, loading: false, message: '' });
        }).catch((error) => {
            if (controller.signal.aborted) return;
            setTransactionRequest({ key: lookupTransaction, loading: false, message: errorMessage(error) });
        });
        return () => controller.abort();
    }, [lookupTransaction]);

    useEffect(() => {
        const reconciliations = reconciliationsRef.current;
        return () => {
            for (const reconciliation of reconciliations.values()) {
                disposeReconciliation(reconciliation);
            }
            reconciliations.clear();
            reconciliationOrderRef.current.clear();
            reconciliationFailuresRef.current.clear();
            reconciliationSequenceRef.current = 0;
        };
    }, [historyKey]);

    const requeueReconciliation = (digest: string) => {
        reconciliationSequenceRef.current += 1;
        reconciliationOrderRef.current.set(digest, reconciliationSequenceRef.current);
        setHistory((current) =>
            markReconciliationWaiting(digest, WAITING_FINALIZATION_PROOF.detail, current),
        );
    };

    useEffect(() => {
        if (historyKey === null || loadedHistoryKey !== historyKey) return;

        const reconciliations = reconciliationsRef.current;
        const trackedDigests = new Set(history.map((tx) => tx.digest));
        for (const [digest, reconciliation] of reconciliations) {
            if (trackedDigests.has(digest)) continue;
            disposeReconciliation(reconciliation);
            reconciliations.delete(digest);
        }
        for (const digest of reconciliationOrderRef.current.keys()) {
            if (!trackedDigests.has(digest)) reconciliationOrderRef.current.delete(digest);
        }
        for (const digest of reconciliationFailuresRef.current.keys()) {
            if (!trackedDigests.has(digest)) reconciliationFailuresRef.current.delete(digest);
        }

        const eligible = history.filter((tx) =>
            shouldReconcileTransaction(
                tx,
                signedInAccountKey,
                foregroundSubmissionsRef.current,
            ),
        );
        reconciliationSequenceRef.current = assignReconciliationOrder(
            [...eligible].reverse(),
            reconciliationOrderRef.current,
            reconciliationSequenceRef.current,
        );

        const transactions = selectReconciliations(
            eligible,
            reconciliations,
            reconciliationOrderRef.current,
            MAX_CONCURRENT_RECONCILIATIONS,
        );

        for (const tx of transactions) {
            const reconciliation: TransactionReconciliation = {
                controller: new AbortController(),
                timer: null,
            };
            reconciliations.set(tx.digest, reconciliation);
            const releaseReconciliation = () => {
                if (reconciliations.get(tx.digest) !== reconciliation) return false;
                reconciliations.delete(tx.digest);
                return true;
            };
            setHistory((current) => markReconciliationFetching(tx.digest, current));

            loadTransactionBundle({
                indexerUrl,
                simplexVerificationMaterial,
                digest: tx.digest,
                signal: reconciliation.controller.signal,
            })
                .then((proof) => {
                    if (
                        reconciliation.controller.signal.aborted ||
                        activeHistoryKeyRef.current !== historyKey
                    ) {
                        return;
                    }
                    if (!releaseReconciliation()) return;
                    reconciliationOrderRef.current.delete(tx.digest);
                    reconciliationFailuresRef.current.delete(tx.digest);
                    const proofObservedAt = Date.now();
                    setHistory((current) =>
                        markTransactionFinalized(proof, proofObservedAt, current),
                    );
                    if (wallet !== null && activeHistoryKeyRef.current === historyKey) {
                        void refreshAccount(true);
                    }
                })
                .catch((error) => {
                    if (
                        reconciliation.controller.signal.aborted ||
                        activeHistoryKeyRef.current !== historyKey ||
                        reconciliations.get(tx.digest) !== reconciliation
                    ) {
                        releaseReconciliation();
                        return;
                    }

                    const detail = error instanceof Error ? error.message : String(error);
                    if (!isRetryableProofError(error)) {
                        if (!releaseReconciliation()) return;
                        reconciliationOrderRef.current.delete(tx.digest);
                        reconciliationFailuresRef.current.delete(tx.digest);
                        setHistory((current) =>
                            markReconciliationError(tx.digest, detail, current),
                        );
                        return;
                    }

                    const failures =
                        (reconciliationFailuresRef.current.get(tx.digest) ?? 0) + 1;
                    reconciliationFailuresRef.current.set(tx.digest, failures);

                    const waitingDetail = 'reconciliation retry scheduled';
                    setHistory((current) =>
                        markReconciliationWaiting(tx.digest, waitingDetail, current),
                    );
                    reconciliation.timer = window.setTimeout(() => {
                        if (reconciliations.get(tx.digest) !== reconciliation) return;
                        reconciliation.timer = null;
                        reconciliations.delete(tx.digest);
                        if (
                            reconciliation.controller.signal.aborted ||
                            activeHistoryKeyRef.current !== historyKey
                        ) {
                            return;
                        }
                        requeueReconciliation(tx.digest);
                    }, reconciliationRetryDelay(failures, Date.now() - tx.submittedAt));
                });
        }
    }, [history, historyKey, loadedHistoryKey, signedInAccountKey, wallet]);

    useEffect(() => {
        return () => {
            if (copyToastTimeoutRef.current !== null) {
                window.clearTimeout(copyToastTimeoutRef.current);
            }
        };
    }, []);

    // Reads current account state without activity. Requests for the same wallet share one
    // read, and a read for a replaced wallet is aborted. `floor` raises the account floor, and
    // the reads repeat until one is certified at or above it.
    const refreshAccount = (afterFinalization = false, floor = 0n): Promise<void> => {
        if (!wallet || !walletAccountKey) return Promise.resolve();
        if (floor > accountFloorRef.current) accountFloorRef.current = floor;
        if (accountFloorRef.current > 0n) setIsAccountBehind(true);
        const existing = walletRefreshRef.current;
        if (existing?.wallet === wallet && existing.accountKey === walletAccountKey) {
            // A finalization during the read needs one later read to include it.
            existing.again ||= afterFinalization;
            return existing.promise;
        }
        existing?.controller.abort();

        // Results publish only while this read is not aborted and its wallet is still active.
        const controller = new AbortController();
        const request = walletHistorySession.begin({
            indexerUrl, simplexVerificationMaterial, account: walletAccountKey,
        }, controller.signal);
        const current = () => !controller.signal.aborted &&
            walletHistorySession.isCurrent(request) && activeWalletRef.current === wallet &&
            activeWalletKeyRef.current === walletAccountKey;
        const refresh: WalletRefresh = {
            wallet, accountKey: walletAccountKey, controller, again: false,
            promise: Promise.resolve(),
        };
        const promise = (async () => {
            const started = Date.now();
            let behind = 0;

            // Read again when a finalization arrived during the previous read.
            do {
                refresh.again = false;
                if (behind === 0) setAccountMessage('loading account proof');

                // A snapshot certified below the floor, or no account at all, predates a
                // transaction this wallet has already verified, so the indexer has not
                // published that block yet.
                let stale = false;
                try {
                    const bundle = await retryAccountWork(() => loadAccountBundle({
                        indexerUrl, simplexVerificationMaterial, account: walletAccountKey,
                        includeTransactions: false, signal: controller.signal,
                    }), controller.signal, isRetryableAccountProofError);
                    if (!current()) return;
                    if (!walletHistorySession.observe(request, bundle.account)) return;
                    const snapshot = { height: bundle.target.height, view: bundle.target.view, timestampMs: bundle.target.timestampMs };
                    const nextAccount: WalletAccountView = {
                        status: 'verified',
                        balance: bundle.account.balance,
                        nonce: { base: bundle.account.nonce, bitmap: bundle.account.nonceBitmap },
                        wallet, accountKey: walletAccountKey, snapshot, location: bundle.account.location,
                        txCount: bundle.account.txCount, writeHeight: bundle.account.writeHeight,
                        timestampMs: bundle.account.timestampMs,
                    };
                    setAccount(nextAccount);
                    setCommittedNonceState(accountNonceState(nextAccount));
                    setAccountMessage('');
                    stale = bundle.target.height < accountFloorRef.current;
                    if (!stale) {
                        accountFloorRef.current = 0n;
                        setIsAccountBehind(false);
                    }
                } catch (error) {
                    if (!current()) return;
                    const failure = accountLookupFailure(error);
                    if (failure.notFound) setAccount({ status: 'not-found', wallet, accountKey: walletAccountKey });
                    setAccountMessage(failure.notFound ? '' : failure.message);
                    stale = failure.notFound && accountFloorRef.current > 0n;
                }
                if (stale) {
                    behind += 1;
                    refresh.again = await waitForRetry(
                        reconciliationRetryDelay(behind, Date.now() - started), controller.signal,
                    );
                }
            } while (refresh.again && current());
        })().finally(() => {
            if (walletRefreshRef.current === refresh) walletRefreshRef.current = null;
        });
        refresh.promise = promise;
        walletRefreshRef.current = refresh;
        return promise;
    };

    // A wallet change clears committed account state before the new wallet's first verified read.
    useEffect(() => {
        setAccount(null);
        accountFloorRef.current = 0n;
        setIsAccountBehind(false);
        committedNonceRef.current = emptyNonceState();
        applyLocalNonceReservations();
        if (!wallet) {
            reservedNoncesRef.current.clear();
            applyLocalNonceReservations();
            setAccountMessage('account metadata unavailable');
        } else if (walletAccountKey) {
            void refreshAccount();
        }
        return () => {
            walletRefreshRef.current?.controller.abort();
            walletRefreshRef.current = null;
        };
    }, [wallet, walletAccountKey]);

    const handleCreateWallet = async () => {
        setWalletMessage('opening passkey prompt');
        try {
            const nextWallet = await createWallet();
            walletHistorySession.invalidate();
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
            walletHistorySession.invalidate();
            setWallet(nextWallet);
            setWalletMessage('signed in');
        } catch (error) {
            setWalletMessage(error instanceof Error ? error.message : String(error));
        }
    };

    const handleSignOut = () => {
        walletHistorySession.invalidate();
        try {
            clearSession();
        } catch (error) {
            setStorageError(storageErrorMessage(error));
        }
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

    const openAccountPage = useCallback((value: string): boolean => {
        const normalized = normalizeAccountInput(value);
        if (!normalized) return false;

        searchRef.current?.cancel();

        // A new account starts from a fresh snapshot, and the account view replaces any block view.
        if (normalized !== lookupAccount || accountCursorStack.length > 1) {
            accountHistorySession.invalidate();
        }
        if (normalized !== lookupAccount) accountSnapshotRef.current = null;
        setLookupAccount(normalized);
        setLookupBlock(null);
        setLookupTransaction('');
        setAccountCursorStack([null]);
        const url = new URL(window.location.href);
        url.pathname = '/';
        url.searchParams.delete('block');
        url.searchParams.delete('transaction');
        url.searchParams.set('account', normalized);
        const nextLocation = `${url.pathname}${url.search}${url.hash}`;
        if (nextLocation !== `${window.location.pathname}${window.location.search}${window.location.hash}`) {
            window.history.pushState(null, '', nextLocation);
        }
        setIsWalletOpen(false);
        return true;
    }, [lookupAccount, accountCursorStack.length, accountHistorySession]);

    const clearAccountLookup = () => {
        searchRef.current?.cancel();
        accountHistorySession.invalidate();
        setLookupAccount('');
        setLookupBlock(null);
        setLookupTransaction('');
        accountSnapshotRef.current = null;
        setAccountCursorStack([null]);
        const url = new URL(window.location.href);
        url.pathname = '/';
        url.searchParams.delete('block');
        url.searchParams.delete('transaction');
        url.searchParams.delete('account');
        const nextLocation = `${url.pathname}${url.search}${url.hash}`;
        if (nextLocation !== `${window.location.pathname}${window.location.search}${window.location.hash}`) {
            window.history.pushState(null, '', nextLocation);
        }
    };

    const openBlockPage = useCallback((height: bigint) => {
        // The block view replaces any account view and starts at the first page.
        searchRef.current?.cancel();
        accountHistorySession.invalidate();
        setLookupAccount('');
        accountSnapshotRef.current = null;
        setLookupBlock(height);
        setLookupTransaction('');
        setBlockOffsets([0n]);
        const url = new URL(window.location.href);
        url.pathname = '/';
        url.searchParams.delete('account');
        url.searchParams.delete('transaction');
        url.searchParams.set('block', height.toString());
        window.history.pushState(null, '', `${url.pathname}${url.search}${url.hash}`);
    }, [accountHistorySession]);

    const openTransactionPage = useCallback((digest: string) => {
        const normalized = normalizeAccountInput(digest);
        if (!normalized) return;
        searchRef.current?.cancel();
        accountHistorySession.invalidate();
        setIsWalletOpen(false);
        setLookupAccount('');
        setLookupBlock(null);
        accountSnapshotRef.current = null;
        setLookupTransaction(normalized);
        const url = new URL(window.location.href);
        url.pathname = '/';
        url.searchParams.delete('account');
        url.searchParams.delete('block');
        url.searchParams.set('transaction', normalized);
        window.history.pushState(null, '', `${url.pathname}${url.search}${url.hash}`);
    }, [accountHistorySession]);

    const refreshAccountPage = () => {
        // Dropping the snapshot lets the first page request a new certified target.
        accountHistorySession.invalidate();
        accountSnapshotRef.current = null;
        setAccountCursorStack([null]);
        setAccountRefresh((current) => current + 1);
    };

    const nextAccountPage = () => {
        if (!accountNextCursor || !accountPaginationReady) return;
        accountHistorySession.invalidate();
        setAccountCursorStack((current) => [...current, accountNextCursor]);
    };

    const previousAccountPage = () => {
        if (!accountPaginationReady || accountCursorStack.length <= 1) return;
        accountHistorySession.invalidate();
        setAccountCursorStack((current) => current.length <= 1 ? current : current.slice(0, -1));
    };

    // Preserve reservations until committed account state reflects finalization.
    const canClearSubmittedTransaction = (transaction: SubmittedTransaction) =>
        transaction.status === 'rejected' ||
        (transaction.status === 'finalized' &&
            consumeNonce(committedNonceRef.current, BigInt(transaction.nonce)) === null);

    const clearSubmittedTransactionHistory = () => {
        const retained = history.filter((transaction) => !canClearSubmittedTransaction(transaction));
        setHistory(retained);
        if (historyKey !== null) {
            const error = writeHistory(historyKey, retained);
            if (error) setStorageError(error);
        }
    };

    const updateSubmittedHistory = (
        key: string,
        update: (current: SubmittedTransaction[]) => SubmittedTransaction[],
    ) => {
        const next = update(readHistory(key, setStorageError));
        const error = writeHistory(key, next);
        if (error) setStorageError(error);
        if (loadedHistoryKeyRef.current === key) {
            setHistory(update);
        }
    };

    const cancelReconciliation = (digest: string) => {
        const reconciliation = reconciliationsRef.current.get(digest);
        if (reconciliation) {
            disposeReconciliation(reconciliation);
            reconciliationsRef.current.delete(digest);
        }
        reconciliationOrderRef.current.delete(digest);
        reconciliationFailuresRef.current.delete(digest);
    };

    const submitTransfer = async () => {
        if (!wallet) return;
        if (submissionInProgressRef.current) return;
        if (!walletAccountKey) {
            setSubmitMessage('loading account address');
            return;
        }
        const originHistoryKey = historyKey;
        if (originHistoryKey === null || loadedHistoryKeyRef.current !== originHistoryKey) {
            setSubmitMessage('submitted transaction history is unavailable');
            return;
        }

        submissionInProgressRef.current = true;
        setPendingSubmissionCount((count) => count + 1);
        setSubmitMessage('forming transaction');
        let reservedNonce: bigint | null = null;
        let submitted: { digest: string; historyKey: string } | null = null;
        try {
            const parsedToKey = parseAccountKeyHex(toKey);
            const parsedValue = parseU64(value, 'value');
            const previousNonce = nextNonceRef.current;
            const parsedNonce = nextAvailableNonce(previousNonce);
            const nextNonce = consumeNonce(previousNonce, parsedNonce);
            if (nextNonce === null) {
                throw new Error('nonce must fit in u64');
            }
            reservedNoncesRef.current.add(parsedNonce);
            applyLocalNonceReservations();
            reservedNonce = parsedNonce;

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
                reconciliationVersion: 2,
                sender: walletAccountKey,
                digest: encoded.digestHex,
                to: toHex(parsedToKey),
                value: parsedValue.toString(),
                nonce: parsedNonce.toString(),
                submittedAt: Date.now(),
                reportedInMs: null,
                reportedHeight: null,
                finalizationObservedInMs: null,
                proofObservedInMs: null,
                status: 'reconciling',
                detail: 'submitting for admission',
                finalizedHeight: null,
                certificate: WAITING_FINALIZATION_CERTIFICATE,
                proof: WAITING_FINALIZATION_PROOF,
            };
            cancelReconciliation(encoded.digestHex);
            foregroundSubmissionsRef.current.add(encoded.digestHex);
            updateSubmittedHistory(
                originHistoryKey,
                (current) => prependTransaction(pending, current),
            );
            submitted = { digest: encoded.digestHex, historyKey: originHistoryKey };
            setSubmitMessage('submitting');

            const status = await submitTransactions(
                indexerUrl,
                encodeTransactionBatch([encoded.bytes]),
            );
            if (status.status === 'pending') {
                updateSubmittedHistory(
                    originHistoryKey,
                    (current) =>
                        markSubmissionReconciling(
                            encoded.digestHex,
                            'submission timed out',
                            current,
                        ),
                );
                setSubmitMessage('');
                return;
            }
            const outcome = singleTransactionOutcome(status);
            if (outcome.kind === 'ambiguous') {
                throw new TransactionSubmissionError('ambiguous', outcome.detail);
            }

            const observedAt = Date.now();
            updateSubmittedHistory(
                originHistoryKey,
                (current) =>
                    markValidatorFinalizationObserved(
                        encoded.digestHex,
                        outcome.height,
                        observedAt,
                        current,
                    ),
            );
            setSubmitMessage('');

            // Evidence delivered with the report passes the same verification as a fetched
            // bundle. A row without verified evidence waits for the indexer's bundle.
            if (outcome.evidence !== undefined) {
                const verified = await verifyTransactionEvidence({
                    indexerUrl, simplexVerificationMaterial, digest: encoded.digestHex,
                }, outcome.evidence).catch(() => null);
                const verifiedAt = Date.now();
                updateSubmittedHistory(
                    originHistoryKey,
                    (current) => verified === null
                        ? markSubmissionReconciling(encoded.digestHex, `reported h${outcome.height}`, current)
                        : markTransactionFinalized(verified, verifiedAt, current),
                );
                if (verified !== null && activeHistoryKeyRef.current === originHistoryKey) {
                    void refreshAccount(true, verified.height);
                }
            }
        } catch (error) {
            const currentSubmission = submitted;
            const rejected =
                currentSubmission !== null && isDeterministicSubmissionRejection(error);
            if (currentSubmission !== null && rejected) {
                const { digest, historyKey: originHistoryKey } = currentSubmission;
                cancelReconciliation(digest);
                const detail = error instanceof Error ? error.message : String(error);
                updateSubmittedHistory(
                    originHistoryKey,
                    (current) => markSubmissionRejected(digest, detail, current),
                );
            } else if (currentSubmission !== null) {
                const { digest, historyKey: originHistoryKey } = currentSubmission;
                const detail = error instanceof Error ? error.message : String(error);
                updateSubmittedHistory(
                    originHistoryKey,
                    (current) =>
                        markSubmissionReconciling(
                            digest,
                            `delivery uncertain. ${detail}`,
                            current,
                        ),
                );
            }

            if (
                (currentSubmission === null || rejected) &&
                reservedNonce !== null &&
                activeHistoryKeyRef.current === originHistoryKey
            ) {
                reservedNoncesRef.current.delete(reservedNonce);
                applyLocalNonceReservations();
            }
            setSubmitMessage(
                currentSubmission !== null && !rejected
                    ? 'delivery uncertain. reconciling by transaction digest'
                    : error instanceof Error
                        ? error.message
                        : String(error),
            );
        } finally {
            submissionInProgressRef.current = false;
            if (submitted !== null) {
                foregroundSubmissionsRef.current.delete(submitted.digest);
            }
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
                    <SearchForm ref={searchRef} endpoint={indexerUrl} onOpenAccount={openAccountPage} onOpenTransaction={openTransactionPage} />
                    <div className="app__header-actions">
                        {(status.kind !== 'live' || lookupAccount !== '' || lookupBlock !== null || lookupTransaction !== '') && (
                            <>
                                <StatusBadge status={status} spinner={spinner} height={blocks[0]?.height ?? null} />
                                <span className="app__header-separator" aria-hidden="true">
                                    ⬝
                                </span>
                            </>
                        )}
                        <button className="wallet-trigger" onClick={() => {
                            searchRef.current?.cancel();
                            setIsWalletOpen(true);
                        }}>
                            wallet{walletAccountKey && <span className="wallet-trigger__key"> {shortHex(walletAccountKey)}</span>}
                        </button>
                    </div>
                </header>
                {storageError && (
                    <div className="app__warning" role="alert">
                        {storageError}
                    </div>
                )}
                <main className="app__main app__main--minimal">
                    <section className="explorer-stage" aria-label="block explorer">
                        {lookupAccount ? (
                            <AccountPage
                                account={lookupAccount}
                                onCopy={copyValue}
                                onOpenAddress={openAccountPage}
                                onOpenTransaction={openTransactionPage}
                                pageNumber={displayedAccount?.pageNumber ?? accountCursorStack.length}
                                pageRequestKey={currentAccountViewKey}
                                retainingPage={displayedAccount !== null && displayedAccount.key !== currentAccountViewKey}
                                proof={accountNotFound ? { status: 'not-found' }
                                    : displayedAccount?.proof ?? { status: 'fetching', detail: 'verifying account evidence' }}
                                target={displayedAccount?.target ?? null}
                                transactionProofs={displayedAccount?.transactionProofs ?? []}
                                transactions={displayedAccount?.transactions ?? []}
                                activityError={accountRequestMatches ? accountRequest.message : ''}
                                loading={accountLoading}
                                hasPrevious={accountPaginationReady && accountCursorStack.length > 1}
                                hasNext={accountPaginationReady && accountNextCursor !== null}
                                onPrevious={previousAccountPage}
                                onNext={nextAccountPage}
                                onRefresh={refreshAccountPage}
                            />
                        ) : lookupBlock !== null ? (
                            <BlockPage
                                height={lookupBlock}
                                offset={currentBlockOffset}
                                bundle={blockBundle?.block.height === lookupBlock ? blockBundle : null}
                                message={blockMessage}
                                loading={blockLoading}
                                pageNumber={blockOffsets.length}
                                hasPrevious={blockOffsets.length > 1}
                                onPrevious={() => setBlockOffsets((current) => current.slice(0, -1))}
                                onNext={() => {
                                    const next = blockBundle?.nextOffset;
                                    if (next !== null && next !== undefined) {
                                        setBlockOffsets((current) => [...current, next]);
                                    }
                                }}
                                onOpenAddress={openAccountPage}
                                onOpenTransaction={openTransactionPage}
                            />
                        ) : lookupTransaction ? (
                            <TransactionPage digest={lookupTransaction}
                                bundle={transactionBundle?.transaction.digest === lookupTransaction ? transactionBundle : null}
                                message={transactionRequest.key === lookupTransaction ? transactionRequest.message : ''}
                                loading={transactionRequest.key !== lookupTransaction || transactionRequest.loading}
                                onCopy={copyValue} onOpenAddress={openAccountPage} onOpenBlock={openBlockPage} />
                        ) : (
                            <HomeFeed feed={feed} onOpenBlock={openBlockPage} />
                        )}
                    </section>
                </main>
                {isWalletOpen && (
                    <WalletModal onClose={() => setIsWalletOpen(false)}>
                        <WalletPanel
                            wallet={wallet}
                            walletAccountKey={walletAccountKey}
                            walletMessage={walletMessage}
                            account={walletAccount}
                            accountMessage={accountMessage}
                            isAccountBehind={isAccountBehind}
                            toKey={toKey}
                            value={value}
                            nonce={nonce}
                            submitMessage={submitMessage}
                            isSubmitting={isSubmitting}
                            canClearSubmittedTransactions={history.some(canClearSubmittedTransaction)}
                            spinner={spinner}
                            onCreateWallet={handleCreateWallet}
                            onSignIn={handleSignIn}
                            onSignOut={handleSignOut}
                            onRefreshAccount={() => { void refreshAccount(); }}
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
                            onOpenTransaction={openTransactionPage}
                        />
                    </WalletModal>
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
    onOpenTransaction,
    pageNumber,
    pageRequestKey,
    retainingPage,
    proof,
    target,
    transactionProofs,
    transactions,
    activityError,
    loading,
    hasPrevious,
    hasNext,
    onPrevious,
    onNext,
    onRefresh,
}: {
    account: string;
    onCopy: (value: string) => void;
    onOpenAddress: (value: string) => void;
    onOpenTransaction: (digest: string) => void;
    pageNumber: number;
    pageRequestKey: string;
    retainingPage: boolean;
    proof: AccountProofState;
    target: LatestProofTarget | null;
    transactionProofs: readonly VerifiedTransactionProof[];
    transactions: AccountTransactionRow[];
    activityError: string;
    loading: boolean;
    hasPrevious: boolean;
    hasNext: boolean;
    onPrevious: () => void;
    onNext: () => void;
    onRefresh: () => void;
}) {
    const transactionProof = transactionProofs[0];
    const proofItems = transactionProofs.length;
    const notFound = proof.status === 'not-found';
    return (
        <section className="account-page" aria-label="account proof" aria-busy={loading}>
            <div className="account-page__title">
                <h2>account</h2>
                <button onClick={onRefresh} disabled={loading}>refresh</button>
            </div>
            <div className="account-page__line">
                <span className="account-page__prompt">address</span>
                <CopyableValue value={account} onCopy={onCopy} />
            </div>
            {!notFound && <div className="account-proof-grid">
                <div className="account-proof-grid__details">
                    <ProofDatum label="block" pending={!target} value={target ? shortHex(bytesToHex(target.blockDigest)) : '—'} />
                    <ProofDatum
                        label="balance"
                        pending={proof.status !== 'verified'}
                        value={
                            proof.status === 'verified'
                                ? `${proof.balance.toString()} / nonce ${proof.nonce.toString()} / ${proof.txCount} txs`
                                : '—'
                        }
                    />
                </div>
                <div className="account-proof-grid__evidence account-proof-grid__evidence--three">
                    <CertificateDatum target={target} latest />
                    <ProofDatum
                        label="transaction proof"
                        verified={!!transactionProof}
                        pending={!target}
                        value={transactionProof
                            ? <span className="proof-badge">op{transactionProof.tip} / {proofItems}L</span>
                            : proof.status === 'verified' && proof.txCount === 0n ? 'empty history' : '—'}
                    />
                    <ProofDatum
                        label="account proof"
                        verified={proof.status === 'verified'}
                        pending={proof.status === 'fetching'}
                        value={
                            proof.status === 'verified'
                                ? <span className="proof-badge">loc {proof.location} / h{proof.writeHeight}</span>
                                : '—'
                        }
                    />
                </div>
            </div>}
            {notFound && <PageStatus message={activityError} />}
            {!notFound && <>
            <div className="account-page__subhead">
                <h3>page {pageNumber}</h3>
                <div className="account-page__pager">
                    <span key={pageRequestKey} aria-hidden="true"
                        className={`account-page__progress${loading && retainingPage ? ' account-page__progress--pending' : ''}`}>loading</span>
                    <button disabled={!hasPrevious} onClick={onPrevious}>prev</button>
                    <button disabled={!hasNext} onClick={onNext}>next</button>
                </div>
            </div>
            <PageStatus message={activityError || (loading && !retainingPage ? target ? 'refreshing verified selection' : 'verifying account evidence' : '')} />
            <div className="account-tx-list">
                {!target && <PendingTransactionRow includeDigest />}
                {target && transactions.length === 0 && (
                    <div className="account-tx-row account-tx-row--empty">no transactions in this account version</div>
                )}
                {transactions.map((row) => (
                    <div className="account-tx-row" key={`${row.location}-${row.direction}`}>
                        <div className="account-tx-row__main">
                            <AddressValue kind="transaction" value={row.digest} onOpenAddress={onOpenTransaction} />
                            <span className="tx-party">
                                <span className="account-tx-row__label">from</span>
                                <AccountPageAddressValue
                                    account={account}
                                    value={row.direction === 'sent' ? account : row.counterparty}
                                    onCopy={onCopy}
                                    onOpenAddress={onOpenAddress}
                                />
                            </span>
                            <span className="tx-party">
                                <span className="account-tx-row__label">to</span>
                                <AccountPageAddressValue
                                    account={account}
                                    value={row.direction === 'sent' ? row.counterparty : account}
                                    onCopy={onCopy}
                                    onOpenAddress={onOpenAddress}
                                />
                            </span>
                        </div>
                        <div className="account-tx-row__meta">
                            <span>value {row.value.toString()}</span>
                            <span>nonce {row.nonce.toString()}</span>
                            <span>account index {row.accountIndex.toString()}</span>
                            <span>loc {row.location.toString()}</span>
                        </div>
                    </div>
                ))}
            </div>
            </>}
        </section>
    );
}

function BlockPage({
    height, offset, bundle, message, loading, pageNumber, hasPrevious,
    onPrevious, onNext, onOpenAddress, onOpenTransaction,
}: {
    height: bigint;
    offset: bigint;
    bundle: BlockBundle | null;
    message: string;
    loading: boolean;
    pageNumber: number;
    hasPrevious: boolean;
    onPrevious: () => void;
    onNext: () => void;
    onOpenAddress: (value: string) => void;
    onOpenTransaction: (digest: string) => void;
}) {
    const pageIsCurrent = bundle?.offset === offset;
    const transactionProof = bundle?.transactions[0]?.proof;
    return (
        <section className="account-page" aria-label="certified block" aria-busy={loading}>
            <div className="account-page__title">
                <h2>block {height.toString()}</h2>
            </div>
            <div className="account-proof-grid">
                <div className="account-proof-grid__details">
                    <ProofDatum pending={!bundle} label="block" value={bundle ? shortHex(bytesToHex(bundle.block.blockDigest)) : '—'} />
                    <ProofDatum pending={!bundle} label="transactions" value={bundle?.block.transactionCount.toString() ?? '—'} />
                </div>
                <div className="account-proof-grid__evidence">
                    <CertificateDatum target={bundle?.target ?? null} />
                    <ProofDatum
                        label="transaction proof"
                        verified={!!transactionProof}
                        pending={!transactionProof}
                        value={bundle && transactionProof
                            ? <span className="proof-badge">op{transactionProof.tip} / {bundle.transactions.length}L</span>
                            : '—'}
                    />
                </div>
            </div>
            <div className="account-page__subhead">
                <h3>page {bundle?.pageNumber ?? pageNumber}</h3>
                <div className="account-page__pager">
                    <span key={offset.toString()} aria-hidden="true"
                        className={`account-page__progress${loading && bundle && !pageIsCurrent ? ' account-page__progress--pending' : ''}`}>loading</span>
                    <button disabled={!hasPrevious || loading || !pageIsCurrent} onClick={onPrevious}>prev</button>
                    <button disabled={loading || !pageIsCurrent || bundle?.nextOffset == null} onClick={onNext}>next</button>
                </div>
            </div>
            <PageStatus message={message || (loading && !bundle ? 'verifying block evidence' : '')} />
            {bundle && bundle.transactions.length === 0 && <div className="account-tx-row">no transactions in this block</div>}
            <div className="account-tx-list">
                {!bundle && <PendingTransactionRow includeDigest />}
                {bundle?.transactions.map((transaction) => (
                    <div className="account-tx-row" key={transaction.location.toString()}>
                        <div className="account-tx-row__main">
                            <AddressValue kind="transaction" value={transaction.digest} onOpenAddress={onOpenTransaction} />
                            <span className="tx-party">
                                <span className="account-tx-row__label">from</span>
                                <AddressValue value={transaction.sender} onOpenAddress={onOpenAddress} />
                            </span>
                            <span className="tx-party">
                                <span className="account-tx-row__label">to</span>
                                <AddressValue value={transaction.recipient} onOpenAddress={onOpenAddress} />
                            </span>
                        </div>
                        <div className="account-tx-row__meta">
                            <span>value {transaction.value.toString()}</span>
                            <span>nonce {transaction.nonce.toString()}</span>
                            <span>loc {transaction.location.toString()}</span>
                        </div>
                    </div>
                ))}
            </div>
        </section>
    );
}

function TransactionPage({ digest, bundle, message, loading, onCopy, onOpenAddress, onOpenBlock }: {
    digest: string;
    bundle: Awaited<ReturnType<typeof loadTransactionBundle>> | null;
    message: string;
    loading: boolean;
    onCopy: (value: string) => void;
    onOpenAddress: (value: string) => void;
    onOpenBlock: (height: bigint) => void;
}) {
    const transaction = bundle?.transaction;
    return (
        <section className="account-page" aria-label="verified transaction" aria-busy={loading}>
            <div className="account-page__title"><h2>transaction</h2></div>
            <div className="account-page__line">
                <span className="account-page__prompt">hash</span>
                <CopyableValue value={digest} onCopy={onCopy} />
            </div>
            <div className="account-proof-grid">
                <div className="account-proof-grid__details">
                    <ProofDatum pending={!bundle} label="block" value={bundle ? <button className="account-page__height-link" onClick={() => onOpenBlock(bundle.height)}>h{bundle.height.toString()}:{transaction!.index}</button> : '—'} />
                    <ProofDatum pending={!bundle} label="location" value={bundle?.location.toString() ?? '—'} />
                </div>
                <div className="account-proof-grid__evidence">
                    <CertificateDatum target={bundle?.target ?? null} />
                    <ProofDatum verified={!!bundle} pending={!bundle} label="transaction proof" value={bundle ? <span className="proof-badge">op{bundle.tip} / 1L</span> : '—'} />
                </div>
            </div>
            <PageStatus message={message || (loading ? 'verifying transaction evidence' : '')} />
            {!transaction && <PendingTransactionRow />}
            {transaction && <div className="account-tx-row">
                <div className="account-tx-row__main">
                    <span className="tx-party"><span className="account-tx-row__label">from</span><AddressValue value={transaction.sender} onOpenAddress={onOpenAddress} /></span>
                    <span className="tx-party"><span className="account-tx-row__label">to</span><AddressValue value={transaction.recipient} onOpenAddress={onOpenAddress} /></span>
                </div>
                <div className="account-tx-row__meta"><span>value {transaction.value.toString()}</span><span>nonce {transaction.nonce.toString()}</span></div>
            </div>}
        </section>
    );
}

function VerifiedEvidence({ children }: { children: React.ReactNode }) {
    return (
        <span className="verified-evidence">
            <span className="verified-evidence__check" aria-hidden="true">✓</span>
            <span className="visually-hidden">verified in browser: </span>
            {children}
        </span>
    );
}

function ProofDatum({ label, value, detail, pending = false, verified = false }: {
    label: string;
    value: React.ReactNode;
    detail?: React.ReactNode;
    pending?: boolean;
    verified?: boolean;
}) {
    return (
        <div className={`account-proof-grid__cell${verified ? ' verified-surface' : ''}`}>
            <span>{verified ? <VerifiedEvidence>{label}</VerifiedEvidence> : label}</span>
            <strong className={pending ? 'page-pending' : undefined}>{value}</strong>
            {detail}
        </div>
    );
}

/**
 * The certificate every proof on a page is verified against, with how long ago it was certified.
 * A view whose certificate stands for the latest state judges that age against the browser clock.
 */
function CertificateDatum({ target, latest = false }: {
    target: Pick<LatestProofTarget, 'height' | 'view' | 'timestampMs'> | null;
    latest?: boolean;
}) {
    return (
        <ProofDatum
            label="block cert"
            verified={!!target}
            pending={!target}
            value={target
                ? <span className="proof-badge">h{target.height.toString()} / v{target.view.toString()}
                    <span className={latest ? 'cert-age cert-age--latest' : 'cert-age'}>(<Age timestampMs={target.timestampMs} />)</span></span>
                : '—'}
        />
    );
}

function PageStatus({ message }: { message: string }) {
    return <div className="page-status" role="status">{message || '\u00a0'}</div>;
}

function PendingTransactionRow({ includeDigest = false }: { includeDigest?: boolean }) {
    return (
        <div className="account-tx-row page-pending" aria-label="transaction evidence pending">
            <div className="account-tx-row__main">
                {includeDigest && <span className="page-pending__address">—</span>}
                <span className="tx-party"><span className="account-tx-row__label">from</span><span className="page-pending__address">—</span></span>
                <span className="tx-party"><span className="account-tx-row__label">to</span><span className="page-pending__address">—</span></span>
            </div>
            <div className="account-tx-row__meta"><span>value —</span><span>nonce —</span></div>
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
    walletAccountKey,
    walletMessage,
    account,
    accountMessage,
    isAccountBehind,
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
    account: WalletAccountState | null;
    accountMessage: string;
    isAccountBehind: boolean;
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
    const isWalletLoading = walletMessage === 'opening passkey prompt';
    const showWalletMessage = walletMessage !== '' && walletMessage !== 'signed in';
    const isAccountLoading = accountMessage === 'loading account proof';
    const walletAccountDisplay = walletAccountKey?.toLowerCase() ?? 'not authenticated';
    const verified = account?.status === 'verified' ? account : null;
    const isNew = account?.status === 'not-found';

    return (
        <section className="wallet">
            <div className="wallet__header">
                {showWalletMessage && (
                    <div className="wallet__status" role="status">
                        <SpinnerText active={isWalletLoading} spinner={spinner}>
                            {walletMessage}
                        </SpinnerText>
                    </div>
                )}
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
            <div className="account-page__line">
                <span className="account-page__prompt">address</span>
                <CopyableValue
                    disabled={!walletAccountKey}
                    plain
                    value={walletAccountDisplay}
                    onCopy={onCopy}
                />
            </div>
            <div className="wallet__grid">
                <div className="wallet__cell">
                    <span>balance</span>
                    <strong>{verified ? verified.balance.toString() : isNew ? DEFAULT_ACCOUNT_BALANCE.toString() : 'unknown'}</strong>
                    <small>
                        {isAccountBehind
                            ? <SpinnerText active spinner={spinner}>updating</SpinnerText>
                            : verified ? `nonce ${verified.nonce.base.toString()} / ${verified.txCount.toString()} txs` : isNew ? 'new account' : '\u00a0'}
                    </small>
                </div>
                <div className="wallet__cell">
                    <span>local nonce</span>
                    <strong>{nonce}</strong>
                </div>
                {verified && (
                    <div className="wallet__evidence account-proof-grid__evidence">
                        <CertificateDatum target={verified.snapshot} latest />
                        <ProofDatum
                            label="account proof"
                            verified
                            value={<span className="proof-badge">loc {verified.location.toString()} / h{verified.writeHeight.toString()}</span>}
                        />
                    </div>
                )}
            </div>
            {wallet && <PageStatus message={accountMessage} />}
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
                        placeholder="recipient address"
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
                <button
                    className="transfer__submit"
                    disabled={!wallet || isSubmitting}
                    type="submit"
                >
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

function IdentifierValue({ value }: { value: string }) {
    return (
        <span className="copyable__value" aria-hidden="true">
            <span className="copyable__full">{value}</span>
            <span className="copyable__short">{shortHex(value)}</span>
            <span className="copyable__compact">{shortHex(value, 6)}</span>
        </span>
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
            aria-label={`copy ${value}`}
            className={className}
            disabled={disabled}
            onClick={handleClick}
            title={value}
            type="button"
        >
            <IdentifierValue value={value} />
        </button>
    );
}

function AddressValue({
    kind = 'address',
    disabled = false,
    plain = false,
    value,
    onOpenAddress,
}: {
    kind?: 'address' | 'transaction';
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
            aria-label={`open ${kind} ${value}`}
            className={className}
            disabled={disabled}
            onClick={() => onOpenAddress(value)}
            title={`open ${kind} ${value}`}
            type="button"
        >
            <IdentifierValue value={value} />
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
    onOpenTransaction,
}: {
    transactions: SubmittedTransaction[];
    signedInAccountKey: string | null;
    onCopy: (value: string) => void;
    onOpenAddress: (value: string) => void;
    onOpenTransaction: (digest: string) => void;
}) {
    if (transactions.length === 0) {
        return null;
    }

    return (
        <section className="tx-history">
            <div className="account-page__subhead">
                <h3>submitted transactions</h3>
                {signedInAccountKey && (
                    <div className="account-page__pager">
                        <button type="button" onClick={() => onOpenAddress(signedInAccountKey)}>view account</button>
                    </div>
                )}
            </div>
            <div className="account-tx-list">
                {transactions.map((tx) => (
                    <TransactionRecord
                        key={tx.digest}
                        onCopy={onCopy}
                        onOpenAddress={onOpenAddress}
                        onOpenTransaction={onOpenTransaction}
                        signedInAccountKey={signedInAccountKey}
                        tx={tx}
                    />
                ))}
            </div>
        </section>
    );
}

function TransactionRecord({
    onCopy,
    onOpenAddress,
    onOpenTransaction,
    signedInAccountKey,
    tx,
}: {
    onCopy: (value: string) => void;
    onOpenAddress: (value: string) => void;
    onOpenTransaction: (digest: string) => void;
    signedInAccountKey: string | null;
    tx: SubmittedTransaction;
}) {
    const timeline = submissionTimeline(tx);
    const failure = timeline.find((step) => step.state === 'failed');
    const reason = failure?.detail ?? '';
    const party = (value: string) => signedInAccountKey !== null && normalizeAccountInput(value) === signedInAccountKey
        ? <CopyableValue value={value} onCopy={onCopy} />
        : <AddressValue value={value} onOpenAddress={onOpenAddress} />;
    return (
        <div className="account-tx-row">
            <div className="account-tx-row__main">
                <AddressValue kind="transaction" value={tx.digest} onOpenAddress={onOpenTransaction} />
                <span className="tx-party">
                    <span className="account-tx-row__label">from</span>
                    {party(tx.sender)}
                </span>
                <span className="tx-party">
                    <span className="account-tx-row__label">to</span>
                    {party(tx.to)}
                </span>
            </div>
            <div className="account-tx-row__meta">
                <span>value {tx.value}</span>
                <span>nonce {tx.nonce}</span>
                <span>{formatClock(tx.submittedAt)}</span>
                {reason && <span className="tx-record__detail verification-error">{reason}</span>}
                <ol className="timeline" aria-label="submission progress">
                    {timeline.map((step) => (
                        <li key={step.kind} className={`timeline__step timeline__step--${step.state}`}>
                            {step.state === 'pending' && <span className="tx-proof-spinner" aria-hidden="true" />}
                            {step.state === 'failed' && <span aria-hidden="true">!</span>}
                            {step.state === 'done' && step.kind === 'verified'
                                ? <VerifiedEvidence>{step.label}</VerifiedEvidence>
                                : step.label}
                            {step.elapsedMs !== null && <span className="timeline__elapsed">{formatElapsed(step.elapsedMs)}</span>}
                        </li>
                    ))}
                </ol>
            </div>
        </div>
    );
}

/** Elapsed local time since submission, compact enough for a timeline step. */
function formatElapsed(milliseconds: number): string {
    if (milliseconds < 1_000) return `${milliseconds}ms`;
    if (milliseconds < 60_000) return `${(milliseconds / 1_000).toFixed(1)}s`;
    return `${Math.round(milliseconds / 1_000)}s`;
}

function shortHex(value: string, prefixLength = 10): string {
    return value.length <= prefixLength + 9
        ? value
        : `${value.slice(0, prefixLength)}…${value.slice(-8)}`;
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

function accountNonceState(account: WalletAccountView | null): NonceState {
    if (!account) {
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

function transactionFromLocation(): string {
    const url = new URL(window.location.href);
    return normalizeAccountInput(url.searchParams.get('transaction') ??
        /^\/transaction\/([0-9a-fA-F]{64})$/.exec(url.pathname)?.[1] ?? '') ?? '';
}

/** Reads a positive u64 block height from `?block=` or `/block/<height>`. */
function blockFromLocation(): bigint | null {
    const url = new URL(window.location.href);
    const value = url.searchParams.get('block') ?? /^\/block\/(\d+)$/.exec(url.pathname)?.[1];
    if (!value || !/^[1-9]\d{0,19}$/.test(value)) return null;
    const height = BigInt(value);
    return height <= (1n << 64n) - 1n ? height : null;
}

function readHistory(
    key: string,
    onError?: (message: string) => void,
): SubmittedTransaction[] {
    try {
        return readStoredHistory(key, window.localStorage);
    } catch (error) {
        onError?.(storageErrorMessage(error));
        return [];
    }
}

function writeHistory(key: string, history: SubmittedTransaction[]): string | null {
    try {
        window.localStorage.setItem(key, JSON.stringify(history));
        return null;
    } catch (error) {
        return storageErrorMessage(error);
    }
}

function storageErrorMessage(error: unknown): string {
    const detail = error instanceof Error ? error.message : String(error);
    return `browser storage unavailable. ${detail}`;
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

function StatusBadge({ status, spinner, height }: { status: Status; spinner: string; height: bigint | null }) {
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
        <span className="app__status">
            height <span className="accent">{height?.toString() ?? '—'}</span>
        </span>
    );
}

const ExplorerStats = memo(function ExplorerStats({
    blocks,
    totalBlocksObserved,
    totalTxObserved,
    observedRateWindow,
}: {
    blocks: VerifiedBlock[];
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
                label="local received tx/sec"
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
    blocks: VerifiedBlock[],
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
    for (const block of blocks.slice(0, HISTOGRAM_MAX_COLUMNS)) {
        if (latest === null || block.height > latest) {
            latest = block.height;
        }
        if (block.txCount > peak) {
            peak = block.txCount;
        }
    }

    return {
        latestHeight: latest?.toString() ?? '—',
        totalTxObserved: totalBlocksObserved === 0 ? '—' : totalTxObserved.toLocaleString(),
        peakTxPerBlock: totalBlocksObserved === 0 ? '—' : peak.toLocaleString(),
        avgTxPerBlock: formatAverageTxPerBlock(totalTxObserved, totalBlocksObserved),
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
 * The homepage's chart, statistics and block log. They share one view of the feed, so a block
 * enters all three in the same frame.
 */
function HomeFeed({ feed, onOpenBlock }: { feed: FeedState; onOpenBlock: (height: bigint) => void }) {
    const [now, setNow] = useState(Date.now);
    const reducedMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
    const shown = reducedMotion ? feed.totalBlocksObserved : shownCount(feed, now);
    const { blocks, totalTxObserved, totalBlocksObserved } = useMemo(() => shownFeed(feed, shown), [feed, shown]);

    // The clock runs only while blocks wait to be released.
    const releasing = shown < feed.totalBlocksObserved;
    useEffect(() => {
        if (!releasing) return;
        let frame = requestAnimationFrame(function step() {
            setNow(Date.now());
            frame = requestAnimationFrame(step);
        });
        return () => cancelAnimationFrame(frame);
    }, [releasing]);

    // A row's fade lasts at most two arrivals, so quick blocks do not leave the top rows dim.
    const twoArrivalsMs = feed.pace.rate > 0 ? 2 / feed.pace.rate : null;
    const rowFadeMs = twoArrivalsMs !== null && twoArrivalsMs < MIN_ROW_FADE_MS ? 0 : twoArrivalsMs;

    return (
        <>
            <Histogram blocks={blocks} />
            <ExplorerStats
                blocks={blocks}
                observedRateWindow={feed.observedRateWindow}
                totalBlocksObserved={totalBlocksObserved}
                totalTxObserved={totalTxObserved}
            />
            <BlockLog blocks={blocks} rowFadeMs={rowFadeMs} onOpenBlock={onOpenBlock} />
        </>
    );
}

const Histogram = memo(function Histogram({ blocks }: { blocks: VerifiedBlock[] }) {
    const frameRef = useRef<HTMLDivElement>(null);
    const [columns, setColumns] = useState(HISTOGRAM_INITIAL_COLUMNS);

    // Columns are a fixed pixel width from the stylesheet; the frame decides how many fit.
    useEffect(() => {
        const frame = frameRef.current;
        if (!frame) return;

        const recompute = () => {
            const columnWidth = parseFloat(getComputedStyle(frame).getPropertyValue('--histogram-column'));
            if (!(columnWidth > 0)) return;
            const availableColumns = Math.floor(frame.clientWidth / columnWidth);
            const nextColumns = Math.max(
                HISTOGRAM_MIN_COLUMNS,
                Math.min(HISTOGRAM_MAX_COLUMNS, availableColumns),
            );
            setColumns((current) => (current === nextColumns ? current : nextColumns));
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

    const { columns: bars, domain } = useMemo(() => buildHistogram(blocks, columns), [blocks, columns]);

    return (
        <div className="histogram-frame" ref={frameRef}>
            <div className="histogram" role="img" aria-label={`recent block transaction counts, zero to ${domain} transactions per block; ticks mark empty blocks`}>
                {bars.map((bar, index) => bar === null
                    ? <span className="histogram__column" key={`blank-${index}`} />
                    : <span
                        className={bar.txCount === 0 ? 'histogram__column histogram__column--empty' : 'histogram__column'}
                        key={bar.height.toString()}
                        style={{ '--bar': bar.fraction } as React.CSSProperties}
                    />)}
            </div>
        </div>
    );
});

const BlockLog = memo(function BlockLog({ blocks, rowFadeMs, onOpenBlock }: {
    blocks: VerifiedBlock[];
    rowFadeMs: number | null;
    onOpenBlock: (height: bigint) => void;
}) {
    // Hover and focus freeze the displayed rows so new blocks do not shift a row under the pointer.
    // Touch input pauses only through focus.
    const [pausedBlocks, setPausedBlocks] = useState<VerifiedBlock[] | null>(null);
    const pointerInside = useRef(false);
    const recent = (pausedBlocks ?? blocks).slice(0, BLOCK_LOG_MAX);

    if (recent.length === 0) return null;

    return (
        <section className="block-log" aria-label="recent finalized blocks">
            <div className="block-log__header" aria-hidden="true">
                <span>height</span>
                <span>block hash</span>
                <span># txs</span>
                <span>timestamp</span>
            </div>
            <div
                className="block-log__list"
                style={rowFadeMs === null ? undefined : { '--block-row-fade': `${rowFadeMs}ms` } as React.CSSProperties}
                onPointerEnter={(event) => {
                    if (event.pointerType === 'touch') return;
                    pointerInside.current = true;
                    setPausedBlocks((current) => current ?? blocks);
                }}
                onPointerLeave={(event) => {
                    if (event.pointerType === 'touch') return;
                    pointerInside.current = false;
                    if (!event.currentTarget.contains(document.activeElement)) {
                        setPausedBlocks(null);
                    }
                }}
                onFocus={() => setPausedBlocks((current) => current ?? blocks)}
                onBlur={(event) => {
                    if (!pointerInside.current && !event.currentTarget.contains(event.relatedTarget)) {
                        setPausedBlocks(null);
                    }
                }}
            >
                {recent.map((block) => (
                    <BlockLogRow key={block.height.toString()} block={block} onOpenBlock={onOpenBlock} />
                ))}
            </div>
        </section>
    );
});

const BlockLogRow = memo(function BlockLogRow({
    block,
    onOpenBlock,
}: {
    block: VerifiedBlock;
    onOpenBlock: (height: bigint) => void;
}) {
    const hash = useMemo(() => bytesToHex(block.digest), [block.digest]);

    // A touch press focuses the row so the log freezes before the click lands. A canceled touch
    // releases it.
    return (
        <button
            type="button"
            className="block-row"
            onPointerDown={(event) => {
                if (event.pointerType === 'touch') {
                    event.currentTarget.focus({ preventScroll: true });
                }
            }}
            onPointerCancel={(event) => {
                if (event.pointerType === 'touch') event.currentTarget.blur();
            }}
            onClick={() => onOpenBlock(block.height)}
            aria-label={`view block ${block.height}`}
            aria-describedby={`block-finality-${block.height}`}
        >
            <span className="block-row__height">
                {block.height.toString()}
                <span className="block-row__finality" id={`block-finality-${block.height}`}>
                    <VerifiedEvidence>
                        {block.height === block.finality.certifiedHeight
                            ? `cert v${block.finality.certificateView}`
                            : `via h${block.finality.certifiedHeight}`}
                    </VerifiedEvidence>
                </span>
            </span>
            <span className="block-row__hash" title={hash}>
                {shortHex(hash)}
            </span>
            <span className="block-row__txcount">{block.txCount.toLocaleString()}</span>
            <span className="block-row__time">{formatClock(block.timestampMs)}</span>
        </button>
    );
});
