// The paid-stream demo view: an x402-style metered service driven end to end
// from the browser. The passkey wallet signs one OpenChannel that escrows the
// deposit and delegates voucher signing to a fresh per-channel ed25519 key;
// that key then pays the operator's `/stream` endpoint token by token while
// the essay renders. Stop paying and the stream pauses, then hangs up —
// enforcement is the demo. The close (or a post-expiry timeout reclaim)
// refunds the deposit remainder straight back to the wallet.

import { memo, useEffect, useMemo, useRef, useState } from 'react';

import { AddressValue } from './AddressValue';
import {
    channelAddress,
    encodeTransactionBatch,
    fromHex,
    parseAccountKeyHex,
    toHex,
} from './codec';
import { statusHasHeight, submitTransactions, type TxStatus } from './mempool';
import { consumeNonce } from './nonce';
import {
    OperatorRequestError,
    fetchAdvertisement,
    openStream,
    postVoucher,
    registerChannel,
    settleChannel,
} from './operatorClient';
import {
    channelDeposit,
    channelExpiry,
    isSettlementBoundaryMessage,
    resolveChannelRecordState,
    voucherFinalTopUp,
    voucherTopUp,
    type OperatorAdvertisement,
    type StreamEnd,
    type StreamMeter,
} from './paidStream';
import { fetchIndexedAccountState, fetchIndexedNonceState } from './qmdb';
import { createVoucherKey, importVoucherKey, type VoucherKey } from './voucherKey';
import { errorMessage, readStoredJson, shortHex } from './util';

/// Retry delay for a transiently failed voucher post — well inside the
/// operator's grace window, so a blip cannot kill a paying stream.
const VOUCHER_RETRY_MS = 1_000;
/// The page tracks one outstanding channel: the record lands here after the
/// wallet signs the open (before submission) and stays until a close or a
/// timeout reclaim resolves the escrow — the only two ways the funds move,
/// so the record is never deleted while they haven't.
const CHANNEL_STORAGE_KEY = 'constantinople.stream-channel.v2';

interface ChannelRecord {
    readonly channelHex: string;
    /// Optional only for records written before payer identity was persisted.
    /// Old records can recover it from the currently signed-in wallet after
    /// verifying that it derives the stored channel address.
    readonly payerHex?: string;
    readonly openNonce: string;
    readonly deposit: string;
    readonly openTxDigestHex: string;
    /// The exact signed open transaction. Persisted before the first
    /// submission and resubmitted verbatim on retries: the bytes carry the
    /// wallet nonce they were signed with, so a copy can never land twice
    /// and retrying is always safe.
    readonly signedOpenTxHex: string;
    /// The receiver/operator account and expiry the channel was opened with
    /// (a timeout reclaim must reconstruct the channel address from them).
    readonly operatorHex: string;
    readonly expiry: string;
    /// The channel's delegated voucher key: the raw public key the channel
    /// address commits to, and the private half (an extractable JWK — see
    /// voucherKey.ts for the demo-posture tradeoff).
    readonly voucherPublicKeyHex: string;
    readonly voucherKeyJwk: JsonWebKey;
    /// Opaque bearer credential granted by registration. Optional only for
    /// records written by an older build; the registration retry fills it in
    /// before streaming or settlement becomes available.
    readonly capability?: string;
}

/// What the wallet hands back for persistence after signing the open,
/// before submitting it.
export interface PendingOpen {
    readonly channelHex: string;
    readonly payerHex: string;
    readonly openNonce: string;
    readonly openTxDigestHex: string;
    readonly signedOpenTxHex: string;
}

/// The page's ask to the wallet: sign and submit one OpenChannel. `persist`
/// MUST be called after signing and before submission, so a lost response
/// cannot orphan the escrow.
export interface OpenStreamChannelRequest {
    readonly operatorHex: string;
    readonly voucherPublicKeyHex: string;
    readonly deposit: bigint;
    readonly expiry: bigint;
    readonly persist: (pending: PendingOpen) => void;
}

/// The page's ask to the wallet: sign and submit one TimeoutChannel
/// reclaiming an expired channel's escrow.
export interface ReclaimStreamChannelRequest {
    readonly channelHex: string;
    readonly operatorHex: string;
    readonly voucherPublicKeyHex: string;
    readonly openNonce: string;
}

type Phase = 'idle' | 'opening' | 'ready' | 'streaming' | 'ended' | 'settling' | 'settled';

export interface PaidStreamPageProps {
    readonly operatorUrl: string;
    readonly mempoolUrl: string;
    readonly sqlUrl: string;
    readonly chainHeight: bigint | null;
    readonly walletReady: boolean;
    readonly walletAccountHex: string | null;
    readonly walletBalance: number | null;
    /// Signs and submits the OpenChannel with the passkey (one user ceremony
    /// per channel — the delegation the voucher key operates under).
    readonly onOpenChannel: (request: OpenStreamChannelRequest) => Promise<TxStatus | null>;
    /// Signs and submits a post-expiry TimeoutChannel with the passkey.
    readonly onReclaimChannel: (request: ReclaimStreamChannelRequest) => Promise<TxStatus | null>;
    readonly onOpenWallet: () => void;
    readonly onOpenAddress: (accountHex: string) => void;
    readonly onNotify: (message: string) => void;
}

/// Memoized so unrelated App state does not disturb an active stream. The
/// latest chain height intentionally re-renders the page to update expiry
/// runway and reveal post-expiry recovery.
export const PaidStreamPage = memo(function PaidStreamPage({
    operatorUrl,
    mempoolUrl,
    sqlUrl,
    chainHeight,
    walletReady,
    walletAccountHex,
    walletBalance,
    onOpenChannel,
    onReclaimChannel,
    onOpenWallet,
    onOpenAddress,
    onNotify,
}: PaidStreamPageProps) {
    const [phase, setPhase] = useState<Phase>('idle');
    const [note, setNote] = useState('');
    // Payment feedback is transient: a later stream chunk proves the
    // operator accepted payment and resumed delivery, so it clears itself.
    const [paymentNotice, setPaymentNotice] = useState('');
    const [advertisement, setAdvertisement] = useState<OperatorAdvertisement | null>(null);
    const [channel, setChannel] = useState<ChannelRecord | null>(() => readChannelRecord());
    const [text, setText] = useState('');
    const [meter, setMeter] = useState<StreamMeter>({ served: 0n, paid: 0n });
    const [paying, setPaying] = useState(true);
    const [voucherCount, setVoucherCount] = useState(0);
    const [endReason, setEndReason] = useState<StreamEnd['reason'] | null>(null);

    const payingRef = useRef(true);
    /// The current voucher post, if any. Settlement waits for this before
    /// flushing the final delivered cumulative, so closing can never race an
    /// older in-flight voucher.
    const voucherPostRef = useRef<Promise<void> | null>(null);
    const lastSignedRef = useRef(0n);
    /// A cumulative the operator permanently rejected; never re-sign it, or
    /// a doomed voucher would re-post on every chunk.
    const deadTargetRef = useRef<bigint | null>(null);
    /// Mirror of `meter`, for the voucher retry timer (state is stale
    /// inside it). `updateMeter` is the only writer of either.
    const meterRef = useRef<StreamMeter>({ served: 0n, paid: 0n });
    /// Bumped by `resetSession` so a voucher post that resolves after a
    /// reset cannot write the old channel's cumulative into the new one.
    const sessionGenerationRef = useRef(0);
    /// The active channel's voucher signer, created at open or reactivated
    /// from the persisted record on load.
    const voucherKeyRef = useRef<VoucherKey | null>(null);
    const closeStreamRef = useRef<(() => void) | null>(null);
    const textRef = useRef<HTMLPreElement | null>(null);

    const updateMeter = ({ served, paid }: StreamMeter) => {
        meterRef.current = { served, paid };
        setMeter({ served, paid });
    };

    /// The channel's decoded account key (its hex is what persists).
    const channelKey = useMemo(
        () => (channel ? parseAccountKeyHex(channel.channelHex) : null),
        [channel],
    );

    // Boot: fetch the operator advertisement, and reactivate a restored
    // channel's voucher key so a reloaded page can keep paying.
    useEffect(() => {
        let cancelled = false;
        fetchAdvertisement(operatorUrl).then(
            (ad) => {
                if (!cancelled) setAdvertisement(ad);
            },
            () => {
                if (!cancelled) {
                    setAdvertisement(null);
                }
            },
        );
        void (async () => {
            const restored = readChannelRecord();
            if (!restored) return;
            try {
                const key = await importVoucherKey(
                    restored.voucherKeyJwk,
                    restored.voucherPublicKeyHex,
                );
                if (!cancelled) voucherKeyRef.current = key;
            } catch (error) {
                if (!cancelled) {
                    setNote(`stored voucher key failed to import: ${errorMessage(error)}`);
                }
            }
        })();
        return () => {
            cancelled = true;
        };
    }, [operatorUrl]);

    const retryOperator = async () => {
        setNote('checking operator…');
        try {
            setAdvertisement(await fetchAdvertisement(operatorUrl));
            setNote('');
        } catch {
            setAdvertisement(null);
            setNote('');
        }
    };

    /// Closes a live stream, if any. Nulling the ref matters: the voucher
    /// retry timer reads `closeStreamRef.current !== null` as "stream is
    /// live".
    const closeStream = () => {
        closeStreamRef.current?.();
        closeStreamRef.current = null;
    };

    /// Clears a browser-local recovery record only when the index proves that
    /// it cannot represent live escrow: either the channel was deleted, or it
    /// never existed and its signed open nonce has since been consumed.
    const resolveStoredChannel = async (
        record: ChannelRecord,
        cancelled?: () => boolean,
    ): Promise<boolean> => {
        // A resolution that outlives its session (the user reset and opened
        // a fresh channel while a query stalled) must not touch the new
        // session's phase.
        const generation = sessionGenerationRef.current;
        const stale = () =>
            (cancelled?.() ?? false) || generation !== sessionGenerationRef.current;
        try {
            // The payer nonce is read BEFORE the channel state — see
            // `resolveChannelRecordState` for why the reverse order races
            // the indexer ingesting the open and can discard the only
            // recovery record for live escrow.
            let openNonceAvailable: boolean | null = null;
            const payerHex = record.payerHex ?? walletAccountHex;
            if (payerHex && (await channelMatchesPayer(record, payerHex))) {
                if (stale()) return false;
                const payerNonce = await fetchIndexedNonceState({
                    sqlUrl,
                    account: payerHex,
                });
                if (payerNonce !== null) {
                    openNonceAvailable =
                        consumeNonce(payerNonce, BigInt(record.openNonce)) !== null;
                }
            }
            if (stale()) return false;
            const channelState = await fetchIndexedAccountState({
                sqlUrl,
                account: record.channelHex,
            });
            if (stale()) return false;

            switch (resolveChannelRecordState({ channelState, openNonceAvailable })) {
                case 'settled':
                    clearStoredChannel(
                        record,
                        'channel resolved on-chain; no deposit remains locked.',
                        'settled',
                    );
                    return true;
                case 'never-opened':
                    clearStoredChannel(
                        record,
                        'channel open never finalized; no deposit was locked.',
                        'idle',
                    );
                    return true;
                case 'keep':
                    return false;
            }
        } catch {
            // Reconciliation is recovery assistance, not a prerequisite for
            // normal operation. A transient indexer failure leaves the only
            // recovery record intact and lets the existing action continue.
            return false;
        }
    };

    const clearStoredChannel = (record: ChannelRecord, message: string, nextPhase: Phase) => {
        // A different channel may have superseded this record (adopted from
        // another tab) while its resolution was in flight; leave the
        // successor's record — and the page state now describing it — alone.
        const stored = readChannelRecord();
        if (stored !== null && stored.channelHex !== record.channelHex) return;
        if (stored !== null) {
            clearChannelRecord();
        }
        setChannel((current) =>
            current?.channelHex === record.channelHex ? null : current,
        );
        setEndReason(null);
        setNote(message);
        setPhase(nextPhase);
    };

    // Close a live stream when the view unmounts.
    useEffect(() => () => closeStream(), []);

    // A settlement sweep or a lost HTTP response can resolve the channel
    // while its browser-local record survives. Reconcile that record as soon
    // as the page restores it so stale retry/reclaim controls never appear.
    useEffect(() => {
        const restored = readChannelRecord();
        if (!restored) return;

        let cancelled = false;
        void resolveStoredChannel(restored, () => cancelled);
        return () => {
            cancelled = true;
        };
    }, [sqlUrl, walletAccountHex]);

    // Follow the typewriter.
    useEffect(() => {
        const element = textRef.current;
        if (element) element.scrollTop = element.scrollHeight;
    }, [text]);

    const setPayingMode = (next: boolean) => {
        payingRef.current = next;
        setPaying(next);
        // A paused stream emits no further events, so resuming payment must
        // re-run the payment decision itself — otherwise the grace window
        // kills the stream despite the resume.
        if (next) maybePay();
    };

    /// Signs and posts one voucher for `target`, recording it in the payment
    /// log on success. Owns the outstanding-post bookkeeping: the promise
    /// stored in `voucherPostRef` never rejects (overlap checks and
    /// settlement's wait await it bare) and is cleared on completion unless
    /// the session was reset (generation guard) or a newer post replaced it
    /// (identity guard). The returned promise DOES reject, so each caller
    /// applies its own error policy.
    const postSignedVoucher = (
        voucherKey: VoucherKey,
        channelKey: Uint8Array,
        target: bigint,
    ): Promise<void> => {
        const generation = sessionGenerationRef.current;
        const pending = (async () => {
            const signature = await voucherKey.signVoucher(channelKey, target);
            await postVoucher(operatorUrl, { channel: channelKey, cumulative: target, signature });
            if (generation !== sessionGenerationRef.current) return;
            lastSignedRef.current = target;
            setVoucherCount((current) => current + 1);
        })();
        let tracked!: Promise<void>;
        tracked = pending
            .catch(() => undefined)
            .finally(() => {
                // A post stalled across a reset must not clear the NEW
                // session's post out from under it.
                if (
                    generation === sessionGenerationRef.current &&
                    voucherPostRef.current === tracked
                ) {
                    voucherPostRef.current = null;
                }
            });
        voucherPostRef.current = tracked;
        return pending;
    };

    /// Signs and posts a voucher whenever the meter (read from `meterRef`,
    /// which every stream event updates first) says one is due. Called from
    /// every stream event; a ref guards against overlapping posts.
    const maybePay = () => {
        if (!payingRef.current || voucherPostRef.current) return;
        const voucherKey = voucherKeyRef.current;
        if (!voucherKey || !advertisement || !channel || !channelKey) return;
        const target = voucherTopUp({
            served: meterRef.current.served,
            paid: meterRef.current.paid,
            lastSigned: lastSignedRef.current,
            deadTarget: deadTargetRef.current,
            debtLimit: advertisement.debtLimit,
            deposit: BigInt(channel.deposit),
        });
        if (target === null) return;
        const generation = sessionGenerationRef.current;
        postSignedVoucher(voucherKey, channelKey, target).catch((error) => {
            if (generation !== sessionGenerationRef.current) return;
            if (error instanceof OperatorRequestError && !error.transient) {
                deadTargetRef.current = target;
                setPaymentNotice(`voucher rejected: ${error.message}`);
                return;
            }
            // The operator announces a pause only once per pause, so a
            // transiently failed post must retry on its own — no further
            // SSE event may arrive to re-trigger payment before the
            // grace window expires.
            setPaymentNotice(`voucher failed: ${errorMessage(error)} — retrying`);
            window.setTimeout(() => {
                if (closeStreamRef.current !== null) maybePay();
            }, VOUCHER_RETRY_MS);
        });
    };

    /// Stops batching at settlement time: after the stream is closed and its
    /// meter can no longer advance, wait for an older post and then cover any
    /// delivered remainder exactly. This preserves the no-prepayment policy
    /// without making the operator forfeit the last partial voucher window.
    const flushDeliveredVoucher = async (): Promise<bigint | null> => {
        await voucherPostRef.current;
        if (!payingRef.current || !channel || !channelKey) return null;

        const target = voucherFinalTopUp({
            served: meterRef.current.served,
            paid: meterRef.current.paid,
            lastSigned: lastSignedRef.current,
            deposit: BigInt(channel.deposit),
        });
        if (target === null) return null;
        if (deadTargetRef.current === target) {
            throw new Error(`the operator previously rejected the final voucher ${target}`);
        }

        const voucherKey = voucherKeyRef.current;
        if (!voucherKey) throw new Error('voucher key unavailable');
        await postSignedVoucher(voucherKey, channelKey, target);
        return target;
    };

    /// Open the channel from the wallet (one passkey ceremony) and register
    /// it with the operator.
    const startSession = async () => {
        if (!walletReady) {
            setNote('sign in with the wallet first — it signs the channel open');
            onOpenWallet();
            return;
        }
        setPhase('opening');
        setNote('');
        // Tracked outside the try so a failure never re-creates a record
        // the flow already persisted.
        let record = channel;
        // Another tab may have persisted a channel since this page mounted.
        // The record guards live escrow (it is the only copy of the signed
        // open and the voucher key), so never clobber it — adopt it.
        const stored = readChannelRecord();
        if (stored && stored.channelHex !== record?.channelHex) {
            record = stored;
            setChannel(stored);
            voucherKeyRef.current = null;
        }
        try {
            if (record && (await resolveStoredChannel(record))) return;

            // Fresh advertisement: the expiry derives from the operator's
            // current height.
            const ad = await fetchAdvertisement(operatorUrl);
            setAdvertisement(ad);

            if (!record) {
                const deposit = channelDeposit(ad);
                if (walletBalance === null || BigInt(walletBalance) < deposit) {
                    throw new Error(
                        `wallet balance too low for the ${deposit} deposit; mint to the wallet first`,
                    );
                }
                // A fresh delegated key per channel; generating it doubles
                // as the WebCrypto ed25519 support probe (needs Chrome 137+,
                // Safari 17+, or Firefox 130+).
                const voucherKey = await createVoucherKey();
                voucherKeyRef.current = voucherKey;
                const expiry = channelExpiry(ad);
                const voucherPublicKeyHex = toHex(voucherKey.publicKey);
                setNote('approve the channel open in the wallet…');
                const openStatus = await onOpenChannel({
                    operatorHex: ad.accountHex,
                    voucherPublicKeyHex,
                    deposit,
                    expiry,
                    // Runs after signing, before submission: from here the
                    // escrow can always be found again.
                    persist: (pending) => {
                        record = {
                            ...pending,
                            deposit: deposit.toString(),
                            operatorHex: ad.accountHex,
                            expiry: expiry.toString(),
                            voucherPublicKeyHex,
                            voucherKeyJwk: voucherKey.privateJwk,
                        };
                        persistChannel(record);
                        setChannel(record);
                    },
                });
                const signedRecord = readChannelRecord();
                if (!signedRecord) {
                    throw new Error('channel open was not signed');
                }
                record = signedRecord;
                // NOTE: an open rejected at execution is indistinguishable
                // from a dropped proposal here — a 1-tx batch with nothing
                // included always reports `dropped` with no height (never
                // `partially_finalized`). Surfacing the difference needs the
                // mempool to report judged drops with a height (deferred);
                // until then the registration retry loop is the only signal.
                // A dropped proposal or lost submission response does not
                // require another passkey ceremony. Resubmit the exact
                // persisted bytes; the signed nonce makes this idempotent if
                // the first request actually finalized.
                if (openStatus === null || openStatus.status === 'dropped') {
                    setNote('confirming the channel open on-chain…');
                    await submitTransactions(
                        mempoolUrl,
                        encodeTransactionBatch([fromHex(signedRecord.signedOpenTxHex)]),
                    );
                }
            } else {
                // A restored or retried record: make sure its voucher key is
                // active and its open is on-chain (verbatim resubmission is
                // idempotent).
                if (!voucherKeyRef.current) {
                    voucherKeyRef.current = await importVoucherKey(
                        record.voucherKeyJwk,
                        record.voucherPublicKeyHex,
                    );
                }
                setNote('confirming the channel open on-chain…');
                // Resubmit the persisted open verbatim. This is advisory:
                // registration verifies the digest against the chain, so a
                // duplicate finalized open may report dropped and still
                // register successfully. Known demo edge: if the first
                // response was lost and the wallet reused the rolled-back
                // nonce before retry, the open cannot land; clear the stream
                // channel from localStorage to recover from repeated 503s.
                await submitTransactions(
                    mempoolUrl,
                    encodeTransactionBatch([fromHex(record.signedOpenTxHex)]),
                );
            }

            // Register with the operator (idempotent, retried through
            // indexer lag). The zero voucher proves this browser holds the
            // channel's voucher key and makes the channel closeable from
            // the very first moment.
            setNote('registering the channel with the operator…');
            const voucherKey = voucherKeyRef.current;
            if (!voucherKey) throw new Error('voucher key unavailable');
            const zeroVoucherSignature = await voucherKey.signVoucher(
                parseAccountKeyHex(record.channelHex),
                0n,
            );
            const capability = await registerChannel(operatorUrl, {
                openTxDigestHex: record.openTxDigestHex,
                zeroVoucherSignature,
            });
            record = { ...record, capability };
            persistChannel(record);
            setChannel(record);
            setNote('');
            onNotify('channel ready');
            setPhase('ready');
        } catch (error) {
            const message = error instanceof Error ? error.message : String(error);
            setNote(
                message === 'open transaction is not finalized'
                    ? 'still finalizing. try again shortly.'
                    : message,
            );
            // Every failure returns to 'idle': the start button is the
            // retry path — it reuses a persisted record and re-runs the
            // idempotent resubmit and registration steps.
            setPhase('idle');
        }
    };

    // The text pane is deliberately not cleared: the operator resumes from
    // the channel's persistent served position, so on a stop/resume or
    // reconnect the existing prefix is exactly what precedes the next chunk.
    // Only a fresh channel (resetSession) starts a blank pane.
    const startStream = () => {
        if (!channelKey || !channel?.capability) return;
        closeStream();
        setEndReason(null);
        setNote('');
        setPaymentNotice('');
        setPhase('streaming');
        closeStreamRef.current = openStream(operatorUrl, channelKey, channel.capability, {
            onChunk: (chunk) => {
                setText((current) => current + chunk.text);
                updateMeter(chunk);
                setPaymentNotice('');
                maybePay();
            },
            onPaymentRequired: (paused) => {
                updateMeter(paused);
                setPaymentNotice('stream paused — payment required');
                maybePay();
            },
            onEnd: (end) => {
                closeStreamRef.current = null;
                updateMeter(end);
                setEndReason(end.reason);
                setNote('');
                setPaymentNotice('');
                setPhase('ended');
            },
            onError: (message) => {
                closeStreamRef.current = null;
                setNote(message);
                setPaymentNotice('');
                setPhase('ready');
            },
        });
    };

    const stopStream = () => {
        closeStream();
        setPaymentNotice('');
        setPhase('ready');
    };

    const settle = async () => {
        if (!channelKey || !channel?.capability) return;
        closeStream();
        setPaymentNotice('');
        const origin = settlementOrigin(phase);
        setPhase('settling');
        try {
            setNote('paying for delivered content…');
            let finalVoucher: bigint | null = null;
            try {
                finalVoucher = await flushDeliveredVoucher();
            } catch (error) {
                const settlementStarted =
                    error instanceof OperatorRequestError &&
                    !error.transient &&
                    isSettlementBoundaryMessage(error.message);
                if (!settlementStarted) throw error;
            }
            setNote('closing the channel on-chain…');
            const outcome = await settleChannel(operatorUrl, channelKey, channel.capability);
            if (outcome.settled) {
                setNote('');
                onNotify(
                    finalVoucher === null
                        ? `settled ${outcome.cumulative} on-chain; remaining deposit refunded.`
                        : `settled ${outcome.cumulative} on-chain; final voucher ${finalVoucher}; remaining deposit refunded.`,
                );
                // A finalized close resolved the escrow, so there is
                // nothing left to reclaim.
                clearChannelRecord();
                setChannel(null);
                setEndReason(null);
                setPhase('settled');
            } else {
                setNote('channel expired before settlement. reclaim the deposit.');
                // An abandoned close leaves the escrow live. Keep its only
                // persisted recovery record and return to controls that
                // expose the post-expiry timeout reclaim.
                setPhase(origin);
            }
        } catch (error) {
            // The operator may have settled (or swept) this channel and
            // forgotten it; reconcile against the chain before surfacing a
            // retry that can only fail the same way.
            if (await resolveStoredChannel(channel)) return;
            setNote(`settlement failed: ${errorMessage(error)}`);
            setPhase(origin);
        }
    };

    /// Reclaims an expired channel's escrow with a TimeoutChannel signed by
    /// the wallet — the exit for a channel the operator will never close
    /// (e.g. one whose registration never completed). The chain refuses the
    /// reclaim until the block height passes the channel's expiry, so the
    /// freshest available height gates the attempt with a useful message
    /// instead of a doomed submission.
    const reclaimDeposit = async () => {
        if (!channel) return;
        closeStream();
        // See `settle`: failure must return whence it came.
        const origin = settlementOrigin(phase);
        setPhase('settling');
        setNote('reclaiming the deposit…');
        try {
            // Only the payer's wallet derives this channel's address; any
            // other signer would submit a doomed transaction and burn a
            // wallet nonce for nothing.
            if (
                !walletAccountHex ||
                !(await channelMatchesPayer(channel, walletAccountHex))
            ) {
                throw new Error(
                    'this channel was opened by a different wallet — sign in with the wallet that opened it',
                );
            }
            // The reclaim goes to the mempool, not the operator: when the
            // operator is unreachable (the very case a timeout reclaim
            // exists for), fall back to the page's own view of the chain
            // height rather than refusing.
            const ad = await fetchAdvertisement(operatorUrl).catch(() => null);
            const height = maxHeight(ad?.height ?? null, currentHeight);
            const expiry = BigInt(channel.expiry);
            if (height !== null && height <= expiry) {
                throw new Error(
                    `channel not expired yet — reclaimable after block ${expiry} (chain is at ${height})`,
                );
            }
            setNote('approve the reclaim in the wallet…');
            const status = await onReclaimChannel({
                channelHex: channel.channelHex,
                operatorHex: channel.operatorHex,
                voucherPublicKeyHex: channel.voucherPublicKeyHex,
                openNonce: channel.openNonce,
            });
            if (status === null || !statusHasHeight(status)) {
                if (await resolveStoredChannel(channel)) return;
                throw new Error(
                    `timeout reclaim was ${status?.status ?? 'not signed'} — the channel may already be closed`,
                );
            }
            clearChannelRecord();
            setChannel(null);
            setEndReason(null);
            setNote('');
            onNotify('deposit returned to wallet');
            setPhase('settled');
        } catch (error) {
            setNote(errorMessage(error));
            setPhase(origin);
        }
    };

    /// Starts over after the previous channel resolved (settled close or
    /// timeout reclaim — the record is gone either way, and the refund
    /// landed back in the wallet).
    const resetSession = () => {
        sessionGenerationRef.current += 1;
        voucherKeyRef.current = null;
        // The generation bump above stops any straggling post from clearing
        // this, so the reset clears it itself.
        voucherPostRef.current = null;
        setText('');
        updateMeter({ served: 0n, paid: 0n });
        setVoucherCount(0);
        setPaymentNotice('');
        setEndReason(null);
        lastSignedRef.current = 0n;
        deadTargetRef.current = null;
        setPayingMode(true);
        setNote('');
        setPhase('idle');
    };

    if (!operatorUrl) {
        return (
            <div className="paid-stream">
                <p className="paid-stream__note">operator not configured. set VITE_OPERATOR_URL.</p>
            </div>
        );
    }

    const debtLimit = advertisement?.debtLimit ?? 0n;
    const debt = meter.served > meter.paid ? meter.served - meter.paid : 0n;
    const paymentWarning = debtLimit > 0n && debt * 4n >= debtLimit * 3n;
    const streamCost = advertisement
        ? advertisement.streamTokens * advertisement.pricePerToken
        : 0n;
    const contentRatio = streamCost > 0n ? Number(meter.served) / Number(streamCost) : 0;
    const deliveredTokens = advertisement?.pricePerToken
        ? meter.served / advertisement.pricePerToken
        : 0n;
    const streaming = phase === 'streaming';
    const channelExpiryBlock = channel ? BigInt(channel.expiry) : null;
    const currentHeight = maxHeight(chainHeight, advertisement?.height ?? null);
    const reclaimable =
        channelExpiryBlock !== null &&
        currentHeight !== null &&
        currentHeight > channelExpiryBlock;
    const expiryDetail =
        channelExpiryBlock === null || currentHeight === null
            ? null
            : currentHeight > channelExpiryBlock
              ? 'expired'
              : currentHeight === channelExpiryBlock
                ? 'expires this block'
                : `${(channelExpiryBlock - currentHeight).toString()} blocks left`;
    // Known-wrong wallet for the persisted channel (old records lack
    // payerHex; those fall through to reclaimDeposit's derivation check).
    const payerMismatch =
        channel?.payerHex !== undefined &&
        walletAccountHex !== null &&
        channel.payerHex.toLowerCase() !== walletAccountHex.toLowerCase();
    const terminalStream =
        phase === 'ended' && endReason !== null && endReason !== 'payment_timeout';
    const endMessage = streamEndMessage(endReason, paying);
    const showStreamOutput = channel?.capability !== undefined || phase === 'settled';
    const operatorAccountHex = advertisement?.accountHex ?? channel?.operatorHex ?? null;

    return (
        <div className="paid-stream">
            <div className="paid-stream__heading">
                <h2>stream</h2>
            </div>

            {phase !== 'settled' && !advertisement && (
                <div className="paid-stream__summary-heading">
                    <span className="paid-stream__operator-retry">
                        <span>operator unavailable</span>
                        <button
                            className="action-button action-button--secondary"
                            onClick={() => void retryOperator()}
                            type="button"
                        >
                            retry
                        </button>
                    </span>
                </div>
            )}
            {phase !== 'settled' && (advertisement || channel) && (
                <div className="paid-stream__fact-groups">
                    <dl className="paid-stream__facts">
                        {operatorAccountHex && (
                            <div>
                                <dt>operator</dt>
                                <dd>
                                    <SessionAddress
                                        hex={operatorAccountHex}
                                        onOpenAddress={onOpenAddress}
                                    />
                                </dd>
                            </div>
                        )}
                        <div>
                            <dt>deposit</dt>
                            <dd>
                                {channel
                                    ? channel.deposit
                                    : advertisement
                                      ? `${channelDeposit(advertisement).toString()} required`
                                      : '—'}
                            </dd>
                        </div>
                        {advertisement && (
                            <div>
                                <dt>price</dt>
                                <dd>{advertisement.pricePerToken.toString()} / token</dd>
                            </div>
                        )}
                    </dl>
                    {channel && (
                        <dl className="paid-stream__facts">
                            <div>
                                <dt>channel</dt>
                                <dd>
                                    <SessionAddress
                                        hex={channel.channelHex}
                                        onOpenAddress={onOpenAddress}
                                    />
                                </dd>
                            </div>
                            <div>
                                <dt>{channel.capability ? 'expiry' : 'pending expiry'}</dt>
                                <dd>
                                    block {channel.expiry}
                                    {expiryDetail && ` · ${expiryDetail}`}
                                </dd>
                            </div>
                        </dl>
                    )}
                </div>
            )}

            <div className="paid-stream__controls">
                <div className="paid-stream__primary-controls">
                    {phase === 'idle' && (
                        <button
                            className="action-button action-button--primary"
                            disabled={!advertisement}
                            onClick={() => void startSession()}
                            type="button"
                        >
                            {channel ? 'retry opening' : 'open channel'}
                        </button>
                    )}
                    {phase === 'opening' && (
                        <button className="action-button action-button--primary" disabled type="button">
                            opening…
                        </button>
                    )}
                    {(phase === 'ready' || (phase === 'ended' && !terminalStream)) && channel && (
                        <button
                            className={`action-button ${
                                text
                                    ? 'action-button--emphasis'
                                    : 'action-button--primary'
                            }`}
                            onClick={startStream}
                            type="button"
                        >
                            {text ? 'resume stream' : 'start stream'}
                        </button>
                    )}
                    {streaming && (
                        <button
                            className="action-button action-button--toggle"
                            onClick={stopStream}
                            type="button"
                        >
                            pause stream
                        </button>
                    )}
                    {phase === 'settled' && (
                        <button
                            className="action-button action-button--primary"
                            onClick={resetSession}
                            type="button"
                        >
                            new session
                        </button>
                    )}
                </div>
                <div className="paid-stream__secondary-controls">
                    {terminalStream && channel?.capability && (
                        <button
                            className="action-button action-button--emphasis"
                            onClick={() => void settle()}
                            type="button"
                        >
                            {endReason === 'channel_closed'
                                ? 'confirm settlement'
                                : 'settle on-chain'}
                        </button>
                    )}
                    {(streaming ||
                        phase === 'ready' ||
                        (phase === 'ended' && endReason === 'payment_timeout')) && (
                        <button
                            className={`action-button ${
                                paying ? 'action-button--toggle' : 'action-button--emphasis'
                            }`}
                            onClick={() => setPayingMode(!paying)}
                            type="button"
                        >
                            {paying ? 'pause auto-pay' : 'resume auto-pay'}
                        </button>
                    )}
                    {channel?.capability &&
                        !terminalStream &&
                        phase !== 'opening' &&
                        phase !== 'settling' &&
                        phase !== 'settled' && (
                            <button
                                className="action-button action-button--secondary"
                                onClick={() => void settle()}
                                type="button"
                            >
                                end & settle
                            </button>
                        )}
                    {channel &&
                        reclaimable &&
                        (phase === 'idle' || phase === 'ready' || phase === 'ended') && (
                        <button
                            className="action-button action-button--danger"
                            disabled={payerMismatch}
                            onClick={() => void reclaimDeposit()}
                            title={
                                payerMismatch
                                    ? 'sign in with the wallet that opened this channel'
                                    : 'reclaim the escrow after the channel expiry (the exit when settle is refused)'
                            }
                            type="button"
                        >
                            reclaim deposit
                        </button>
                    )}
                </div>
            </div>

            {note && (
                <p className="paid-stream__note" role="status">
                    {note}
                </p>
            )}
            {paymentNotice && (
                <p className="paid-stream__note" role="status">
                    {paymentNotice}
                </p>
            )}
            {endMessage && (
                <p className="paid-stream__note" role="status">
                    {endMessage}
                </p>
            )}

            {showStreamOutput && (
                <section className="paid-stream__status" aria-label="stream status">
                    <div className="paid-stream__meter-label">
                        <span>stream progress</span>
                        <strong>
                            {deliveredTokens.toString()} /{' '}
                            {advertisement?.streamTokens.toString() ?? '—'} tokens
                        </strong>
                    </div>
                    <div className="paid-stream__meter-bar">
                        <div
                            className="paid-stream__meter-fill"
                            style={{ width: `${Math.min(100, Math.round(contentRatio * 100))}%` }}
                        />
                    </div>
                    <div className="paid-stream__status-meta">
                        <span>
                            paid <strong>{meter.paid.toString()}</strong>
                        </span>
                        <span className={paymentWarning ? 'paid-stream__unpaid--warning' : ''}>
                            unpaid <strong>{debt.toString()}</strong>
                            {paymentWarning && ` / ${debtLimit.toString()}`}
                        </span>
                        {voucherCount > 0 && (
                            <span>
                                {voucherCount} voucher{voucherCount === 1 ? '' : 's'} sent
                            </span>
                        )}
                    </div>
                </section>
            )}

            {showStreamOutput && (
                <pre className="paid-stream__text" ref={textRef}>
                    {text}
                    {streaming && <span className="paid-stream__cursor">▋</span>}
                </pre>
            )}
        </div>
    );
});

/// This page's address rendering: the shared button, abbreviated to fit the
/// facts grid.
function SessionAddress({
    hex,
    onOpenAddress,
}: {
    hex: string;
    onOpenAddress: (accountHex: string) => void;
}) {
    return <AddressValue plain value={hex} display={shortHex(hex)} onOpenAddress={onOpenAddress} />;
}

/// The phase a failed settlement action returns to: the phase it started
/// from ('ended' when it started mid-stream — the stream was just closed).
/// Landing anywhere else strands the user — notably in 'ended' from 'idle',
/// where the start button (the only path that registers a restored channel)
/// no longer renders.
function settlementOrigin(phase: Phase): Phase {
    return phase === 'streaming' ? 'ended' : phase;
}

/// The freshest of two optionally-known block heights.
function maxHeight(a: bigint | null, b: bigint | null): bigint | null {
    if (a === null) return b;
    if (b === null) return a;
    return a > b ? a : b;
}

async function channelMatchesPayer(record: ChannelRecord, payerHex: string): Promise<boolean> {
    const operator = parseAccountKeyHex(record.operatorHex);
    const derived = await channelAddress(
        parseAccountKeyHex(payerHex),
        operator,
        operator,
        fromHex(record.voucherPublicKeyHex),
        BigInt(record.openNonce),
    );
    return toHex(derived) === record.channelHex.toLowerCase();
}

function isChannelRecord(value: unknown): value is ChannelRecord {
    if (typeof value !== 'object' || value === null) return false;
    const record = value as Partial<ChannelRecord>;
    return (
        typeof record.channelHex === 'string' &&
        (record.payerHex === undefined || typeof record.payerHex === 'string') &&
        typeof record.openNonce === 'string' &&
        typeof record.deposit === 'string' &&
        typeof record.openTxDigestHex === 'string' &&
        typeof record.signedOpenTxHex === 'string' &&
        typeof record.operatorHex === 'string' &&
        typeof record.expiry === 'string' &&
        typeof record.voucherPublicKeyHex === 'string' &&
        typeof record.voucherKeyJwk === 'object' &&
        record.voucherKeyJwk !== null &&
        (record.capability === undefined || typeof record.capability === 'string')
    );
}

function readChannelRecord(): ChannelRecord | null {
    return readStoredJson(CHANNEL_STORAGE_KEY, isChannelRecord);
}

function persistChannel(record: ChannelRecord): void {
    localStorage.setItem(CHANNEL_STORAGE_KEY, JSON.stringify(record));
}

/// The record is the only copy of the signed open and the voucher key;
/// every deletion goes through here so the (few, safety-critical) flows
/// that may forget a channel are greppable in one place.
function clearChannelRecord(): void {
    localStorage.removeItem(CHANNEL_STORAGE_KEY);
}

function streamEndMessage(reason: StreamEnd['reason'] | null, paying: boolean): string {
    switch (reason) {
        case 'complete':
            return 'stream complete.';
        case 'payment_timeout':
            return paying
                ? 'payment timed out. retry the stream.'
                : 'payment timed out. resume auto-pay, then resume the stream.';
        case 'deposit_exhausted':
            return 'deposit used. settle the channel.';
        case 'channel_closed':
            return 'channel closed.';
        default:
            return '';
    }
}
