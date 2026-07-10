// The paid-stream demo view: an x402-style metered service driven end to end
// from the browser. The passkey wallet signs one OpenChannel that escrows the
// deposit and delegates voucher signing to a fresh per-channel ed25519 key;
// that key then pays the operator's `/stream` endpoint token by token while
// the essay renders. Stop paying and the stream pauses, then hangs up —
// enforcement is the demo. The close (or a post-expiry timeout reclaim)
// refunds the deposit remainder straight back to the wallet.

import { memo, useEffect, useMemo, useRef, useState } from 'react';

import { AddressValue } from './AddressValue';
import { encodeTransactionBatch, fromHex, parseAccountKeyHex, toHex } from './codec';
import { statusHasHeight, submitTransactions, type TxStatus } from './mempool';
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
    voucherTopUp,
    type OperatorAdvertisement,
    type StreamEnd,
    type StreamMeter,
} from './paidStream';
import { createVoucherKey, importVoucherKey, type VoucherKey } from './voucherKey';
import { readStoredJson, shortHex } from './util';

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
}

/// What the wallet hands back for persistence after signing the open,
/// before submitting it.
export interface PendingOpen {
    readonly channelHex: string;
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
    readonly walletReady: boolean;
    readonly walletBalance: number | null;
    /// Signs and submits the OpenChannel with the passkey (one user ceremony
    /// per channel — the delegation the voucher key operates under).
    readonly onOpenChannel: (request: OpenStreamChannelRequest) => Promise<TxStatus | null>;
    /// Signs and submits a post-expiry TimeoutChannel with the passkey.
    readonly onReclaimChannel: (request: ReclaimStreamChannelRequest) => Promise<TxStatus | null>;
    readonly onOpenWallet: () => void;
    readonly onOpenAddress: (accountHex: string) => void;
    readonly onCopy: (value: string) => void;
}

/// Memoized: App re-renders on every live-dashboard tick, and none of that
/// concerns this page — its props are primitives and stable callbacks.
export const PaidStreamPage = memo(function PaidStreamPage({
    operatorUrl,
    mempoolUrl,
    walletReady,
    walletBalance,
    onOpenChannel,
    onReclaimChannel,
    onOpenWallet,
    onOpenAddress,
    onCopy,
}: PaidStreamPageProps) {
    const [phase, setPhase] = useState<Phase>('idle');
    const [note, setNote] = useState('');
    const [advertisement, setAdvertisement] = useState<OperatorAdvertisement | null>(null);
    const [channel, setChannel] = useState<ChannelRecord | null>(() => readChannelRecord());
    const [text, setText] = useState('');
    const [meter, setMeter] = useState<StreamMeter>({ served: 0n, paid: 0n });
    const [paying, setPaying] = useState(true);
    // Signed cumulatives, newest first (strictly monotonic per channel, so
    // the values key the log rows).
    const [payments, setPayments] = useState<bigint[]>([]);
    const [endReason, setEndReason] = useState<StreamEnd['reason'] | null>(null);

    const payingRef = useRef(true);
    const voucherInflightRef = useRef(false);
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
            (error) => {
                if (!cancelled) setNote(`operator unreachable: ${String(error)}`);
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
                if (!cancelled) setNote(`stored voucher key failed to import: ${String(error)}`);
            }
        })();
        return () => {
            cancelled = true;
        };
    }, [operatorUrl]);

    /// Closes a live stream, if any. Nulling the ref matters: the voucher
    /// retry timer reads `closeStreamRef.current !== null` as "stream is
    /// live".
    const closeStream = () => {
        closeStreamRef.current?.();
        closeStreamRef.current = null;
    };

    // Close a live stream when the view unmounts.
    useEffect(() => () => closeStream(), []);

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

    /// Signs and posts a voucher whenever the meter (read from `meterRef`,
    /// which every stream event updates first) says one is due. Called from
    /// every stream event; a ref guards against overlapping posts.
    const maybePay = () => {
        if (!payingRef.current || voucherInflightRef.current) return;
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
        voucherInflightRef.current = true;
        const generation = sessionGenerationRef.current;
        void (async () => {
            try {
                const signature = await voucherKey.signVoucher(channelKey, target);
                await postVoucher(operatorUrl, { channel: channelKey, cumulative: target, signature });
                if (generation !== sessionGenerationRef.current) return;
                lastSignedRef.current = target;
                setPayments((current) => [target, ...current].slice(0, 8));
            } catch (error) {
                if (generation !== sessionGenerationRef.current) return;
                if (error instanceof OperatorRequestError && !error.transient) {
                    deadTargetRef.current = target;
                    setNote(`voucher rejected: ${error.message}`);
                    return;
                }
                // The operator announces a pause only once per pause, so a
                // transiently failed post must retry on its own — no further
                // SSE event may arrive to re-trigger payment before the
                // grace window expires.
                setNote(`voucher failed: ${String(error)} — retrying`);
                window.setTimeout(() => {
                    if (closeStreamRef.current !== null) maybePay();
                }, VOUCHER_RETRY_MS);
            } finally {
                // A post stalled across a reset must not clear the NEW
                // session's inflight flag out from under it.
                if (generation === sessionGenerationRef.current) {
                    voucherInflightRef.current = false;
                }
            }
        })();
    };

    /// Resubmits the persisted open verbatim. Advisory rather than
    /// authoritative: the registration that follows verifies the open by
    /// digest against the chain, so an unresolved status here just falls
    /// through. (Known demo edge: if the open's response was lost AND the
    /// wallet reused the rolled-back nonce on another transaction before a
    /// retry, this open can never land and registration will keep answering
    /// 503 — recover by clearing the stream channel from localStorage.)
    // (A duplicate of an already-finalized open reports dropped; the
    // registration that follows is the check that actually decides.)
    const resubmitOpen = async (record: ChannelRecord) => {
        await submitTransactions(
            mempoolUrl,
            encodeTransactionBatch([fromHex(record.signedOpenTxHex)]),
        );
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
                await onOpenChannel({
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
                if (!record) {
                    throw new Error('channel open was not signed');
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
                await resubmitOpen(record);
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
            await registerChannel(operatorUrl, {
                openTxDigestHex: record.openTxDigestHex,
                zeroVoucherSignature,
            });
            setNote('channel registered — start the stream');
            setPhase('ready');
        } catch (error) {
            setNote(error instanceof Error ? error.message : String(error));
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
        if (!channelKey) return;
        closeStream();
        setEndReason(null);
        setNote('');
        setPhase('streaming');
        closeStreamRef.current = openStream(operatorUrl, channelKey, {
            onChunk: (chunk) => {
                setText((current) => current + chunk.text);
                updateMeter(chunk);
                maybePay();
            },
            onPaymentRequired: (paused) => {
                updateMeter(paused);
                setNote('debt limit reached — stream paused until a voucher lands');
                maybePay();
            },
            onEnd: (end) => {
                closeStreamRef.current = null;
                updateMeter(end);
                setEndReason(end.reason);
                setNote('');
                setPhase('ended');
            },
            onError: (message) => {
                closeStreamRef.current = null;
                setNote(message);
                setPhase('ready');
            },
        });
    };

    const stopStream = () => {
        closeStream();
        setPhase('ready');
    };

    const settle = async () => {
        if (!channelKey) return;
        closeStream();
        // A failure returns to the phase the action started from ('ended'
        // when it started mid-stream: the stream was just closed). Landing
        // anywhere else strands the user — notably in 'ended' from 'idle',
        // where the start button (the only path that registers a restored
        // channel) no longer renders.
        const origin: Phase = phase === 'streaming' ? 'ended' : phase;
        setPhase('settling');
        setNote('closing the channel on-chain…');
        try {
            const outcome = await settleChannel(operatorUrl, channelKey);
            setNote(
                outcome.settled
                    ? `settled: one close paid ${outcome.cumulative} for ${payments.length ? 'all the vouchers you watched' : 'the session'} — the remainder refunded to the wallet`
                    : 'close abandoned — the channel expired first',
            );
            // Settled is the one outcome that may forget the channel: the
            // close resolved the escrow, so there is nothing left to
            // reclaim.
            localStorage.removeItem(CHANNEL_STORAGE_KEY);
            setChannel(null);
            setPhase('settled');
        } catch (error) {
            setNote(`settlement failed: ${String(error)}`);
            setPhase(origin);
        }
    };

    /// Reclaims an expired channel's escrow with a TimeoutChannel signed by
    /// the wallet — the exit for a channel the operator will never close
    /// (e.g. one whose registration never completed). The chain refuses the
    /// reclaim until the block height passes the channel's expiry, so the
    /// operator's advertised height gates the attempt with a useful message
    /// instead of a doomed submission.
    const reclaimDeposit = async () => {
        if (!channel) return;
        closeStream();
        // See `settle`: failure must return whence it came.
        const origin: Phase = phase === 'streaming' ? 'ended' : phase;
        setPhase('settling');
        setNote('reclaiming the deposit…');
        try {
            const ad = await fetchAdvertisement(operatorUrl);
            const expiry = BigInt(channel.expiry);
            if (ad.height <= expiry) {
                throw new Error(
                    `channel not expired yet — reclaimable after block ${expiry} (chain is at ${ad.height})`,
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
                throw new Error(
                    `timeout reclaim was ${status?.status ?? 'not signed'} — the channel may already be closed`,
                );
            }
            localStorage.removeItem(CHANNEL_STORAGE_KEY);
            setChannel(null);
            setNote('deposit reclaimed — the escrow returned to the wallet');
            setPhase('settled');
        } catch (error) {
            setNote(error instanceof Error ? error.message : String(error));
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
        voucherInflightRef.current = false;
        setText('');
        updateMeter({ served: 0n, paid: 0n });
        setPayments([]);
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
                <p className="paid-stream__note">
                    no operator configured — set VITE_OPERATOR_URL (the local deploy does this
                    automatically when the indexer and relayer run).
                </p>
            </div>
        );
    }

    const debtLimit = advertisement?.debtLimit ?? 0n;
    const debt = meter.served > meter.paid ? meter.served - meter.paid : 0n;
    const debtRatio = debtLimit > 0n ? Number(debt) / Number(debtLimit) : 0;
    const streaming = phase === 'streaming';

    return (
        <div className="paid-stream">
            <div className="paid-stream__intro">
                <p>
                    an x402-style metered service: the operator sells an essay token by token, paid
                    through a payment channel. the wallet signs one open delegating payment to a
                    disposable voucher key — the chain sees two transactions (open and close) no
                    matter how many vouchers stream in between.
                </p>
            </div>

            <dl className="paid-stream__facts">
                <div>
                    <dt>channel</dt>
                    <dd>
                        {channel ? (
                            <SessionAddress hex={channel.channelHex} onOpenAddress={onOpenAddress} />
                        ) : (
                            'none yet'
                        )}
                        {channel && (
                            <span className="paid-stream__fact-note"> deposit {channel.deposit}</span>
                        )}
                    </dd>
                </div>
                <div>
                    <dt>voucher key</dt>
                    <dd>
                        {channel ? (
                            <span title={channel.voucherPublicKeyHex}>
                                {shortHex(channel.voucherPublicKeyHex)}
                            </span>
                        ) : (
                            'created at open'
                        )}
                        {channel && (
                            <span className="paid-stream__fact-note"> signs vouchers only</span>
                        )}
                    </dd>
                </div>
                <div>
                    <dt>operator</dt>
                    <dd>
                        {advertisement ? (
                            <>
                                <SessionAddress
                                    hex={advertisement.accountHex}
                                    onOpenAddress={onOpenAddress}
                                />{' '}
                                <span className="paid-stream__fact-note">
                                    {advertisement.pricePerToken.toString()}/token, credit window{' '}
                                    {advertisement.debtLimit.toString()}
                                </span>
                            </>
                        ) : (
                            'unreachable'
                        )}
                    </dd>
                </div>
            </dl>

            <div className="paid-stream__controls">
                {phase === 'idle' && (
                    <button
                        className="transfer__submit"
                        disabled={!advertisement}
                        onClick={() => void startSession()}
                        type="button"
                    >
                        start session
                    </button>
                )}
                {phase === 'opening' && (
                    <button className="transfer__submit" disabled type="button">
                        opening…
                    </button>
                )}
                {(phase === 'ready' || phase === 'ended') && channel && (
                    <button className="transfer__submit" onClick={startStream} type="button">
                        {text ? 'resume stream' : 'start stream'}
                    </button>
                )}
                {streaming && (
                    <button className="transfer__submit" onClick={stopStream} type="button">
                        stop stream
                    </button>
                )}
                {(streaming || phase === 'ready') && (
                    <button
                        className="transfer__submit"
                        onClick={() => setPayingMode(!paying)}
                        type="button"
                    >
                        {paying ? 'stop paying' : 'resume paying'}
                    </button>
                )}
                {channel && phase !== 'opening' && phase !== 'settling' && phase !== 'settled' && (
                    <button className="transfer__submit" onClick={() => void settle()} type="button">
                        settle on-chain
                    </button>
                )}
                {channel && (phase === 'idle' || phase === 'ready' || phase === 'ended') && (
                    <button
                        className="transfer__submit"
                        onClick={() => void reclaimDeposit()}
                        title="reclaim the escrow after the channel expiry (the exit when settle is refused)"
                        type="button"
                    >
                        reclaim deposit
                    </button>
                )}
                {phase === 'settled' && (
                    <button className="transfer__submit" onClick={resetSession} type="button">
                        new session
                    </button>
                )}
            </div>

            {note && <p className="paid-stream__note">{note}</p>}
            {endReason && (
                <p className="paid-stream__note">stream ended: {endReason.replace('_', ' ')}</p>
            )}

            <div className="paid-stream__meter" aria-label="stream payment meter">
                <span>served {meter.served.toString()}</span>
                <span>paid {meter.paid.toString()}</span>
                <span>
                    debt {debt.toString()}/{debtLimit.toString()}
                </span>
                <div className="paid-stream__meter-bar">
                    <div
                        className={`paid-stream__meter-fill${debtRatio >= 1 ? ' paid-stream__meter-fill--full' : ''}`}
                        style={{ width: `${Math.min(100, Math.round(debtRatio * 100))}%` }}
                    />
                </div>
            </div>

            <div className="paid-stream__panes">
                <pre className="paid-stream__text" ref={textRef}>
                    {text}
                    {streaming && <span className="paid-stream__cursor">▋</span>}
                </pre>
                <div className="paid-stream__payments">
                    <h3>vouchers (off-chain)</h3>
                    {payments.length === 0 ? (
                        <p className="paid-stream__fact-note">none yet</p>
                    ) : (
                        <ul>
                            {payments.map((cumulative) => (
                                <li key={cumulative.toString()}>
                                    <button
                                        className="copyable copyable--plain"
                                        onClick={() => onCopy(cumulative.toString())}
                                        title="copy"
                                        type="button"
                                    >
                                        cumulative {cumulative.toString()}
                                    </button>
                                </li>
                            ))}
                        </ul>
                    )}
                </div>
            </div>
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

function isChannelRecord(value: unknown): value is ChannelRecord {
    if (typeof value !== 'object' || value === null) return false;
    const record = value as Partial<ChannelRecord>;
    return (
        typeof record.channelHex === 'string' &&
        typeof record.openNonce === 'string' &&
        typeof record.deposit === 'string' &&
        typeof record.openTxDigestHex === 'string' &&
        typeof record.signedOpenTxHex === 'string' &&
        typeof record.operatorHex === 'string' &&
        typeof record.expiry === 'string' &&
        typeof record.voucherPublicKeyHex === 'string' &&
        typeof record.voucherKeyJwk === 'object' &&
        record.voucherKeyJwk !== null
    );
}

function readChannelRecord(): ChannelRecord | null {
    return readStoredJson(CHANNEL_STORAGE_KEY, isChannelRecord);
}

function persistChannel(record: ChannelRecord): void {
    localStorage.setItem(CHANNEL_STORAGE_KEY, JSON.stringify(record));
}
