// The paid-stream demo view: an x402-style metered service driven end to end
// from the browser. The passkey wallet funds an ed25519 session key, the
// session key opens a payment channel to the operator (who is also the
// payee), and the operator's `/stream` endpoint then sells an essay token by
// token while this page signs vouchers to keep the debt under the advertised
// limit. Stop paying and the stream pauses, then hangs up — enforcement is
// the demo.
//
// The fund and open transactions are deliberately submitted sequentially
// (each awaited to finality): the transfer credits the session account that
// the OpenChannel debits, and same-block cross-lane writes to one account
// conflict — batching them would drop one.

import { memo, useEffect, useMemo, useRef, useState } from 'react';

import { AddressValue } from './AddressValue';
import {
    channelAddress,
    encodeSignedOpenChannelTransaction,
    encodeSignedTimeoutChannelTransaction,
    encodeTransactionBatch,
    fromHex,
    parseAccountKeyHex,
    toHex,
} from './codec';
import { fetchAccount, statusHasHeight, submitTransactions } from './mempool';
import {
    OperatorRequestError,
    fetchAdvertisement,
    openStream,
    postVoucher,
    registerChannel,
    settleChannel,
} from './operatorClient';
import {
    channelExpiry,
    nonceConsumed,
    voucherTopUp,
    type OperatorAdvertisement,
    type StreamEnd,
    type StreamMeter,
} from './paidStream';
import { loadOrCreateSessionKey, type SessionKey } from './sessionKey';
import { readStoredJson, shortHex, sleep } from './util';

/// Tokens of content a session's deposit buys (the essay is shorter, so a
/// paying session ends with `complete`, not `deposit_exhausted`).
const DEPOSIT_TOKENS = 600n;
/// How long to wait for the funding transfer to land in the session
/// account's committed balance.
const FUNDING_POLL_ATTEMPTS = 20;
const FUNDING_POLL_MS = 500;
/// Retry delay for a transiently failed voucher post — well inside the
/// operator's grace window, so a blip cannot kill a paying stream.
const VOUCHER_RETRY_MS = 1_000;
/// The page tracks one outstanding channel: the record lands here before the
/// open is submitted and stays until a close or a timeout reclaim resolves
/// the escrow — the only two ways a channel's funds move, so the record is
/// never deleted while they haven't.
const CHANNEL_STORAGE_KEY = 'constantinople.stream-channel.v1';

interface ChannelRecord {
    readonly channelHex: string;
    readonly openNonce: string;
    readonly deposit: string;
    readonly openTxDigestHex: string;
    /// The exact signed open transaction. Persisted before the first
    /// submission and resubmitted verbatim until it lands: the session key
    /// then signs exactly one transaction per nonce, which is what makes the
    /// nonce check in `confirmOpen` definitive.
    readonly signedOpenTxHex: string;
    /// The receiver/operator account and expiry the channel was opened with
    /// (a timeout reclaim must reconstruct the channel address from them).
    readonly operatorHex: string;
    readonly expiry: string;
}

type Phase =
    | 'unsupported'
    | 'idle'
    | 'opening'
    | 'ready'
    | 'streaming'
    | 'ended'
    | 'settling'
    | 'settled';

export interface PaidStreamPageProps {
    readonly operatorUrl: string;
    readonly mempoolUrl: string;
    readonly walletReady: boolean;
    readonly walletBalance: number | null;
    /// Transfers `amount` from the passkey wallet to the session account and
    /// resolves true once the transfer finalized.
    readonly onFundSession: (accountKeyHex: string, amount: bigint) => Promise<boolean>;
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
    onFundSession,
    onOpenWallet,
    onOpenAddress,
    onCopy,
}: PaidStreamPageProps) {
    const [phase, setPhase] = useState<Phase>('idle');
    const [note, setNote] = useState('');
    const [session, setSession] = useState<SessionKey | null>(null);
    const [sessionBalance, setSessionBalance] = useState<number | null>(null);
    const [advertisement, setAdvertisement] = useState<OperatorAdvertisement | null>(null);
    const [channel, setChannel] = useState<ChannelRecord | null>(() => readChannelRecord());
    const [text, setText] = useState('');
    const [meter, setMeter] = useState<StreamMeter>({ served: 0n, paid: 0n });
    const [paying, setPaying] = useState(true);
    // Signed cumulatives, newest first (strictly monotonic per session, so
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
    /// reset cannot write the old session's cumulative into the new one.
    const sessionGenerationRef = useRef(0);
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

    // Boot: restore/create the session key while the operator advertisement
    // fetch runs alongside. Key generation failing is the WebCrypto
    // ed25519-support probe.
    useEffect(() => {
        let cancelled = false;
        void (async () => {
            const advertisementPromise = fetchAdvertisement(operatorUrl);
            advertisementPromise.then(
                (ad) => {
                    if (!cancelled) setAdvertisement(ad);
                },
                (error) => {
                    if (!cancelled) setNote(`operator unreachable: ${String(error)}`);
                },
            );
            try {
                const key = await loadOrCreateSessionKey();
                if (!cancelled) setSession(key);
            } catch (error) {
                // Usually missing WebCrypto ed25519 support, but storage
                // being disabled lands here too — surface the real error.
                if (!cancelled) {
                    setNote(String(error));
                    setPhase('unsupported');
                }
            }
        })();
        return () => {
            cancelled = true;
        };
    }, [operatorUrl]);

    // Track the session account's committed balance. Paused while streaming:
    // vouchers are off-chain, so the balance cannot move until settlement.
    useEffect(() => {
        if (!session || phase === 'streaming') return;
        let cancelled = false;
        const poll = async () => {
            try {
                const view = await fetchAccount(mempoolUrl, toHex(session.publicKey));
                if (!cancelled) setSessionBalance(view?.balance ?? 0);
            } catch {
                // The relayer facade may not be up yet; keep polling.
            }
        };
        void poll();
        const interval = window.setInterval(() => void poll(), 2_000);
        return () => {
            cancelled = true;
            window.clearInterval(interval);
        };
    }, [session, mempoolUrl, phase]);

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
        if (!session || !advertisement || !channel || !channelKey) return;
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
                const signature = await session.signVoucher(channelKey, target);
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
                voucherInflightRef.current = false;
            }
        })();
    };

    /// Resubmits the persisted open verbatim and throws unless it landed.
    /// Verbatim resubmission is what makes the nonce check definitive: this
    /// is the only transaction the session key ever signed with `openNonce`,
    /// so the nonce being consumed proves this open consumed it — and the
    /// nonce being free proves the escrow does not exist yet. The record is
    /// therefore never discarded on an unconfirmed open; retrying is always
    /// safe and always converges. Idempotent and cheap, so every session
    /// start re-runs it instead of trusting persisted state.
    const confirmOpen = async (record: ChannelRecord, sessionPublicKeyHex: string) => {
        const status = await submitTransactions(
            mempoolUrl,
            encodeTransactionBatch([fromHex(record.signedOpenTxHex)]),
        );
        if (!statusHasHeight(status)) {
            const view = await fetchAccount(mempoolUrl, sessionPublicKeyHex);
            const consumed =
                view !== null &&
                nonceConsumed(
                    { base: BigInt(view.nonce.base), bitmap: BigInt(view.nonce.bitmap) },
                    BigInt(record.openNonce),
                );
            if (!consumed) {
                throw new Error(
                    `channel open was ${status.status} — start the session again to retry`,
                );
            }
        }
    };

    /// Fund the session account, open the channel, and register it.
    const startSession = async () => {
        if (!session) return;
        if (!walletReady) {
            setNote('sign in with the wallet first — it funds the session key');
            onOpenWallet();
            return;
        }
        setPhase('opening');
        setNote('');
        // Tracked outside the try so a failure never re-creates a record
        // the flow already persisted.
        let record = channel;
        try {
            // Fresh advertisement (the expiry derives from the operator's
            // current height), fetched alongside the session account view —
            // the two are independent.
            const sessionPublicKeyHex = toHex(session.publicKey);
            const [ad, initialView] = await Promise.all([
                fetchAdvertisement(operatorUrl),
                fetchAccount(mempoolUrl, sessionPublicKeyHex),
            ]);
            setAdvertisement(ad);
            const price = ad.pricePerToken > 0n ? ad.pricePerToken : 1n;
            const deposit = DEPOSIT_TOKENS * price;
            const operatorAccount = parseAccountKeyHex(ad.accountHex);

            if (!record) {
                // Step 1: the wallet funds the session account (sequential —
                // see the module comment on cross-lane conflicts).
                let view = initialView;
                let balance = BigInt(view?.balance ?? 0);
                if (balance < deposit) {
                    const needed = deposit - balance;
                    if (walletBalance === null || BigInt(walletBalance) < needed) {
                        throw new Error(
                            `wallet balance too low to fund the session (needs ${needed}); mint to the wallet first`,
                        );
                    }
                    setNote(`funding session account (${needed} from the wallet)…`);
                    if (!(await onFundSession(toHex(session.accountKey), needed))) {
                        throw new Error('funding transfer did not finalize');
                    }
                    for (let attempt = 0; balance < deposit; attempt++) {
                        if (attempt >= FUNDING_POLL_ATTEMPTS) {
                            throw new Error('funding transfer not visible in the session account yet; retry shortly');
                        }
                        await sleep(FUNDING_POLL_MS);
                        view = await fetchAccount(mempoolUrl, sessionPublicKeyHex);
                        balance = BigInt(view?.balance ?? 0);
                    }
                }

                // Step 2: the session key signs the channel open. The
                // operator is both the settling key and the payee (a
                // payee-run operator). The last fetched view's nonce is
                // current: the funding transfer is inbound and cannot
                // advance it.
                const openNonce = BigInt(view?.nonce.base ?? 0);
                const expiry = channelExpiry(ad);
                const encoded = await encodeSignedOpenChannelTransaction(
                    {
                        senderPublicKey: session.publicKey,
                        receiverAccountKey: operatorAccount,
                        operatorAccountKey: operatorAccount,
                        deposit,
                        expiry,
                        nonce: openNonce,
                    },
                    session.signTransaction,
                );
                const address = await channelAddress(
                    session.accountKey,
                    operatorAccount,
                    operatorAccount,
                    openNonce,
                );
                // Persisted BEFORE submission: if the response is lost after
                // the open finalized, this record is the only way back to
                // the escrow. `confirmOpen` below reconciles either way.
                record = {
                    channelHex: toHex(address),
                    openNonce: openNonce.toString(),
                    deposit: deposit.toString(),
                    openTxDigestHex: encoded.digestHex,
                    signedOpenTxHex: toHex(encoded.bytes),
                    operatorHex: ad.accountHex,
                    expiry: expiry.toString(),
                };
                persistChannel(record);
                setChannel(record);
            }

            // Step 3: submit the open (a first submission and a retry are
            // the same verbatim resubmission) until it is known finalized.
            setNote('opening the channel on-chain…');
            await confirmOpen(record, sessionPublicKeyHex);

            // Step 4: register with the operator (idempotent, retried
            // through indexer lag).
            setNote('registering the channel with the operator…');
            await registerChannel(operatorUrl, {
                channel: parseAccountKeyHex(record.channelHex),
                payerPublicKey: session.publicKey,
                openNonce: BigInt(record.openNonce),
                openTxDigestHex: record.openTxDigestHex,
            });
            setNote('channel registered — start the stream');
            setPhase('ready');
        } catch (error) {
            setNote(error instanceof Error ? error.message : String(error));
            // Every failure returns to 'idle': the start button is the
            // retry path — it skips funding when a record exists and re-runs
            // the idempotent confirm and registration steps.
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
        setPhase('settling');
        setNote('closing the channel on-chain…');
        try {
            const outcome = await settleChannel(operatorUrl, channelKey);
            setNote(
                outcome.settled
                    ? `settled: one close paid ${outcome.cumulative} for ${payments.length ? 'all the vouchers you watched' : 'the session'}`
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
            setPhase('ended');
        }
    };

    /// Reclaims an expired channel's escrow with a TimeoutChannel signed by
    /// the session key — the exit for a channel the operator will never
    /// close (its sweep ignores voucherless channels, and settle rejects
    /// them). The chain refuses the reclaim until the block height passes
    /// the channel's expiry, so the operator's advertised height gates the
    /// attempt with a useful message instead of a doomed submission.
    const reclaimDeposit = async () => {
        if (!session || !channel) return;
        closeStream();
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
            const view = await fetchAccount(mempoolUrl, toHex(session.publicKey));
            const operatorAccount = parseAccountKeyHex(channel.operatorHex);
            const encoded = await encodeSignedTimeoutChannelTransaction(
                {
                    senderPublicKey: session.publicKey,
                    receiverAccountKey: operatorAccount,
                    operatorAccountKey: operatorAccount,
                    openNonce: BigInt(channel.openNonce),
                    nonce: BigInt(view?.nonce.base ?? 0),
                },
                session.signTransaction,
            );
            const status = await submitTransactions(
                mempoolUrl,
                encodeTransactionBatch([encoded.bytes]),
            );
            if (!statusHasHeight(status)) {
                throw new Error(
                    `timeout reclaim was ${status.status} — the channel may already be closed`,
                );
            }
            localStorage.removeItem(CHANNEL_STORAGE_KEY);
            setChannel(null);
            setNote('deposit reclaimed — the escrow returned to the session account');
            setPhase('settled');
        } catch (error) {
            setNote(error instanceof Error ? error.message : String(error));
            setPhase('ended');
        }
    };

    /// Starts over after the previous channel resolved (settled close or
    /// timeout reclaim — the record is gone either way). Deliberately keeps
    /// the session key: the resolution refunds the deposit remainder to its
    /// account, so the balance carries into the next session (and the next
    /// open just uses the account's next nonce).
    const resetSession = () => {
        sessionGenerationRef.current += 1;
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
    if (phase === 'unsupported') {
        return (
            <div className="paid-stream">
                <p className="paid-stream__note">
                    could not create the session key ({note}) — typically the browser's WebCrypto
                    cannot generate ed25519 keys (needs Chrome 137+, Safari 17+, or Firefox 130+),
                    or storage is disabled.
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
                    through a payment channel. the chain sees two transactions — the open and the
                    close — no matter how many vouchers stream in between.
                </p>
            </div>

            <dl className="paid-stream__facts">
                <div>
                    <dt>session account</dt>
                    <dd>
                        {session ? (
                            <SessionAddress hex={toHex(session.accountKey)} onOpenAddress={onOpenAddress} />
                        ) : (
                            '…'
                        )}{' '}
                        <span className="paid-stream__fact-note">
                            balance {sessionBalance ?? '…'}
                        </span>
                    </dd>
                </div>
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
                        disabled={!session || !advertisement}
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
        typeof record.expiry === 'string'
    );
}

function readChannelRecord(): ChannelRecord | null {
    return readStoredJson(CHANNEL_STORAGE_KEY, isChannelRecord);
}

function persistChannel(record: ChannelRecord): void {
    localStorage.setItem(CHANNEL_STORAGE_KEY, JSON.stringify(record));
}

