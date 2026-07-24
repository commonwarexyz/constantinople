import { useEffect, useMemo, useRef, useState, type FormEvent } from 'react';
import {
    blocksUntilCommitteeLock,
    committeeChanges,
    committeeLockDetail,
    createCommitteeDraft,
    mergeCommitteeRoster,
    reconcileCommitteeDrafts,
    reconcileCommitteeSelection,
    validateCommitteeSelection,
    type CommitteeChange,
    type CommitteeSnapshot,
    type EligibleCommitteePeer,
    type FinalizedCommitteeOverlay,
} from './committee';

export default function CommitteePage({
    snapshot,
    loading,
    loadError,
    walletAccountKey,
    submitMessage,
    finalizedOverlays,
    isSubmitting,
    onRefresh,
    onOpenWallet,
    onSubmit,
}: {
    snapshot: CommitteeSnapshot | null;
    loading: boolean;
    loadError: string;
    walletAccountKey: string | null;
    submitMessage: string;
    finalizedOverlays: readonly FinalizedCommitteeOverlay[];
    isSubmitting: boolean;
    onRefresh: () => void;
    onOpenWallet: () => void;
    onSubmit: (changes: readonly CommitteeChange[]) => void;
}) {
    const [editor, setEditor] = useState<{
        drafts: EligibleCommitteePeer[];
        selected: Set<string>;
    }>({ drafts: [], selected: new Set() });
    const [draftPeer, setDraftPeer] = useState('');
    const [draftAddress, setDraftAddress] = useState('');
    const [draftError, setDraftError] = useState('');
    const previousSnapshotRef = useRef<CommitteeSnapshot | null>(null);
    const selectionBaseline = snapshot
        ? [
              snapshot.targetEpoch.toString(),
              snapshot.updatesOpen ? 'open' : 'closed',
              snapshot.lockHeight.toString(),
              snapshot.scheduled.join(','),
              snapshot.available.map(({ peer, address }) => `${peer}@${address}`).join(','),
          ].join(':')
        : '';

    useEffect(() => {
        const previousSnapshot = previousSnapshotRef.current;
        setEditor((current) => {
            const drafts = reconcileCommitteeDrafts(
                previousSnapshot,
                snapshot,
                current.drafts,
            );
            const previousEffective = previousSnapshot === null
                ? null
                : {
                      ...previousSnapshot,
                      available: mergeCommitteeRoster(
                          previousSnapshot.available,
                          current.drafts,
                      ),
                  };
            const nextEffective = snapshot === null
                ? null
                : {
                      ...snapshot,
                      available: mergeCommitteeRoster(snapshot.available, drafts),
                  };
            return {
                drafts,
                selected: reconcileCommitteeSelection(
                    previousEffective,
                    nextEffective,
                    current.selected,
                ),
            };
        });
        setDraftError('');
        previousSnapshotRef.current = snapshot;
    }, [selectionBaseline]);

    const effectiveSnapshot = useMemo(
        () => snapshot === null
            ? null
            : {
                  ...snapshot,
                  available: mergeCommitteeRoster(snapshot.available, editor.drafts),
              },
        [snapshot, editor.drafts],
    );
    const selectionError = validateCommitteeSelection(editor.selected);
    const changes = useMemo(
        () =>
            effectiveSnapshot?.updatesOpen && selectionError === null
                ? committeeChanges(effectiveSnapshot, editor.selected)
                : [],
        [effectiveSnapshot, editor.selected, selectionError],
    );

    if (snapshot === null) {
        return (
            <section className="committee-page" aria-label="committee controls">
                <div className="committee-page__empty">
                    <span>{loading ? 'loading committee state' : loadError || 'committee state unavailable'}</span>
                    {!loading && <button type="button" onClick={onRefresh}>↻ retry</button>}
                </div>
            </section>
        );
    }

    const current = new Set(snapshot.current);
    const next = new Set(snapshot.next);
    const scheduled = new Set(snapshot.scheduled);
    const awaitingByPeer = new Map<string, CommitteeChange>();
    for (const overlay of finalizedOverlays) {
        for (const change of overlay.changes) awaitingByPeer.set(change.peer, change);
    }
    const latestOverlay = finalizedOverlays.at(-1) ?? null;
    const indexedBlockLag = latestOverlay === null || snapshot.height >= latestOverlay.finalizedHeight
        ? 0n
        : latestOverlay.finalizedHeight - snapshot.height;
    const roster = effectiveSnapshot?.available ?? snapshot.available;
    const visibleSelection = snapshot.updatesOpen ? editor.selected : scheduled;
    const blockDistance = blocksUntilCommitteeLock(snapshot);
    const canSubmit =
        snapshot.updatesOpen &&
        changes.length > 0 &&
        selectionError === null &&
        !isSubmitting;

    const togglePeer = (peer: string) => {
        setEditor((previous) => {
            const next = new Set(previous.selected);
            if (next.has(peer)) next.delete(peer);
            else next.add(peer);
            return { ...previous, selected: next };
        });
    };

    const addDraft = (event: FormEvent) => {
        event.preventDefault();
        try {
            const draft = createCommitteeDraft(roster, draftPeer, draftAddress);
            setEditor((previous) => ({
                drafts: [...previous.drafts, draft],
                selected: new Set([...previous.selected, draft.peer]),
            }));
            setDraftPeer('');
            setDraftAddress('');
            setDraftError('');
        } catch (error) {
            setDraftError(error instanceof Error ? error.message : String(error));
        }
    };

    const discardDraft = (peer: string) => {
        setEditor((previous) => {
            const selected = new Set(previous.selected);
            selected.delete(peer);
            return {
                drafts: previous.drafts.filter((draft) => draft.peer !== peer),
                selected,
            };
        });
    };

    return (
        <section
            className="committee-page"
            aria-labelledby="committee-heading"
            aria-busy={loading || isSubmitting}
        >
            <header className="committee-hero">
                <div className="committee-hero__title">
                    <div className="committee-page__kicker">
                        <span aria-hidden="true">///</span> consensus roster
                    </div>
                    <h2 id="committee-heading">committee</h2>
                </div>
                <div className={snapshot.updatesOpen ? 'committee-lock committee-lock--open' : 'committee-lock committee-lock--closed'}>
                    <i aria-hidden="true" />
                    <div>
                        <strong>{snapshot.updatesOpen ? 'submissions open' : 'submissions locked'}</strong>
                        <span>{committeeLockDetail(snapshot)}</span>
                    </div>
                </div>
            </header>

            <div className="committee-summary">
                <CommitteeDatum label="finalized height" value={snapshot.height.toString()} />
                <CommitteeDatum label="current epoch" value={snapshot.epoch.toString()} />
                <CommitteeDatum label="selected / eligible" value={`${visibleSelection.size}/${roster.length}`} />
                <CommitteeDatum label="blocks to lock" value={blockDistance.toString()} />
            </div>

            <section className="committee-lifecycle" aria-labelledby="committee-lifecycle-heading">
                <div className="committee-section-heading">
                    <h3 id="committee-lifecycle-heading">epoch pipeline</h3>
                    <span>
                        active → locked → {snapshot.updatesOpen ? 'editable' : 'scheduled'}
                    </span>
                </div>
                <div className="committee-lifecycle__track" role="group" aria-label="committee lifecycle">
                    <CommitteeStage
                        stage="active now"
                        epoch={snapshot.epoch}
                        detail={`${snapshot.current.length} validators`}
                        tone="active"
                    />
                    <CommitteeStage
                        stage="locked next"
                        epoch={snapshot.epoch + 1n}
                        detail={`${snapshot.next.length} validators`}
                        tone="queued"
                    />
                    <CommitteeStage
                        stage={snapshot.updatesOpen ? 'editing' : 'scheduled'}
                        epoch={snapshot.targetEpoch}
                        detail={`${visibleSelection.size} validators`}
                        tone={snapshot.updatesOpen ? 'editing' : 'locked'}
                    />
                </div>
            </section>

            <section className="committee-roster" aria-labelledby="committee-roster-heading">
                <div className="committee-section-heading committee-roster__heading">
                    <h3 id="committee-roster-heading">validator roster</h3>
                    <span>{roster.length} eligible{editor.drafts.length > 0 ? ` · ${editor.drafts.length} local` : ''}</span>
                </div>
                <form className="committee-add" onSubmit={addDraft}>
                    <div className="committee-add__prompt" aria-hidden="true">$</div>
                    <label>
                        <span>public key</span>
                        <input
                            value={draftPeer}
                            onChange={(event) => setDraftPeer(event.target.value)}
                            placeholder="32-byte Ed25519 hex"
                            spellCheck={false}
                            autoComplete="off"
                            disabled={!snapshot.updatesOpen || isSubmitting}
                        />
                    </label>
                    <label>
                        <span>network address</span>
                        <input
                            value={draftAddress}
                            onChange={(event) => setDraftAddress(event.target.value)}
                            placeholder="203.0.113.7:9000 or [2001:db8::7]:9000"
                            spellCheck={false}
                            autoComplete="off"
                            disabled={!snapshot.updatesOpen || isSubmitting}
                        />
                    </label>
                    <button
                        type="submit"
                        disabled={!snapshot.updatesOpen || isSubmitting || !draftPeer.trim() || !draftAddress.trim()}
                    >
                        + add validator
                    </button>
                    {draftError && <span className="committee-add__error" role="alert">{draftError}</span>}
                </form>
                <div className="committee-table" role="table" aria-label="committee peers">
                    <div className="committee-row committee-row--head" role="row">
                        <span role="columnheader" aria-label="selection" />
                        <span role="columnheader">validator</span>
                        <span role="columnheader">now</span>
                        <span role="columnheader">next</span>
                        <span role="columnheader">{snapshot.updatesOpen ? 'editing' : 'scheduled'}</span>
                    </div>
                    {roster.map((candidate) => {
                        const isDraft = editor.drafts.some(({ peer }) => peer === candidate.peer);
                        const isCurrent = current.has(candidate.peer);
                        const isNext = next.has(candidate.peer);
                        const isSelected = visibleSelection.has(candidate.peer);
                        const isScheduled = scheduled.has(candidate.peer);
                        const awaiting = awaitingByPeer.get(candidate.peer) ?? null;
                        const pending = isScheduled === isSelected
                            ? null
                            : isSelected
                                ? 'addition'
                                : 'removal';
                        return (
                            <label
                                className={`committee-row${pending ? ` committee-row--pending-${pending}` : ''}${awaiting ? ` committee-row--indexing-${awaiting.address === null ? 'removal' : 'addition'}` : ''}${!snapshot.updatesOpen || isSubmitting ? ' committee-row--disabled' : ''}`}
                                role="row"
                                key={candidate.peer}
                            >
                                <span className="committee-row__select" role="cell">
                                    <input
                                        type="checkbox"
                                        checked={isSelected}
                                        disabled={!snapshot.updatesOpen || isSubmitting}
                                        onChange={() => togglePeer(candidate.peer)}
                                        aria-label={`${isSelected ? 'remove' : 'add'} ${candidate.peer} ${isSelected ? 'from' : 'to'} the epoch ${snapshot.targetEpoch.toString()} committee`}
                                    />
                                </span>
                                <span className="committee-row__identity" role="cell">
                                    <strong title={candidate.peer}>{candidate.peer}</strong>
                                    <span className="committee-row__endpoint">
                                        <small title={candidate.address}>{candidate.address}</small>
                                        {isDraft && (
                                            <button
                                                type="button"
                                                className="committee-row__discard"
                                                disabled={isSubmitting}
                                                onClick={(event) => {
                                                    event.preventDefault();
                                                    event.stopPropagation();
                                                    discardDraft(candidate.peer);
                                                }}
                                                aria-label={`discard local validator ${candidate.peer}`}
                                            >
                                                × discard
                                            </button>
                                        )}
                                    </span>
                                </span>
                                <MembershipBadge
                                    phase="now"
                                    label={isCurrent ? 'active' : 'standby'}
                                    tone={isCurrent ? 'active' : 'muted'}
                                />
                                <MembershipBadge
                                    phase="next"
                                    label={isNext ? 'included' : 'excluded'}
                                    tone={isNext ? 'queued' : 'muted'}
                                />
                                <MembershipBadge
                                    phase={snapshot.updatesOpen ? 'editing' : 'scheduled'}
                                    label={pending === 'addition'
                                        ? '+ add'
                                        : pending === 'removal'
                                            ? '− remove'
                                            : awaiting?.address === null
                                                ? '✓ removal finalized'
                                                : awaiting
                                                    ? '✓ addition finalized'
                                            : isSelected
                                                ? 'selected'
                                                : 'excluded'}
                                    tone={pending ?? (awaiting ? 'queued' : isSelected ? 'editing' : 'muted')}
                                />
                            </label>
                        );
                    })}
                </div>
            </section>

            <div className={`committee-actions${changes.length > 0 ? ' committee-actions--pending' : ''}${latestOverlay ? ' committee-actions--indexing' : ''}`}>
                <div className="committee-actions__summary" aria-live="polite">
                    <i aria-hidden="true">›</i>
                    <div>
                        <strong>
                            {changes.length > 0
                                ? `${changes.length} pending ${changes.length === 1 ? 'change' : 'changes'}`
                                : latestOverlay
                                    ? `${awaitingByPeer.size} finalized ${awaitingByPeer.size === 1 ? 'change' : 'changes'} · awaiting indexer`
                                    : '0 pending changes'}
                        </strong>
                        {changes.length > 0 && (
                            <span>
                                {changes.map((change) => `${change.address === null ? 'remove' : 'add'} ${shortPeer(change.peer)}`).join(' · ')}
                            </span>
                        )}
                        {latestOverlay && (
                            <span className="committee-actions__indexing">
                                epoch {latestOverlay.targetEpoch.toString()} · finalized at {latestOverlay.finalizedHeight.toString()} · {indexedBlockLag > 0n
                                    ? `indexer is ${indexedBlockLag.toString()} blocks behind this update`
                                    : 'waiting for indexed committee rows'}
                            </span>
                        )}
                        {selectionError && <span className="committee-actions__error">{selectionError}</span>}
                        {loadError && <span className="committee-actions__error">refresh: {loadError}</span>}
                        {submitMessage && <span className="committee-actions__message">{submitMessage}</span>}
                    </div>
                </div>
                <div className="committee-actions__buttons">
                    <button type="button" className="committee-button committee-button--secondary" disabled={loading || isSubmitting} onClick={onRefresh}>↻ refresh</button>
                    <button
                        type="button"
                        className="committee-button committee-button--primary"
                        disabled={!canSubmit}
                        onClick={() => walletAccountKey ? onSubmit(changes) : onOpenWallet()}
                    >
                        {isSubmitting
                            ? '… signing / submitting'
                            : walletAccountKey
                                ? `◆ sign & submit ${changes.length} ${changes.length === 1 ? 'update' : 'updates'}`
                                : '◇ open wallet to sign'}
                    </button>
                </div>
            </div>
        </section>
    );
}

function CommitteeDatum({ label, value }: { label: string; value: string }) {
    return (
        <div className="committee-summary__datum">
            <strong>{value}</strong>
            <span>{label}</span>
        </div>
    );
}

function CommitteeStage({
    stage,
    epoch,
    detail,
    tone,
}: {
    stage: string;
    epoch: bigint;
    detail: string;
    tone: 'active' | 'queued' | 'editing' | 'locked';
}) {
    return (
        <div className={`committee-lifecycle__stage committee-lifecycle__stage--${tone}`}>
            <i className="committee-lifecycle__marker" aria-hidden="true" />
            <span>{stage}</span>
            <strong><small>epoch</small> {epoch.toString()}</strong>
            <small>{detail}</small>
        </div>
    );
}

function MembershipBadge({
    phase,
    label,
    tone,
}: {
    phase: string;
    label: string;
    tone: 'active' | 'queued' | 'editing' | 'muted' | 'addition' | 'removal';
}) {
    return (
        <span
            className={`committee-membership committee-membership--${tone}`}
            data-phase={phase}
            role="cell"
        >
            <span>
                <i aria-hidden="true" />
                {label}
            </span>
        </span>
    );
}

function shortPeer(peer: string): string {
    return peer.length <= 20 ? peer : `${peer.slice(0, 12)}…${peer.slice(-8)}`;
}
