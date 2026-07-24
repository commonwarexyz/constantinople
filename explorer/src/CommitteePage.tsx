import { useEffect, useMemo, useRef, useState } from 'react';
import {
    blocksUntilCommitteeLock,
    committeeChanges,
    committeeLockDetail,
    reconcileCommitteeSelection,
    validateCommitteeSelection,
    type CommitteeChange,
    type CommitteeSnapshot,
} from './committee';

export default function CommitteePage({
    snapshot,
    loading,
    loadError,
    walletAccountKey,
    submitMessage,
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
    isSubmitting: boolean;
    onRefresh: () => void;
    onOpenWallet: () => void;
    onSubmit: (changes: readonly CommitteeChange[]) => void;
}) {
    const [selected, setSelected] = useState<Set<string>>(new Set());
    const previousSnapshotRef = useRef<CommitteeSnapshot | null>(null);
    const selectionBaseline = snapshot
        ? [
              snapshot.targetEpoch.toString(),
              snapshot.updatesOpen ? 'open' : 'closed',
              snapshot.scheduled.join(','),
              snapshot.available.map(({ peer }) => peer).join(','),
          ].join(':')
        : '';

    useEffect(() => {
        const previousSnapshot = previousSnapshotRef.current;
        setSelected((current) =>
            reconcileCommitteeSelection(previousSnapshot, snapshot, current),
        );
        previousSnapshotRef.current = snapshot;
    }, [selectionBaseline]);

    const selectionError = validateCommitteeSelection(selected);
    const changes = useMemo(
        () =>
            snapshot?.updatesOpen && selectionError === null
                ? committeeChanges(snapshot, selected)
                : [],
        [snapshot, selected, selectionError],
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
    const visibleSelection = snapshot.updatesOpen ? selected : scheduled;
    const blockDistance = blocksUntilCommitteeLock(snapshot);
    const canSubmit =
        snapshot.updatesOpen &&
        changes.length > 0 &&
        selectionError === null &&
        !isSubmitting;

    const togglePeer = (peer: string) => {
        setSelected((previous) => {
            const next = new Set(previous);
            if (next.has(peer)) next.delete(peer);
            else next.add(peer);
            return next;
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
                <CommitteeDatum label="selected / eligible" value={`${visibleSelection.size}/${snapshot.available.length}`} />
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
                    <span>{snapshot.available.length} eligible</span>
                </div>
                <div className="committee-table" role="table" aria-label="committee peers">
                    <div className="committee-row committee-row--head" role="row">
                        <span role="columnheader" aria-label="selection" />
                        <span role="columnheader">validator</span>
                        <span role="columnheader">now</span>
                        <span role="columnheader">next</span>
                        <span role="columnheader">{snapshot.updatesOpen ? 'editing' : 'scheduled'}</span>
                    </div>
                    {snapshot.available.map((candidate) => {
                        const isCurrent = current.has(candidate.peer);
                        const isNext = next.has(candidate.peer);
                        const isSelected = visibleSelection.has(candidate.peer);
                        const isScheduled = scheduled.has(candidate.peer);
                        const pending = isScheduled === isSelected
                            ? null
                            : isSelected
                                ? 'addition'
                                : 'removal';
                        return (
                            <label
                                className={`committee-row${pending ? ` committee-row--pending-${pending}` : ''}${!snapshot.updatesOpen || isSubmitting ? ' committee-row--disabled' : ''}`}
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
                                    <small title={candidate.address}>{candidate.address}</small>
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
                                            : isSelected
                                                ? 'selected'
                                                : 'excluded'}
                                    tone={pending ?? (isSelected ? 'editing' : 'muted')}
                                />
                            </label>
                        );
                    })}
                </div>
            </section>

            <div className={`committee-actions${changes.length > 0 ? ' committee-actions--pending' : ''}`}>
                <div className="committee-actions__summary" aria-live="polite">
                    <i aria-hidden="true">›</i>
                    <div>
                        <strong>{changes.length} pending {changes.length === 1 ? 'change' : 'changes'}</strong>
                        {changes.length > 0 && (
                            <span>
                                {changes.map((change) => `${change.registered ? 'register' : 'remove'} ${shortPeer(change.peer)}`).join(' · ')}
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
