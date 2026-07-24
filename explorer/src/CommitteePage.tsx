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
                    {!loading && <button onClick={onRefresh}>retry</button>}
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
        <section className="committee-page" aria-label="committee controls">
            <div className="committee-page__topline">
                <div>
                    <div className="committee-page__kicker">committee controls</div>
                    <h2>committee</h2>
                </div>
                <div className={snapshot.updatesOpen ? 'committee-lock committee-lock--open' : 'committee-lock committee-lock--closed'}>
                    <strong>{snapshot.updatesOpen ? 'updates open' : 'updates locked'}</strong>
                    <span>{committeeLockDetail(snapshot)}</span>
                </div>
            </div>

            <div className="committee-summary">
                <CommitteeDatum label="finalized height" value={snapshot.height.toString()} />
                <CommitteeDatum label="current epoch" value={snapshot.epoch.toString()} />
                <CommitteeDatum label="selected / eligible" value={`${visibleSelection.size} / ${snapshot.available.length}`} />
                <CommitteeDatum label="blocks until submissions close" value={blockDistance.toString()} />
            </div>

            <div className="committee-lifecycle" role="group" aria-label="committee lifecycle">
                <CommitteeStage
                    stage="01 / now"
                    epoch={snapshot.epoch}
                    detail={`${snapshot.current.length} validating`}
                    tone="active"
                />
                <CommitteeStage
                    stage="02 / next · locked"
                    epoch={snapshot.epoch + 1n}
                    detail={`${snapshot.next.length} validators already set`}
                />
                <CommitteeStage
                    stage={snapshot.updatesOpen ? '03 / editing' : '03 / scheduled · locked'}
                    epoch={snapshot.targetEpoch}
                    detail={`${visibleSelection.size} selected · ${snapshot.updatesOpen ? 'submissions open' : 'submissions closed'}`}
                    tone="editing"
                />
            </div>

            <div className="committee-table" role="table" aria-label="committee peers">
                <div className="committee-row committee-row--head" role="row">
                    <span role="columnheader" aria-label="selection" />
                    <span role="columnheader">peer</span>
                    <span role="columnheader">address</span>
                    <span role="columnheader">now</span>
                    <span role="columnheader">next</span>
                    <span role="columnheader">{snapshot.updatesOpen ? 'editing' : 'scheduled'}</span>
                </div>
                {snapshot.available.map((candidate) => {
                    const isCurrent = current.has(candidate.peer);
                    const isNext = next.has(candidate.peer);
                    const isSelected = visibleSelection.has(candidate.peer);
                    const isScheduled = scheduled.has(candidate.peer);
                    return (
                        <label className="committee-row" role="row" key={candidate.peer}>
                            <span role="cell">
                                <input
                                    type="checkbox"
                                    checked={isSelected}
                                    disabled={!snapshot.updatesOpen || isSubmitting}
                                    onChange={() => togglePeer(candidate.peer)}
                                    aria-label={`select ${candidate.peer}`}
                                />
                            </span>
                            <span className="committee-row__peer" role="cell" title={candidate.peer}>
                                {candidate.peer}
                            </span>
                            <span className="committee-row__address" role="cell" title={candidate.address}>
                                {candidate.address}
                            </span>
                            <span className="committee-row__status" role="cell">
                                <strong>{isCurrent ? 'active' : 'standby'}</strong>
                            </span>
                            <span className="committee-row__status" role="cell">
                                <strong>{isNext ? 'included' : 'excluded'}</strong>
                            </span>
                            <span className="committee-row__status" role="cell">
                                <strong>{isSelected ? 'included' : 'excluded'}</strong>
                                {isScheduled !== isSelected && (
                                    <em>{isSelected ? 'pending addition' : 'pending removal'}</em>
                                )}
                            </span>
                        </label>
                    );
                })}
            </div>

            <div className="committee-actions">
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
                <div className="committee-actions__buttons">
                    <button disabled={loading || isSubmitting} onClick={onRefresh}>refresh</button>
                    <button
                        disabled={!canSubmit}
                        onClick={() => walletAccountKey ? onSubmit(changes) : onOpenWallet()}
                    >
                        {isSubmitting
                            ? 'signing / submitting'
                            : walletAccountKey
                                ? `sign & submit ${changes.length} ${changes.length === 1 ? 'update' : 'updates'}`
                                : 'open wallet to sign'}
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
    tone?: 'active' | 'editing';
}) {
    const className = tone
        ? `committee-lifecycle__stage committee-lifecycle__stage--${tone}`
        : 'committee-lifecycle__stage';
    return (
        <div className={className}>
            <span>{stage}</span>
            <strong>epoch {epoch.toString()}</strong>
            <small>{detail}</small>
        </div>
    );
}

function shortPeer(peer: string): string {
    return peer.length <= 20 ? peer : `${peer.slice(0, 12)}…${peer.slice(-8)}`;
}
