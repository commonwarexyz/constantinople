import { useEffect, useMemo, useState } from 'react';
import {
    blocksUntilCommitteeLock,
    committeeChanges,
    committeeLockDetail,
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
    const selectionBaseline = snapshot
        ? `${snapshot.targetEpoch.toString()}:${snapshot.scheduled.join(',')}`
        : '';

    useEffect(() => {
        setSelected(new Set(snapshot?.scheduled ?? []));
    }, [selectionBaseline]);

    const selectionError = validateCommitteeSelection(selected);
    const changes = useMemo(
        () => (snapshot && selectionError === null ? committeeChanges(snapshot, selected) : []),
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
    const scheduled = new Set(snapshot.scheduled);
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
                    <h2>committee / epoch {snapshot.targetEpoch.toString()}</h2>
                </div>
                <div className={snapshot.updatesOpen ? 'committee-lock committee-lock--open' : 'committee-lock committee-lock--closed'}>
                    <strong>{snapshot.updatesOpen ? 'updates open' : 'updates locked'}</strong>
                    <span>{committeeLockDetail(snapshot)}</span>
                </div>
            </div>

            <div className="committee-summary">
                <CommitteeDatum label="current epoch" value={snapshot.epoch.toString()} />
                <CommitteeDatum label="effective epoch" value={snapshot.targetEpoch.toString()} />
                <CommitteeDatum label="selected / eligible" value={`${selected.size} / ${snapshot.available.length}`} />
                <CommitteeDatum label="blocks to final-block lock" value={blockDistance.toString()} />
            </div>

            <div className="committee-page__notice">
                <span>permissionless demo: any signed account may submit an eligible E+2 change</span>
                <span>committee state and the eligible catalog are read from finalized index data</span>
            </div>

            <div className="committee-table" role="table" aria-label="eligible committee peers">
                <div className="committee-row committee-row--head" role="row">
                    <span role="columnheader">select</span>
                    <span role="columnheader">eligible peer</span>
                    <span role="columnheader">address</span>
                    <span role="columnheader">current / E+2</span>
                </div>
                {snapshot.available.map((candidate) => {
                    const isSelected = selected.has(candidate.peer);
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
                            <span role="cell">{candidate.address}</span>
                            <span role="cell">
                                {current.has(candidate.peer) ? 'member' : 'standby'} /{' '}
                                {isSelected ? 'selected' : 'not selected'}
                                {scheduled.has(candidate.peer) !== isSelected && <em> changed</em>}
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

function shortPeer(peer: string): string {
    return peer.length <= 20 ? peer : `${peer.slice(0, 12)}…${peer.slice(-8)}`;
}
