import {
    consumeNonce,
    nextAvailableNonce,
    type NonceState,
} from './nonce.ts';

const MAX_U64 = (1n << 64n) - 1n;
const MAX_COMMITTEE_SIZE = 64;

export interface EligibleCommitteePeer {
    readonly peer: string;
    readonly address: string;
    /** Runtime observation only; it is never an eligibility or validity check. */
    readonly connected: boolean;
}

export interface CommitteeSnapshot {
    readonly height: bigint;
    readonly epoch: bigint;
    readonly targetEpoch: bigint;
    readonly updatesOpen: boolean;
    /** The exact final block, which rejects committee mutations. */
    readonly lockHeight: bigint;
    readonly current: readonly string[];
    readonly scheduled: readonly string[];
    /** The complete immutable eligible catalog, including disconnected peers. */
    readonly available: readonly EligibleCommitteePeer[];
}

export interface CommitteeChange {
    readonly peer: string;
    readonly registered: boolean;
}

export interface PlannedCommitteeTransaction extends CommitteeChange {
    readonly targetEpoch: bigint;
    readonly nonce: bigint;
}

export interface CommitteeTransactionPlan {
    readonly transactions: readonly PlannedCommitteeTransaction[];
    readonly nextNonceState: NonceState;
}

/**
 * Fetch and validate the mempool's `GET /committee` response.
 *
 * Consensus-sized integers must cross JSON as decimal strings. Converting
 * them to bigint here keeps rendering and E+2/lock arithmetic exact.
 */
export async function fetchCommittee(
    baseUrl: string,
    signal?: AbortSignal,
): Promise<CommitteeSnapshot> {
    const response = await fetch(`${trimTrailingSlash(baseUrl)}/committee`, { signal });
    if (!response.ok) {
        const detail = await response.text();
        const suffix = detail ? `: ${detail}` : '';
        throw new Error(`committee lookup failed with HTTP ${response.status}${suffix}`);
    }
    return parseCommitteeResponse(await response.json());
}

export function parseCommitteeResponse(value: unknown): CommitteeSnapshot {
    const response = record(value, 'committee response');
    const height = decimalU64(response.height, 'height');
    const epoch = decimalU64(response.epoch, 'epoch');
    const targetEpoch = decimalU64(response.targetEpoch, 'targetEpoch');
    const lockHeight = decimalU64(response.lockHeight, 'lockHeight');
    const updatesOpen = boolean(response.updatesOpen, 'updatesOpen');
    const current = uniqueStringArray(response.current, 'current');
    const scheduled = uniqueStringArray(response.scheduled, 'scheduled');
    const available = eligiblePeers(response.available);

    if (targetEpoch !== epoch + 2n) {
        throw new Error('targetEpoch must equal epoch + 2');
    }
    assertCommitteeSize(current.length, 'current committee');
    assertCommitteeSize(scheduled.length, 'scheduled committee');

    const eligible = new Set(available.map(({ peer }) => peer));
    for (const peer of [...current, ...scheduled]) {
        if (!eligible.has(peer)) {
            throw new Error(`committee member ${peer} is missing from available`);
        }
    }

    return {
        height,
        epoch,
        targetEpoch,
        updatesOpen,
        lockHeight,
        current,
        scheduled,
        available,
    };
}

/** Return one idempotent per-peer action for every selection change. */
export function committeeChanges(
    snapshot: CommitteeSnapshot,
    selected: ReadonlySet<string>,
): CommitteeChange[] {
    const eligible = new Set(snapshot.available.map(({ peer }) => peer));
    for (const peer of selected) {
        if (!eligible.has(peer)) {
            throw new Error(`peer ${peer} is not eligible`);
        }
    }

    const scheduled = new Set(snapshot.scheduled);
    const changes = snapshot.available.flatMap(({ peer }) => {
        const registered = selected.has(peer);
        return registered === scheduled.has(peer) ? [] : [{ peer, registered }];
    });
    return orderCommitteeChanges(changes, scheduled.size);
}

export function validateCommitteeSelection(selected: ReadonlySet<string>): string | null {
    if (selected.size === 0) return 'committee must contain at least one peer';
    if (selected.size > MAX_COMMITTEE_SIZE) {
        return `committee must contain at most ${MAX_COMMITTEE_SIZE} peers`;
    }
    return null;
}

/**
 * Reserve every action before signing begins, so concurrent UI submissions
 * cannot take a nonce from the middle of this sequential transaction series.
 */
export function planCommitteeTransactions(
    changes: readonly CommitteeChange[],
    targetEpoch: bigint,
    initialNonceState: NonceState,
    scheduledCommitteeSize: number,
): CommitteeTransactionPlan {
    let nextNonceState = initialNonceState;
    const transactions: PlannedCommitteeTransaction[] = [];

    for (const change of orderCommitteeChanges(changes, scheduledCommitteeSize)) {
        const nonce = nextAvailableNonce(nextNonceState);
        const consumed = consumeNonce(nextNonceState, nonce);
        if (consumed === null) {
            throw new Error('committee transaction nonce must fit in u64');
        }
        transactions.push({ ...change, targetEpoch, nonce });
        nextNonceState = consumed;
    }

    return { transactions, nextNonceState };
}

/**
 * Deterministically order idempotent per-peer updates without crossing the
 * consensus committee bounds after any individual transaction.
 */
function orderCommitteeChanges(
    changes: readonly CommitteeChange[],
    initialSize: number,
): CommitteeChange[] {
    assertCommitteeSize(initialSize, 'scheduled committee');

    const seen = new Set<string>();
    const additions: CommitteeChange[] = [];
    const removals: CommitteeChange[] = [];
    for (const change of changes) {
        if (seen.has(change.peer)) {
            throw new Error(`committee changes contain duplicate peer ${change.peer}`);
        }
        seen.add(change.peer);
        (change.registered ? additions : removals).push(change);
    }

    const finalSize = initialSize + additions.length - removals.length;
    assertCommitteeSize(finalSize, 'resulting committee');

    const ordered: CommitteeChange[] = [];
    let size = initialSize;
    let additionIndex = 0;
    let removalIndex = 0;
    while (additionIndex < additions.length || removalIndex < removals.length) {
        if (additionIndex < additions.length && size < MAX_COMMITTEE_SIZE) {
            ordered.push(additions[additionIndex]);
            additionIndex += 1;
            size += 1;
            continue;
        }
        if (removalIndex < removals.length && size > 1) {
            ordered.push(removals[removalIndex]);
            removalIndex += 1;
            size -= 1;
            continue;
        }
        throw new Error('committee changes cannot stay within size bounds');
    }
    return ordered;
}

/** Number of finalized block advances before the exact final-block lock. */
export function blocksUntilCommitteeLock(snapshot: CommitteeSnapshot): bigint {
    return snapshot.height < snapshot.lockHeight
        ? snapshot.lockHeight - snapshot.height
        : 0n;
}

export function committeeLockDetail(snapshot: CommitteeSnapshot): string {
    const finalBlock = snapshot.lockHeight.toString();
    if (snapshot.lockHeight === 0n) {
        return `final block ${finalBlock} rejects committee updates`;
    }
    return `final block ${finalBlock} rejects updates; accepted through block ${(
        snapshot.lockHeight - 1n
    ).toString()}`;
}

export function connectivityAdvisory(connected: boolean): string {
    return connected ? 'connected · advisory' : 'not connected · advisory';
}

function eligiblePeers(value: unknown): EligibleCommitteePeer[] {
    if (!Array.isArray(value)) {
        throw new Error('available must be an array');
    }

    const peers = value.map((entry, index) => {
        const candidate = record(entry, `available[${index}]`);
        return {
            peer: string(candidate.peer, `available[${index}].peer`),
            address: string(candidate.address, `available[${index}].address`),
            connected: boolean(candidate.connected, `available[${index}].connected`),
        };
    });
    const unique = new Set(peers.map(({ peer }) => peer));
    if (unique.size !== peers.length) {
        throw new Error('available contains duplicate peers');
    }
    return peers;
}

function uniqueStringArray(value: unknown, field: string): string[] {
    if (!Array.isArray(value)) {
        throw new Error(`${field} must be an array`);
    }
    const values = value.map((entry, index) => string(entry, `${field}[${index}]`));
    if (new Set(values).size !== values.length) {
        throw new Error(`${field} contains duplicate peers`);
    }
    return values;
}

function decimalU64(value: unknown, field: string): bigint {
    if (typeof value !== 'string' || !/^(0|[1-9]\d*)$/.test(value)) {
        throw new Error(`${field} must be a canonical decimal string`);
    }
    const parsed = BigInt(value);
    if (parsed > MAX_U64) {
        throw new Error(`${field} must fit in u64`);
    }
    return parsed;
}

function assertCommitteeSize(size: number, field: string) {
    if (!Number.isSafeInteger(size) || size < 1 || size > MAX_COMMITTEE_SIZE) {
        throw new Error(`${field} must contain 1..=${MAX_COMMITTEE_SIZE} peers`);
    }
}

function record(value: unknown, field: string): Record<string, unknown> {
    if (typeof value !== 'object' || value === null || Array.isArray(value)) {
        throw new Error(`${field} must be an object`);
    }
    return value as Record<string, unknown>;
}

function string(value: unknown, field: string): string {
    if (typeof value !== 'string' || value.length === 0) {
        throw new Error(`${field} must be a non-empty string`);
    }
    return value;
}

function boolean(value: unknown, field: string): boolean {
    if (typeof value !== 'boolean') {
        throw new Error(`${field} must be a boolean`);
    }
    return value;
}

function trimTrailingSlash(value: string): string {
    return value.replace(/\/+$/, '');
}
