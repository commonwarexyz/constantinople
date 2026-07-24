import {
    consumeNonce,
    nextAvailableNonce,
    type NonceState,
} from './nonce.ts';
import { toHex } from './codec.ts';
import {
    normalizeEd25519PublicKey,
    normalizeValidatorEndpoint,
} from './validator.ts';
import {
    SqlClient,
    type CellValue,
    type DecodedQueryResult,
    type DecodedRow,
} from '@exowarexyz/sql';

const MAX_U64 = (1n << 64n) - 1n;
const MAX_COMMITTEE_SIZE = 64;
const BLOCKS_PER_EPOCH = 64n;
const ED25519_PUBLIC_KEY_BYTES = 32;

const BLOCK_META_TABLE = 'block_meta';
const BLOCK_META_HEIGHT = 'height';
const BLOCK_META_EPOCH = 'epoch';
const COMMITTEE_META_TABLE = 'committee_meta';
const COMMITTEE_META_EPOCH = 'epoch';
const COMMITTEE_META_MEMBERS = 'members';
const ELIGIBLE_PEER_TABLE = 'eligible_peer';
const ELIGIBLE_PEER_PEER = 'peer';
const ELIGIBLE_PEER_ADDRESS = 'address';

export interface EligibleCommitteePeer {
    readonly peer: string;
    readonly address: string;
}

export interface CommitteeSnapshot {
    readonly height: bigint;
    readonly epoch: bigint;
    readonly targetEpoch: bigint;
    readonly updatesOpen: boolean;
    /** The first of the epoch's final two blocks, which reject committee mutations. */
    readonly lockHeight: bigint;
    readonly current: readonly string[];
    /** The immutable committee for the epoch immediately after `epoch`. */
    readonly next: readonly string[];
    readonly scheduled: readonly string[];
    /** Peers and addresses learned from finalized committee snapshots. */
    readonly available: readonly EligibleCommitteePeer[];
}

export interface CommitteeChange {
    readonly peer: string;
    /** The peer's existing canonical endpoint for additions; null for removals. */
    readonly address: string | null;
}

export interface PlannedCommitteeTransaction extends CommitteeChange {
    readonly targetEpoch: bigint;
    readonly nonce: bigint;
}

export interface CommitteeTransactionPlan {
    readonly transactions: readonly PlannedCommitteeTransaction[];
    readonly nextNonceState: NonceState;
}

/** Merge local, previously unknown peers into the indexed roster without duplicates. */
export function mergeCommitteeRoster(
    available: readonly EligibleCommitteePeer[],
    drafts: readonly EligibleCommitteePeer[],
): EligibleCommitteePeer[] {
    const merged = [...available];
    const peers = new Set(available.map(({ peer }) => peer));
    for (const draft of drafts) {
        if (peers.has(draft.peer)) continue;
        peers.add(draft.peer);
        merged.push(draft);
    }
    return merged;
}

/** Build a canonical draft, rejecting both indexed and already-local peers. */
export function createCommitteeDraft(
    roster: readonly EligibleCommitteePeer[],
    publicKey: string,
    endpoint: string,
): EligibleCommitteePeer {
    const peer = normalizeEd25519PublicKey(publicKey);
    if (roster.some((candidate) => candidate.peer === peer)) {
        throw new Error('validator public key already exists in the roster');
    }
    return { peer, address: normalizeValidatorEndpoint(endpoint) };
}

/**
 * Keep local peers through height-only refreshes. Epoch/lock transitions reset
 * the edit session, while peers adopted by the finalized index are deduplicated.
 */
export function reconcileCommitteeDrafts(
    previous: CommitteeSnapshot | null,
    next: CommitteeSnapshot | null,
    drafts: readonly EligibleCommitteePeer[],
): EligibleCommitteePeer[] {
    if (
        previous === null ||
        next === null ||
        !next.updatesOpen ||
        previous.targetEpoch !== next.targetEpoch ||
        previous.lockHeight !== next.lockHeight ||
        previous.updatesOpen !== next.updatesOpen
    ) {
        return [];
    }
    const indexed = new Set(next.available.map(({ peer }) => peer));
    return drafts.filter(({ peer }) => !indexed.has(peer));
}

/** Rebase explicit peer choices onto a newly indexed committee snapshot. */
export function reconcileCommitteeSelection(
    previous: CommitteeSnapshot | null,
    next: CommitteeSnapshot | null,
    selected: ReadonlySet<string>,
): Set<string> {
    if (next === null) return new Set();

    const eligible = new Set(next.available.map(({ peer }) => peer));
    const reconciled = new Set(next.scheduled.filter((peer) => eligible.has(peer)));
    if (
        !next.updatesOpen ||
        previous === null ||
        previous.targetEpoch !== next.targetEpoch
    ) {
        return reconciled;
    }

    const previousSchedule = new Set(previous.scheduled);
    for (const { peer } of next.available) {
        const userSelected = selected.has(peer);
        if (userSelected === previousSchedule.has(peer)) continue;
        if (userSelected) reconciled.add(peer);
        else reconciled.delete(peer);
    }
    return reconciled;
}

/** Read the finalized committee view and known-peer catalog from SQL. */
export async function fetchCommittee(
    sqlUrl: string,
    signal?: AbortSignal,
    client: Pick<SqlClient, 'query'> = new SqlClient(trimTrailingSlash(sqlUrl)),
): Promise<CommitteeSnapshot> {
    const tipResult = await sqlQuery(
        client,
        `
            SELECT ${BLOCK_META_HEIGHT}, ${BLOCK_META_EPOCH}
            FROM ${BLOCK_META_TABLE}
            ORDER BY ${BLOCK_META_HEIGHT} DESC
            LIMIT 1
        `,
        signal,
    );
    const tip = tipResult.rows[0];
    if (!tip) {
        throw new Error('committee state is unavailable before the first indexed block');
    }
    const height = expectBigint(tip.values[BLOCK_META_HEIGHT], BLOCK_META_HEIGHT);
    const epoch = expectBigint(tip.values[BLOCK_META_EPOCH], BLOCK_META_EPOCH);
    const nextEpoch = checkedAdd(epoch, 1n, 'next committee epoch');
    const targetEpoch = checkedAdd(epoch, 2n, 'committee target epoch');

    const [currentResult, nextResult, scheduledResult, availableResult] = await Promise.all([
        fetchCommitteeAt(client, epoch, signal),
        fetchCommitteeAt(client, nextEpoch, signal),
        fetchCommitteeAt(client, targetEpoch, signal),
        sqlQuery(
            client,
            `
                SELECT ${ELIGIBLE_PEER_PEER}, ${ELIGIBLE_PEER_ADDRESS}
                FROM ${ELIGIBLE_PEER_TABLE}
                ORDER BY ${ELIGIBLE_PEER_PEER} ASC
            `,
            signal,
        ),
    ]);
    const current = decodeCommittee(currentResult, epoch);
    const next = decodeCommittee(nextResult, nextEpoch);
    const scheduled = decodeCommittee(scheduledResult, targetEpoch);
    const available = availableResult.rows.map(decodeEligiblePeer);
    if (new Set(available.map(({ peer }) => peer)).size !== available.length) {
        throw new Error('eligible peer index contains duplicate peers');
    }
    assertCommitteeSize(current.length, 'current committee');
    assertCommitteeSize(next.length, 'next committee');
    assertCommitteeSize(scheduled.length, 'scheduled committee');

    const eligible = new Set(available.map(({ peer }) => peer));
    for (const peer of [...current, ...next, ...scheduled]) {
        if (!eligible.has(peer)) {
            throw new Error(`committee member ${peer} is missing from available`);
        }
    }

    const epochEnd = checkedMultiply(
        checkedAdd(epoch, 1n, 'next epoch'),
        BLOCKS_PER_EPOCH,
        'epoch end',
    );
    const lockHeight = epochEnd - 2n;
    const submissionLockHeight = lockHeight - 1n;

    return {
        height,
        epoch,
        targetEpoch,
        updatesOpen: height < submissionLockHeight,
        lockHeight,
        current,
        next,
        scheduled,
        available,
    };
}

async function fetchCommitteeAt(
    client: Pick<SqlClient, 'query'>,
    requestedEpoch: bigint,
    signal?: AbortSignal,
): Promise<DecodedQueryResult> {
    return sqlQuery(
        client,
        `
            SELECT ${COMMITTEE_META_EPOCH}, ${COMMITTEE_META_MEMBERS}
            FROM ${COMMITTEE_META_TABLE}
            WHERE ${COMMITTEE_META_EPOCH} <= ${requestedEpoch.toString()}
            ORDER BY ${COMMITTEE_META_EPOCH} DESC
            LIMIT 1
        `,
        signal,
    );
}

function decodeCommittee(result: DecodedQueryResult, requestedEpoch: bigint): string[] {
    const row = result.rows[0];
    if (!row) {
        throw new Error(`committee for epoch ${requestedEpoch.toString()} is not indexed`);
    }
    const indexedEpoch = expectBigint(row.values[COMMITTEE_META_EPOCH], COMMITTEE_META_EPOCH);
    if (indexedEpoch > requestedEpoch) {
        throw new Error('committee index returned a snapshot after the requested epoch');
    }
    const members = expectBytes(row.values[COMMITTEE_META_MEMBERS], COMMITTEE_META_MEMBERS);
    if (
        members.length === 0 ||
        members.length % ED25519_PUBLIC_KEY_BYTES !== 0 ||
        members.length / ED25519_PUBLIC_KEY_BYTES > MAX_COMMITTEE_SIZE
    ) {
        throw new Error('SQL committee members must contain 1..=64 Ed25519 public keys');
    }
    const decoded: string[] = [];
    for (let offset = 0; offset < members.length; offset += ED25519_PUBLIC_KEY_BYTES) {
        decoded.push(toHex(members.slice(offset, offset + ED25519_PUBLIC_KEY_BYTES)));
    }
    if (new Set(decoded).size !== decoded.length) {
        throw new Error('SQL committee members contain duplicate peers');
    }
    return decoded;
}

function decodeEligiblePeer(row: DecodedRow): EligibleCommitteePeer {
    const peer = expectBytes(row.values[ELIGIBLE_PEER_PEER], ELIGIBLE_PEER_PEER);
    if (peer.length !== ED25519_PUBLIC_KEY_BYTES) {
        throw new Error('SQL eligible peer must be a 32-byte Ed25519 public key');
    }
    return {
        peer: toHex(peer),
        address: normalizeValidatorEndpoint(
            expectString(row.values[ELIGIBLE_PEER_ADDRESS], ELIGIBLE_PEER_ADDRESS),
        ),
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
    const changes = snapshot.available.flatMap(({ peer, address }) => {
        const isSelected = selected.has(peer);
        return isSelected === scheduled.has(peer)
            ? []
            : [{ peer, address: isSelected ? address : null }];
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
        (change.address !== null ? additions : removals).push(change);
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

/** Number of finalized block advances before new submissions must close. */
export function blocksUntilCommitteeLock(snapshot: CommitteeSnapshot): bigint {
    const submissionLockHeight = snapshot.lockHeight > 0n
        ? snapshot.lockHeight - 1n
        : 0n;
    return snapshot.height < submissionLockHeight
        ? submissionLockHeight - snapshot.height
        : 0n;
}

export function committeeLockDetail(snapshot: CommitteeSnapshot): string {
    const firstFrozenBlock = snapshot.lockHeight.toString();
    const finalBlock = (snapshot.lockHeight + 1n).toString();
    if (snapshot.lockHeight === 0n) {
        return `final two blocks ${firstFrozenBlock} and ${finalBlock} reject committee updates`;
    }
    return `final two blocks ${firstFrozenBlock} and ${finalBlock} reject updates; accepted through block ${(
        snapshot.lockHeight - 1n
    ).toString()}`;
}

function assertCommitteeSize(size: number, field: string) {
    if (!Number.isSafeInteger(size) || size < 1 || size > MAX_COMMITTEE_SIZE) {
        throw new Error(`${field} must contain 1..=${MAX_COMMITTEE_SIZE} peers`);
    }
}

async function sqlQuery(
    client: Pick<SqlClient, 'query'>,
    query: string,
    signal?: AbortSignal,
): Promise<DecodedQueryResult> {
    return client.query(query.replace(/\s+/g, ' ').trim(), { signal });
}

function expectBigint(value: CellValue, column: string): bigint {
    if (typeof value !== 'bigint' || value < 0n || value > MAX_U64) {
        throw new Error(`SQL column ${column} must be UInt64`);
    }
    return value;
}

function expectBytes(value: CellValue, column: string): Uint8Array {
    if (!(value instanceof Uint8Array)) {
        throw new Error(`SQL column ${column} must be binary`);
    }
    return value;
}

function expectString(value: CellValue, column: string): string {
    if (typeof value !== 'string' || value.length === 0) {
        throw new Error(`SQL column ${column} must be non-empty Utf8`);
    }
    return value;
}

function checkedAdd(left: bigint, right: bigint, field: string): bigint {
    const result = left + right;
    if (result < 0n || result > MAX_U64) {
        throw new Error(`${field} must fit in u64`);
    }
    return result;
}

function checkedMultiply(left: bigint, right: bigint, field: string): bigint {
    const result = left * right;
    if (result < 0n || result > MAX_U64) {
        throw new Error(`${field} must fit in u64`);
    }
    return result;
}

function trimTrailingSlash(value: string): string {
    return value.replace(/\/+$/, '');
}
