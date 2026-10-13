import type { TransactionRowMetadata, TransactionRowMetadataResult } from './qmdb.ts';

export type TransactionRowMetadataBatch = ReadonlyMap<string, TransactionRowMetadataResult>;

// Rows on a page share one indexed lookup per read floor. A digest missing
// from that lookup switches to its own row query, so it can keep retrying
// without delaying rows whose bodies passed validation.
export class TransactionRowMetadataCache {
    private floor: bigint;
    private batch: Promise<TransactionRowMetadataBatch> | undefined;
    private readonly unbatched = new Set<string>();
    private readonly fetchBatch: (minSequenceNumber: bigint) => Promise<TransactionRowMetadataBatch>;
    private readonly isRetryable: (error: unknown) => boolean;

    constructor({
        fetchBatch,
        isRetryable,
        floor,
        prefetched,
    }: {
        fetchBatch: (minSequenceNumber: bigint) => Promise<TransactionRowMetadataBatch>;
        isRetryable: (error: unknown) => boolean;
        floor: bigint;
        prefetched?: Promise<TransactionRowMetadataBatch>;
    }) {
        this.fetchBatch = fetchBatch;
        this.isRetryable = isRetryable;
        this.floor = floor;
        this.batch = prefetched;
    }

    // Resolves to undefined once the row must query its own metadata.
    async lookup(digest: string, minSequenceNumber: bigint): Promise<TransactionRowMetadata | undefined> {
        if (minSequenceNumber > this.floor) {
            this.floor = minSequenceNumber;
            this.batch = undefined;
        }
        if (this.unbatched.has(digest)) return undefined;

        const batch = this.batch ??= this.fetchBatch(this.floor);
        let results: TransactionRowMetadataBatch;
        try {
            results = await batch;
        } catch (error) {
            // Clearing a transient failure lets the next attempt from any row
            // issue one replacement query. Terminal failures stay cached so
            // every row reports them without querying again.
            if (this.batch === batch && this.isRetryable(error)) this.batch = undefined;
            throw error;
        }

        const result = results.get(digest);
        if (!result) throw new Error(`transaction metadata batch omitted tx digest ${digest}`);
        if (result.status === 'indexed') return result.metadata;
        if (result.status === 'missing') this.unbatched.add(digest);
        throw result.error;
    }
}
