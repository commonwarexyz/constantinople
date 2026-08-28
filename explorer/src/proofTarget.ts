import { transactionProofTip } from './proofMath.ts';

// Published writer watermarks for both QMDB families, as inclusive tips.
export interface PublishedWatermarks {
    readonly state: bigint;
    readonly transactions: bigint;
}

export interface ProofTargetTips {
    readonly stateTip: bigint;
    readonly transactionsTip: bigint;
}

// The QMDB service only states its published watermark inside the
// out_of_range rejection of a tip it cannot serve yet, so probing with an
// unreachable tip is how a client reads it.
const PUBLISHED_WATERMARK_PATTERN = /above published writer watermark (\d+)/;

export function parsePublishedWatermark(message: string): bigint | null {
    const match = PUBLISHED_WATERMARK_PATTERN.exec(message);
    return match ? BigInt(match[1]) : null;
}

// Certificates reach the Store as soon as a block finalizes, while watermarks
// are published only after the bulk upload commits, so the newest certificate
// usually sits a few blocks past what the QMDB service can prove. A target is
// usable only when both families are published through its tips.
export function targetWithinWatermarks(
    target: ProofTargetTips,
    watermarks: PublishedWatermarks,
): boolean {
    return (
        transactionProofTip(target.stateTip) <= watermarks.state &&
        transactionProofTip(target.transactionsTip) <= watermarks.transactions
    );
}
