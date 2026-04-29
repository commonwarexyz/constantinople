import { useEffect, useMemo, useRef, useState } from 'react';
import { type ObservedBlock, subscribeBlocks } from './indexer';

/** Most recent batches to keep in the live feed. Old entries fall off the table. */
const MAX_ROWS = 200;
/** Height (rows) of the throughput histogram at the top of the page. */
const HISTOGRAM_HEIGHT = 8;
/**
 * Upper bound on the responsive histogram column count. We measure the
 * container width and divide by 1ch to derive the actual column count, but
 * keep an absolute ceiling so each column still represents a meaningful
 * slice of recent history on ultra-wide displays.
 */
const HISTOGRAM_MAX_COLUMNS = 400;
/** Initial column count used before the ResizeObserver fires its first measurement. */
const HISTOGRAM_INITIAL_COLUMNS = 80;
/** 8-step unicode block ramp; index 0 is empty so unused cells stay blank. */
const BLOCK_GLYPHS = ' ▁▂▃▄▅▆▇█';

type Status =
    | { kind: 'connecting' }
    | { kind: 'live' }
    | { kind: 'error'; message: string };

// The explorer subscribes to the SQL metadata server (block_meta), NOT
// the raw KV store. The default port matches `--sql-port` in
// `bin/deploy/src/local.rs`; override via `VITE_SQL_URL` for non-default
// deployments. The KV store lives on a separate port (`VITE_INDEXER_URL`)
// and would be used for any future drill-down that fetches a tx body or
// QMDB proof by digest — not consumed by this UI today.
const DEFAULT_SQL_URL = 'http://127.0.0.1:8091';

const indexerUrl = import.meta.env.VITE_SQL_URL ?? DEFAULT_SQL_URL;

export default function App() {
    const [blocks, setBlocks] = useState<ObservedBlock[]>([]);
    // Cumulative counters across every block we've ever observed on the
    // stream. Tracked independently of `blocks` so the "observed" stats
    // keep climbing when older entries roll off the MAX_ROWS buffer.
    const [blocksObserved, setBlocksObserved] = useState(0);
    const [totalTxObserved, setTotalTxObserved] = useState(0);
    const [status, setStatus] = useState<Status>({ kind: 'connecting' });
    const lastSequenceRef = useRef<bigint | null>(null);

    useEffect(() => {
        const controller = new AbortController();
        let cancelled = false;

        (async () => {
            try {
                for await (const block of subscribeBlocks(indexerUrl, controller.signal)) {
                    if (cancelled) return;
                    lastSequenceRef.current = block.sequence;
                    setBlocks((current) => prependBounded(block, current));
                    setBlocksObserved((current) => current + 1);
                    setTotalTxObserved((current) => current + block.txCount);
                    setStatus({ kind: 'live' });
                }
            } catch (error) {
                if (cancelled || controller.signal.aborted) return;
                setStatus({
                    kind: 'error',
                    message: error instanceof Error ? error.message : String(error),
                });
            }
        })();

        return () => {
            cancelled = true;
            controller.abort();
        };
    }, []);

    return (
        <div className="app">
            <div className="app__container">
                <header className="app__header">
                    <h1 className="app__title">
                        <span className="accent">constantinople</span> / explorer
                    </h1>
                    <StatusBadge status={status} url={indexerUrl} />
                </header>
                <SummaryPanel
                    blocks={blocks}
                    blocksObserved={blocksObserved}
                    totalTxObserved={totalTxObserved}
                />
                <Histogram blocks={blocks} />
                <main className="app__main">
                    <BlockTable blocks={blocks} latestSequence={lastSequenceRef.current} />
                </main>
            </div>
        </div>
    );
}

function prependBounded(block: ObservedBlock, current: ObservedBlock[]): ObservedBlock[] {
    const next = [block, ...current];
    if (next.length > MAX_ROWS) {
        next.length = MAX_ROWS;
    }
    return next;
}

function StatusBadge({ status, url }: { status: Status; url: string }) {
    if (status.kind === 'connecting') {
        return (
            <span className="app__status">
                <span className="dot" />
                connecting to {url}
            </span>
        );
    }
    if (status.kind === 'error') {
        return (
            <span className="app__status error">
                <span className="dot" />
                {status.message}
            </span>
        );
    }
    return (
        <span className="app__status live">
            <span className="app__chevrons" aria-hidden="true">
                <span className="app__chevron">&gt;</span>
                <span className="app__chevron">&gt;</span>
                <span className="app__chevron">&gt;</span>
            </span>
            live · {url}
        </span>
    );
}

function SummaryPanel({
    blocks,
    blocksObserved,
    totalTxObserved,
}: {
    blocks: ObservedBlock[];
    blocksObserved: number;
    totalTxObserved: number;
}) {
    const stats = useMemo(() => computeStats(blocks), [blocks]);
    return (
        <section className="summary">
            <Stat label="latest height" value={stats.latestHeight ?? '—'} />
            <Stat label="blocks observed" value={blocksObserved.toLocaleString()} />
            <Stat label="total txs observed" value={totalTxObserved.toLocaleString()} />
            <Stat label="peak txs/block" value={stats.peakTx.toLocaleString()} />
            <Stat label="avg txs/block" value={stats.avgTx.toLocaleString()} />
        </section>
    );
}

function Stat({ label, value }: { label: string; value: React.ReactNode }) {
    return (
        <div className="summary__stat">
            <div className="summary__label">{label}</div>
            <div className="summary__value">{value}</div>
        </div>
    );
}

interface DerivedStats {
    latestHeight: string | null;
    peakTx: number;
    avgTx: number;
}

function computeStats(blocks: ObservedBlock[]): DerivedStats {
    if (blocks.length === 0) {
        return { latestHeight: null, peakTx: 0, avgTx: 0 };
    }
    let totalTx = 0;
    let peakTx = 0;
    let maxHeight = blocks[0].height;
    for (const block of blocks) {
        totalTx += block.txCount;
        if (block.txCount > peakTx) peakTx = block.txCount;
        if (block.height > maxHeight) maxHeight = block.height;
    }
    return {
        latestHeight: maxHeight.toString(),
        peakTx,
        avgTx: Math.round(totalTx / blocks.length),
    };
}

/**
 * ASCII histogram of `txCount` for the most recent blocks. Each column is
 * one block (oldest left → newest right) and uses an 8-step vertical block
 * ramp so a column can be partially filled with sub-row resolution.
 *
 * The column count is responsive: we measure 1ch in the chart's font via a
 * hidden `<span>x</span>` and divide the chart's content width by it on
 * mount and on every resize, so the histogram always fills the available
 * width without changing the monospace cell aesthetic.
 *
 * The y-axis is auto-scaled to the peak in the visible window so a quiet
 * stretch of empty blocks doesn't compress later activity into the baseline.
 */
function Histogram({ blocks }: { blocks: ObservedBlock[] }) {
    const chartRef = useRef<HTMLPreElement>(null);
    const measureRef = useRef<HTMLSpanElement>(null);
    const [columns, setColumns] = useState<number>(HISTOGRAM_INITIAL_COLUMNS);

    useEffect(() => {
        const chart = chartRef.current;
        const measure = measureRef.current;
        if (!chart || !measure) return;

        const recompute = () => {
            const chWidth = measure.getBoundingClientRect().width;
            if (chWidth <= 0) return;
            const style = window.getComputedStyle(chart);
            const padLeft = parseFloat(style.paddingLeft) || 0;
            const padRight = parseFloat(style.paddingRight) || 0;
            const contentWidth = chart.clientWidth - padLeft - padRight;
            if (contentWidth <= 0) return;
            const cols = Math.max(
                1,
                Math.min(HISTOGRAM_MAX_COLUMNS, Math.floor(contentWidth / chWidth)),
            );
            setColumns((prev) => (prev === cols ? prev : cols));
        };

        recompute();
        const observer = new ResizeObserver(recompute);
        observer.observe(chart);
        return () => observer.disconnect();
    }, []);

    const { lines, peak } = useMemo(
        () => buildHistogram(blocks, columns),
        [blocks, columns],
    );
    return (
        <section className="histogram">
            <div className="histogram__y-axis">
                <span>{peak > 0 ? peak.toLocaleString() : ''}</span>
                <span>0</span>
            </div>
            <pre
                ref={chartRef}
                className="histogram__chart"
                aria-label="recent block tx count histogram"
            >
                <span ref={measureRef} className="histogram__measure" aria-hidden="true">
                    x
                </span>
                {lines.join('\n')}
            </pre>
            <div className="histogram__caption">
                tx count per block · last {Math.min(blocks.length, columns)} blocks ·
                oldest → newest
            </div>
        </section>
    );
}

function buildHistogram(
    blocks: ObservedBlock[],
    width: number,
): { lines: string[]; peak: number } {
    // Newest-first → oldest-first so the histogram reads left=old, right=new.
    const recent = blocks.slice(0, width).reverse();
    let peak = 0;
    for (const block of recent) {
        if (block.txCount > peak) peak = block.txCount;
    }
    if (peak === 0) {
        const blank = ' '.repeat(width);
        return { lines: Array.from({ length: HISTOGRAM_HEIGHT }, () => blank), peak };
    }

    // Total fill in 1/8th steps for the entire HISTOGRAM_HEIGHT-tall column.
    const ramp = BLOCK_GLYPHS.length - 1; // 8
    const eighthsPerColumn = HISTOGRAM_HEIGHT * ramp;

    const columnEighths = recent.map((block) =>
        Math.min(eighthsPerColumn, Math.max(1, Math.round((block.txCount / peak) * eighthsPerColumn))),
    );
    // Pad the left side with empty columns when we don't have enough history.
    while (columnEighths.length < width) {
        columnEighths.unshift(0);
    }

    // Render top-to-bottom. For each row (top=0, bottom=HEIGHT-1), the slot
    // for column j gets the 1/8 step left after subtracting the rows below it.
    const lines: string[] = [];
    for (let row = 0; row < HISTOGRAM_HEIGHT; row++) {
        const rowsBelow = HISTOGRAM_HEIGHT - 1 - row;
        let line = '';
        for (const eighths of columnEighths) {
            const remainingForThisRow = Math.max(0, Math.min(ramp, eighths - rowsBelow * ramp));
            line += BLOCK_GLYPHS[remainingForThisRow];
        }
        lines.push(line);
    }
    return { lines, peak };
}

function BlockTable({
    blocks,
    latestSequence,
}: {
    blocks: ObservedBlock[];
    latestSequence: bigint | null;
}) {
    const formatter = useMemo(
        () =>
            new Intl.DateTimeFormat(undefined, {
                hour: '2-digit',
                minute: '2-digit',
                second: '2-digit',
                fractionalSecondDigits: 3,
            }),
        [],
    );

    if (blocks.length === 0) {
        return (
            <div className="empty">
                waiting for blocks… (start the spammer to see them stream in)
            </div>
        );
    }
    return (
        <table className="block-table">
            <thead>
                <tr>
                    <th className="col-height">height</th>
                    <th className="col-txs">txs</th>
                    <th className="col-time">arrived</th>
                </tr>
            </thead>
            <tbody>
                {blocks.map((block) => {
                    const isFresh = latestSequence !== null && block.sequence === latestSequence;
                    return (
                        <tr key={block.sequence.toString()} className={isFresh ? 'is-fresh' : undefined}>
                            <td className="col-height">{block.height.toString()}</td>
                            <td className="col-txs">{block.txCount.toLocaleString()}</td>
                            <td className="col-time">{formatter.format(block.arrivedAt)}</td>
                        </tr>
                    );
                })}
            </tbody>
        </table>
    );
}
