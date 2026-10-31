import { memo, useCallback, useEffect, useMemo, useRef, useState } from 'react';
import {
    ANALYSIS_ROW_LIMIT, ANALYSIS_SQL_LIMIT, analysisPresets, runAnalysis,
    type AnalysisCell, type AnalysisColumn, type AnalysisResult,
} from './analysis';
import { chartScale, chartValue, inferChart, type ChartAxes, type ChartValue } from './analysisChart';

interface Props {
    open: boolean;
    endpoint: string;
    suggestedAccount: string;
    latestHeight: bigint | null;
    onClose: () => void;
    onOpenAccount: (account: string) => void;
    onOpenBlock: (height: bigint) => void;
}

type QueryState =
    | { status: 'idle' }
    | { status: 'running'; sql: string }
    | { status: 'complete'; sql: string; result: AnalysisResult }
    | { status: 'error' | 'canceled'; sql: string; message: string; elapsedMs: number };

const milliseconds = (value: number) => value < 1000 ? `${Math.round(value)} ms` : `${(value / 1000).toFixed(2)} s`;

export const AnalysisDialog = memo(function AnalysisDialog({
    open, endpoint, suggestedAccount, latestHeight, onClose, onOpenAccount, onOpenBlock,
}: Props) {
    const [exampleAccount, setExampleAccount] = useState<string | null>(null);
    const account = (exampleAccount ?? suggestedAccount).trim();
    const validAccount = /^(0x)?[0-9a-f]{64}$/i.test(account);
    const presets = useMemo(() => analysisPresets(latestHeight && latestHeight > 0n ? latestHeight : 1n,
        validAccount ? account : undefined), [latestHeight, account, validAccount]);
    const [sql, setSql] = useState('');
    const [query, setQuery] = useState<QueryState>({ status: 'idle' });
    const [elapsed, setElapsed] = useState(0);
    const panel = useRef<HTMLElement>(null);
    const editor = useRef<HTMLTextAreaElement>(null);
    const initialized = useRef(false);
    const active = useRef<{ controller: AbortController; started: number; sql: string } | null>(null);

    const execute = useCallback(async (statement: string) => {
        active.current?.controller.abort();
        const job = { controller: new AbortController(), started: performance.now(), sql: statement };
        active.current = job;
        setSql(statement);
        initialized.current = true;
        setElapsed(0);
        setQuery({ status: 'running', sql: statement });
        try {
            const result = await runAnalysis(endpoint, statement, job.controller.signal);
            if (active.current === job) setQuery({ status: 'complete', sql: statement, result });
        } catch (error) {
            if (active.current === job) setQuery({
                status: 'error', sql: statement,
                message: error instanceof Error ? error.message : String(error),
                elapsedMs: performance.now() - job.started,
            });
        } finally {
            if (active.current === job) active.current = null;
        }
    }, [endpoint]);

    const cancel = useCallback(() => {
        const job = active.current;
        if (!job) return;
        active.current = null;
        job.controller.abort();
        setQuery({ status: 'canceled', sql: job.sql, message: 'Request canceled.', elapsedMs: performance.now() - job.started });
    }, []);

    useEffect(() => {
        if (open && !initialized.current) {
            setSql(presets[0].sql);
            initialized.current = true;
        }
    }, [open, presets]);

    useEffect(() => { if (!open) cancel(); }, [open, cancel]);
    useEffect(() => () => { active.current?.controller.abort(); }, []);
    useEffect(() => {
        if (query.status !== 'running') return;
        const timer = window.setInterval(() => {
            if (active.current) setElapsed(performance.now() - active.current.started);
        }, 100);
        return () => window.clearInterval(timer);
    }, [query.status]);

    useEffect(() => {
        if (!open) return;
        const previous = document.activeElement;
        editor.current?.focus();
        const keydown = (event: KeyboardEvent) => {
            if (event.key === 'Escape') { event.preventDefault(); onClose(); }
            if (event.key !== 'Tab') return;
            const elements = Array.from(panel.current?.querySelectorAll<HTMLElement>(
                'button:not(:disabled), input, textarea, select, summary, a[href], [tabindex="0"]',
            ) ?? []).filter(element => element.getClientRects().length > 0);
            const first = elements[0], last = elements[elements.length - 1];
            if (event.shiftKey && document.activeElement === first) { event.preventDefault(); last?.focus(); }
            else if (!event.shiftKey && document.activeElement === last) { event.preventDefault(); first?.focus(); }
        };
        document.addEventListener('keydown', keydown);
        return () => {
            document.removeEventListener('keydown', keydown);
            if (previous instanceof HTMLElement && previous.isConnected) previous.focus();
        };
    }, [open, onClose]);

    if (!open) return null;
    const running = query.status === 'running';
    return (
        <div className="modal" role="presentation" onMouseDown={event => {
            if (event.target === event.currentTarget) onClose();
        }}>
            <section className="modal__panel modal__panel--analysis" ref={panel} role="dialog" aria-modal="true" aria-labelledby="analysis-title">
                <header className="modal__header">
                    <h2 id="analysis-title">search / SQL</h2>
                    <button className="modal__close" onClick={onClose}>close</button>
                </header>
                <div className="analysis">
                    <p className="analysis__intro">Explore blocks, transfers, and balances in the index.</p>
                    <label className="analysis__account">account
                        <input aria-label="Account for example queries" value={exampleAccount ?? suggestedAccount}
                            onChange={event => setExampleAccount(event.target.value)} spellCheck={false} autoComplete="off"
                            placeholder="address for balance and transfer examples" />
                    </label>
                    <div className="analysis__presets" aria-label="Example queries">
                        {presets.map(preset => <button key={preset.id} disabled={preset.requiresAccount}
                            onClick={() => setSql(preset.sql)}>{preset.title}</button>)}
                    </div>
                    <label className="analysis__label" htmlFor="analysis-sql">query</label>
                    <textarea ref={editor} id="analysis-sql" className="analysis__editor" value={sql}
                        onChange={event => setSql(event.target.value)} rows={6} maxLength={ANALYSIS_SQL_LIMIT}
                        spellCheck={false} autoCapitalize="off" autoComplete="off"
                        onKeyDown={event => {
                            if (event.key === 'Enter' && (event.metaKey || event.ctrlKey)) {
                                event.preventDefault();
                                void execute(sql);
                            }
                        }} />
                    <div className="analysis__actions">
                        <button className="analysis__run" disabled={!sql.trim()} onClick={() => void execute(sql)}>{running ? 'run again' : 'run query'}</button>
                        {running && <button onClick={cancel}>cancel</button>}
                        <span>⌘ / ctrl + enter</span>
                    </div>
                    <details className="analysis__guide">
                        <summary>schema &amp; query guide</summary>
                        <p>Use one SELECT or WITH query. Results are capped at {ANALYSIS_ROW_LIMIT.toLocaleString()} rows; narrow large scans with WHERE and LIMIT.</p>
                        <dl>
                            <dt>block_meta</dt><dd>height, digest, tx_count, transactions_root, transactions_tip, view, finalized_ts</dd>
                            <dt>account_meta</dt><dd>account, qmdb_location, balance, nonce_base, nonce_bitmap</dd>
                            <dt>tx_activity</dt><dd>account, height, "index", role, tx_digest, counterparty, value, nonce, qmdb_location</dd>
                            <dt>tx_meta</dt><dd>tx_digest, height, qmdb_location, body</dd>
                        </dl>
                        <p>Write addresses and digests as X'64 hex digits', without 0x. The account field fills balance and transfer examples; it starts with the open account or wallet when available.</p>
                        <p>Balance history uses state operation locations, not timestamps. finalized_ts is the publisher’s observed time. Amounts use raw integer units; role 0 is sent and 1 is received.</p>
                        <p>Numeric and time results chart automatically. Alias columns as x and y to choose axes in SQL, or choose them below. Single-row numeric results show totals.</p>
                        <p>These are index results without certificate or proof verification. Store sequence is an observed visibility floor, not a snapshot. Elapsed time includes the request and decoding; the service does not report scan progress.</p>
                    </details>
                    {query.status !== 'idle' && <div className="analysis__result-status" aria-live="polite">
                        {running ? <>
                            <div className="analysis__status-line"><span>running query</span><span>{milliseconds(elapsed)}</span></div>
                            <progress className="analysis__progress" aria-label="Query in progress" />
                        </> : query.status === 'complete' ? <>
                            <div className="analysis__status-line"><span>complete</span><span>{milliseconds(query.result.stats.elapsedMs)}</span></div>
                            <progress className="analysis__progress" aria-label="Query complete" max={1} value={1} />
                        </> : <p className={query.status === 'error' ? 'analysis__error' : ''} role={query.status === 'error' ? 'alert' : undefined}>
                            {query.message} <span className="analysis__muted">({milliseconds(query.elapsedMs)})</span>
                        </p>}
                    </div>}
                    {query.status === 'complete' && <>
                        {sql !== query.sql && <p className="analysis__muted">Results from the last run. Run the edited query to update.</p>}
                        <AnalysisResults result={query.result} onOpenAccount={onOpenAccount} onOpenBlock={onOpenBlock} />
                    </>}
                </div>
            </section>
        </div>
    );
});

const AnalysisResults = memo(function AnalysisResults({ result, onOpenAccount, onOpenBlock }: {
    result: AnalysisResult;
    onOpenAccount: Props['onOpenAccount'];
    onOpenBlock: Props['onOpenBlock'];
}) {
    const [axes, setAxes] = useState<ChartAxes | null>(() => inferChart(result));
    const [page, setPage] = useState(0);
    const [chart, setChart] = useState(true);
    const [bars, setBars] = useState(false);
    const { columns, rows, stats } = result;
    const numeric = columns.map((column, i) => column.kind === 'number' ? i : -1).filter(i => i >= 0);
    return <div className="analysis__results">
        <dl className="analysis__stats">
            <div><dt>rows</dt><dd>{stats.rowCount.toLocaleString()}{result.truncated ? '+' : ''}</dd></div>
            <div><dt>columns</dt><dd>{stats.columnCount}</dd></div>
            <div><dt>batches</dt><dd>{stats.batchCount}</dd></div>
            {stats.sequenceNumber !== undefined && <div><dt>store seq</dt><dd>{stats.sequenceNumber.toString()}</dd></div>}
        </dl>
        {result.truncated && <p className="analysis__muted">Showing the first {ANALYSIS_ROW_LIMIT.toLocaleString()} rows. Add filters to explore the rest.</p>}
        {rows.length === 1 && numeric.length > 0 && <dl className="analysis__totals">
            {numeric.map(i => <div key={i}><dt>{columns[i].name}</dt><dd>{rows[0][i].text}</dd></div>)}
        </dl>}
        {rows.length > 1 && numeric.length > 0 && columns.length > 1 && <>
            <div className="analysis__chart-controls">
                <button aria-pressed={chart && axes !== null} onClick={() => {
                    setChart(!chart || axes === null);
                    if (!axes) setAxes({ x: numeric[0] === 0 ? 1 : 0, y: numeric[0] });
                }}>{chart && axes ? 'hide chart' : 'show chart'}</button>
                {chart && axes && <>
                    <label>x <select aria-label="Chart x axis" value={axes.x} onChange={event => setAxes({ ...axes, x: Number(event.target.value) })}>
                        {columns.map((column, i) => <option key={i} value={i}>{column.name}</option>)}
                    </select></label>
                    <label>y <select aria-label="Chart y axis" value={axes.y} onChange={event => setAxes({ ...axes, y: Number(event.target.value) })}>
                        {numeric.map(i => <option key={i} value={i}>{columns[i].name}</option>)}
                    </select></label>
                    <select aria-label="Chart type" value={bars ? 'bars' : 'line'} onChange={event => setBars(event.target.value === 'bars')}>
                        <option value="line">line</option><option value="bars">bars</option>
                    </select>
                </>}
            </div>
            {chart && axes && <ResultChart result={result} axes={axes} bars={bars} />}
        </>}
        <div className="analysis__table-wrap" tabIndex={0} aria-label="SQL result table">
            <table className="analysis__table">
                <thead><tr>{columns.map((column, i) => <th key={i} scope="col">{column.name}<small>{column.type}</small></th>)}</tr></thead>
                <tbody>{rows.slice(page * 50, page * 50 + 50).map((row, i) => <tr key={i}>
                    {row.map((cell, j) => <td key={j} className={cell.value === null ? 'analysis__muted' : undefined}>
                        <ResultCell cell={cell} column={columns[j]} onOpenAccount={onOpenAccount} onOpenBlock={onOpenBlock} />
                    </td>)}
                </tr>)}</tbody>
            </table>
        </div>
        {rows.length === 0 ? <p className="analysis__muted">No rows matched this query.</p> : <div className="analysis__pagination">
            <span>rows {page * 50 + 1}–{Math.min(page * 50 + 50, rows.length)} of {rows.length.toLocaleString()}</span>
            {rows.length > 50 && <div><button disabled={page === 0} onClick={() => setPage(page - 1)}>prev</button>{' '}
                <button disabled={(page + 1) * 50 >= rows.length} onClick={() => setPage(page + 1)}>next</button></div>}
        </div>}
    </div>;
});

function ResultCell({ cell, column, onOpenAccount, onOpenBlock }: {
    cell: AnalysisCell; column: AnalysisColumn;
    onOpenAccount: Props['onOpenAccount']; onOpenBlock: Props['onOpenBlock'];
}) {
    if (/^(account|counterparty|sender|recipient)$/i.test(column.name) && /^0x[0-9a-f]{64}$/i.test(cell.text)) {
        return <button className="analysis__link" onClick={() => onOpenAccount(cell.text)}>{cell.text}</button>;
    }
    if (column.name.toLowerCase() === 'height' && /^(0|[1-9][0-9]*)$/.test(cell.text) && BigInt(cell.text) < (1n << 64n)) {
        return <button className="analysis__link" onClick={() => onOpenBlock(BigInt(cell.text))}>{cell.text}</button>;
    }
    return cell.text;
}

function axisLabel(value: ChartValue, time: boolean, compact = false): string {
    if (time) {
        const date = new Date(Number(value));
        return Number.isFinite(date.getTime()) ? date.toISOString().replace('T', ' ').slice(0, 19) : String(value);
    }
    return new Intl.NumberFormat('en', { notation: compact && (value > 999999n || value < -999999n) ? 'scientific' : 'standard', maximumFractionDigits: 2 }).format(value);
}

function ResultChart({ result, axes, bars }: { result: AnalysisResult; axes: ChartAxes; bars: boolean }) {
    const xColumn = result.columns[axes.x], yColumn = result.columns[axes.y];
    const categorical = xColumn.kind !== 'number' && xColumn.kind !== 'time';
    const ordered = result.rows.map((row, index) => ({ row, index, x: chartValue(row[axes.x]), y: chartValue(row[axes.y]) }));
    if (!categorical) ordered.sort((a, b) => a.x === null ? 1 : b.x === null ? -1 : a.x < b.x ? -1 : a.x > b.x ? 1 : 0);
    const x = chartScale(categorical ? ordered.map((_row, index) => index) : ordered.flatMap(item => item.x === null ? [] : [item.x]));
    const useBars = bars || categorical;
    const y = chartScale(ordered.flatMap(item => item.y === null ? [] : [item.y]), useBars);
    if (!x || !y) return <p className="analysis__muted">These axes have no plottable values. Exact values are available in the table.</p>;
    const left = 10, right = 890, top = 15, bottom = 200;
    const points = ordered.map((item, index) => {
        const xv = categorical ? index : item.x;
        return xv === null || item.y === null ? null : {
            ...item, px: left + x.position(xv) * (right - left), py: bottom - y.position(item.y) * (bottom - top),
        };
    });
    let segmentStart = true;
    const path = points.map(point => {
        if (!point) { segmentStart = true; return ''; }
        const command = `${segmentStart ? 'M' : 'L'}${point.px},${point.py}`;
        segmentStart = false;
        return command;
    }).join(' ');
    const base = bottom - y.position(typeof y.min === 'bigint' ? 0n : 0) * (bottom - top);
    const width = Math.min(18, (right - left) / Math.max(points.length, 1) * 0.7);
    return <figure className="analysis__chart">
        <div className="analysis__plot">
            <div className="analysis__y-axis">
                <span>{axisLabel(y.max, false, true)}</span>
                <span>{axisLabel(y.min, false, true)}</span>
            </div>
            <svg viewBox="0 0 900 225" preserveAspectRatio="none" role="img" aria-label={`${yColumn.name} by ${xColumn.name}, ${useBars ? 'bar' : 'line'} chart`}>
                {[top, (top + bottom) / 2, bottom].map(position => <line key={position} className="analysis__grid-line" x1={left} x2={right} y1={position} y2={position} />)}
                {!useBars && <path className="analysis__chart-line" d={path} />}
                {points.map(point => point && <g key={point.index}>
                    <title>{xColumn.name}: {point.row[axes.x].text}; {yColumn.name}: {point.row[axes.y].text}</title>
                    {useBars ? <rect className="analysis__chart-bar" x={point.px - width / 2} y={Math.min(base, point.py)} width={width} height={Math.max(1, Math.abs(base - point.py))} />
                        : <circle className="analysis__chart-dot" cx={point.px} cy={point.py} r={2} />}
                </g>)}
            </svg>
        </div>
        <div className="analysis__chart-range"><span>{categorical ? ordered[0].row[axes.x].text : axisLabel(x.min, xColumn.kind === 'time')}</span>
            <span>{categorical ? ordered[ordered.length - 1].row[axes.x].text : axisLabel(x.max, xColumn.kind === 'time')}</span></div>
        <figcaption>{yColumn.name} / {xColumn.name} · {points.filter(Boolean).length} points{points.some(point => point === null) ? ' · null or nonnumeric values omitted' : ''}
            {y.min !== y.max && axisLabel(y.min, false, true) === axisLabel(y.max, false, true) && <span> · range {String(y.min)}–{String(y.max)}</span>}
        </figcaption>
    </figure>;
}
