#!/usr/bin/env python3
"""Compare live Constantinople handoff modes using Prometheus snapshots."""

from __future__ import annotations

import argparse
import concurrent.futures
import datetime as dt
import json
import math
import re
import sys
import time
import urllib.error
import urllib.request
from collections import defaultdict
from pathlib import Path


HEIGHT = "engine_marshal_finalized_height"
HISTOGRAMS = (
    "engine_simplex_voter_notarization_latency_from_view_entry",
    "engine_simplex_voter_finalization_latency_from_view_entry",
)
EVENTS = "engine_simplex_voter_handoff_events_total"
ABANDONED = "engine_simplex_voter_handoff_abandoned_total"
BUILD_HISTOGRAMS = (
    "engine_application_proposal_build_duration",
    "engine_application_proposal_build_delay_duration",
)
RELEVANT_PREFIXES = (HEIGHT, *HISTOGRAMS, *BUILD_HISTOGRAMS,
                     "engine_simplex_voter_handoff_", EVENTS, ABANDONED)
SAMPLE_RE = re.compile(
    r"^([a-zA-Z_:][a-zA-Z0-9_:]*)(?:\{(.*)\})?\s+([^\s]+)(?:\s+\d+)?$"
)
LABEL_RE = re.compile(r'([a-zA-Z_][a-zA-Z0-9_]*)="((?:\\.|[^"\\])*)"(?:,|$)')


class MeasurementError(RuntimeError):
    """The measurement cannot produce a trustworthy comparison."""


def parse_labels(raw: str | None) -> tuple[tuple[str, str], ...]:
    if not raw:
        return ()
    labels: list[tuple[str, str]] = []
    position = 0
    while position < len(raw):
        match = LABEL_RE.match(raw, position)
        if not match:
            raise MeasurementError(f"malformed Prometheus labels: {raw!r}")
        value = re.sub(
            r"\\([\\\"n])",
            lambda found: "\n" if found.group(1) == "n" else found.group(1),
            match.group(2),
        )
        labels.append((match.group(1), value))
        position = match.end()
    return tuple(sorted(labels))


def parse_metrics(text: str) -> dict[str, dict[tuple[tuple[str, str], ...], float]]:
    """Parse relevant Prometheus text samples into a stable mapping."""
    metrics: dict[str, dict[tuple[tuple[str, str], ...], float]] = defaultdict(dict)
    for line_number, line in enumerate(text.splitlines(), 1):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        match = SAMPLE_RE.match(line)
        if not match:
            continue  # Ignore exemplars and OpenMetrics constructs we do not consume.
        name = match.group(1)
        if not name.startswith(RELEVANT_PREFIXES):
            continue
        labels = parse_labels(match.group(2))
        try:
            value = float(match.group(3))
        except ValueError as exc:
            raise MeasurementError(
                f"invalid value for {name} on line {line_number}: {match.group(3)!r}"
            ) from exc
        if not math.isfinite(value):
            raise MeasurementError(f"non-finite value for {name} on line {line_number}")
        if labels in metrics[name]:
            raise MeasurementError(f"duplicate series for {name}{dict(labels)}")
        metrics[name][labels] = value
    return dict(metrics)


def normalize_url(url: str) -> str:
    url = url.strip().rstrip("/")
    if not url:
        raise argparse.ArgumentTypeError("metrics URL must not be empty")
    if not url.startswith(("http://", "https://")):
        raise argparse.ArgumentTypeError(f"metrics URL needs http:// or https://: {url}")
    return f"{url}/metrics" if "/" not in url.split("://", 1)[1] else url


def parse_chain(value: str) -> tuple[str, list[str]]:
    try:
        name, raw_urls = value.split("=", 1)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("chain must be NAME=URL,URL,...") from exc
    name = name.strip()
    if not name:
        raise argparse.ArgumentTypeError("chain name must not be empty")
    urls = [normalize_url(url) for url in raw_urls.split(",") if url.strip()]
    if not urls:
        raise argparse.ArgumentTypeError(f"chain {name!r} has no metrics URLs")
    if len(set(urls)) != len(urls):
        raise argparse.ArgumentTypeError(f"chain {name!r} repeats a metrics URL")
    return name, urls


def validate_chains(chains: list[tuple[str, list[str]]]) -> None:
    """Reject comparisons whose endpoint sets are not directly comparable."""
    names = [name for name, _ in chains]
    if len(set(names)) != len(names):
        raise MeasurementError("--chain names must be unique")
    counts = {len(urls) for _, urls in chains}
    if len(counts) != 1:
        detail = ", ".join(f"{name}={len(urls)}" for name, urls in chains)
        raise MeasurementError(f"chains must have equal primary endpoint counts: {detail}")
    owners: dict[str, str] = {}
    for name, urls in chains:
        for url in urls:
            if url in owners:
                raise MeasurementError(
                    f"metrics URL {url} is shared by chains {owners[url]!r} and {name!r}"
                )
            owners[url] = name


def fetch(url: str, timeout: float) -> dict[str, object]:
    started = time.monotonic()
    try:
        with urllib.request.urlopen(url, timeout=timeout) as response:
            if response.status != 200:
                raise MeasurementError(f"{url}: HTTP {response.status}")
            body = response.read().decode("utf-8")
    except (OSError, UnicodeError, urllib.error.URLError) as exc:
        raise MeasurementError(f"{url}: scrape failed: {exc}") from exc
    completed = time.monotonic()
    return {
        "url": url,
        "started_monotonic_seconds": started,
        "completed_monotonic_seconds": completed,
        "scrape_seconds": completed - started,
        "metrics": parse_metrics(body),
    }


def scrape_all(chains: list[tuple[str, list[str]]], timeout: float) -> dict[str, list[dict[str, object]]]:
    targets = [(name, index, url) for name, urls in chains for index, url in enumerate(urls)]
    results: dict[str, list[dict[str, object] | None]] = {
        name: [None] * len(urls) for name, urls in chains
    }
    with concurrent.futures.ThreadPoolExecutor(max_workers=len(targets)) as executor:
        futures = {
            executor.submit(fetch, url, timeout): (name, index)
            for name, index, url in targets
        }
        for future in concurrent.futures.as_completed(futures):
            name, index = futures[future]
            results[name][index] = future.result()
    return {name: [item for item in nodes if item is not None] for name, nodes in results.items()}


def one_value(snapshot: dict[str, object], metric: str) -> float:
    series = snapshot["metrics"].get(metric, {})  # type: ignore[union-attr]
    if len(series) != 1:
        raise MeasurementError(
            f"{snapshot['url']}: expected exactly one {metric} series, found {len(series)}"
        )
    return next(iter(series.values()))


def validate_baseline(name: str, nodes: list[dict[str, object]]) -> None:
    """Fail before the measurement wait when an endpoint lacks required inputs."""
    if not nodes:
        raise MeasurementError(f"{name}: no node snapshots")
    one_value(nodes[0], HEIGHT)
    for node in nodes:
        node_metrics = node["metrics"]
        for metric in HISTOGRAMS:
            for suffix in ("_count", "_sum", "_bucket"):
                sample_name = metric + suffix
                if sample_name not in node_metrics:
                    raise MeasurementError(
                        f"{node['url']}: missing required histogram metric {sample_name}"
                    )


def checked_delta(before: float, after: float, description: str) -> float:
    if after < before:
        raise MeasurementError(f"{description} reset: baseline={before}, final={after}")
    return after - before


def aggregate_histogram(
    baseline: list[dict[str, object]], final: list[dict[str, object]], metric: str
) -> dict[str, object]:
    count = 0.0
    total = 0.0
    buckets: dict[float, float] = defaultdict(float)
    for before, after in zip(baseline, final, strict=True):
        before_metrics = before["metrics"]  # type: ignore[assignment]
        after_metrics = after["metrics"]  # type: ignore[assignment]
        for suffix in ("_count", "_sum", "_bucket"):
            name = metric + suffix
            if name not in before_metrics or name not in after_metrics:
                raise MeasurementError(f"{after['url']}: missing required histogram metric {name}")
            if set(before_metrics[name]) != set(after_metrics[name]):
                raise MeasurementError(f"{after['url']}: histogram series changed for {name}")
        count += sum(
            checked_delta(before_metrics[metric + "_count"][labels], value, f"{after['url']} {metric}_count")
            for labels, value in after_metrics[metric + "_count"].items()
        )
        total += sum(
            checked_delta(before_metrics[metric + "_sum"][labels], value, f"{after['url']} {metric}_sum")
            for labels, value in after_metrics[metric + "_sum"].items()
        )
        for labels, value in after_metrics[metric + "_bucket"].items():
            label_map = dict(labels)
            if "le" not in label_map:
                raise MeasurementError(f"{after['url']}: {metric}_bucket lacks le label")
            try:
                bound = float(label_map["le"])
            except ValueError as exc:
                raise MeasurementError(f"{after['url']}: invalid bucket bound {label_map['le']!r}") from exc
            buckets[bound] += checked_delta(
                before_metrics[metric + "_bucket"][labels], value, f"{after['url']} {metric}_bucket"
            )

    ordered = sorted(buckets.items())
    if not ordered or not math.isinf(ordered[-1][0]):
        raise MeasurementError(f"{metric}: histogram has no +Inf bucket")
    previous = -1.0
    for bound, cumulative in ordered:
        if cumulative < previous:
            raise MeasurementError(f"{metric}: delta buckets are not cumulative at {bound}")
        previous = cumulative
    if not math.isclose(ordered[-1][1], count, rel_tol=1e-9, abs_tol=1e-9):
        raise MeasurementError(f"{metric}: +Inf bucket delta does not match count delta")

    return {
        "samples": count,
        "sum_seconds": total,
        "mean_seconds": total / count if count else None,
        "p50_bucket_upper_bound_seconds": bucket_quantile_upper_bound(ordered, count, 0.50),
        "p95_bucket_upper_bound_seconds": bucket_quantile_upper_bound(ordered, count, 0.95),
        "bucket_deltas": [
            {"le": "+Inf" if math.isinf(bound) else bound, "count": value}
            for bound, value in ordered
        ],
    }


def bucket_quantile_upper_bound(
    buckets: list[tuple[float, float]], count: float, quantile: float
) -> float | None:
    """Return the containing finite bucket's upper bound, not an interpolated quantile."""
    if count <= 0:
        return None
    target = count * quantile
    for bound, cumulative in buckets:
        if cumulative >= target:
            return None if math.isinf(bound) else bound
    raise MeasurementError("histogram buckets do not cover the sample count")


def aggregate_family_delta(
    baseline: list[dict[str, object]],
    final: list[dict[str, object]],
    metric: str,
    grouping_label: str,
) -> dict[str, float]:
    totals: dict[str, float] = defaultdict(float)
    for before, after in zip(baseline, final, strict=True):
        before_series = before["metrics"].get(metric, {})  # type: ignore[union-attr]
        after_series = after["metrics"].get(metric, {})  # type: ignore[union-attr]
        missing = set(before_series) - set(after_series)
        if missing:
            raise MeasurementError(f"{after['url']}: counter series disappeared from {metric}")
        for labels, value in after_series.items():
            label_map = dict(labels)
            if grouping_label not in label_map:
                raise MeasurementError(f"{after['url']}: {metric} lacks {grouping_label} label")
            totals[label_map[grouping_label]] += checked_delta(
                before_series.get(labels, 0.0), value, f"{after['url']} {metric}{label_map}"
            )
    return dict(sorted(totals.items()))


def serializable_snapshot(snapshot: dict[str, object]) -> dict[str, object]:
    saved: dict[str, list[dict[str, object]]] = {}
    for name, series in sorted(snapshot["metrics"].items()):  # type: ignore[union-attr]
        saved[name] = [
            {"labels": dict(labels), "value": value}
            for labels, value in sorted(series.items())
        ]
    return {
        "url": snapshot["url"],
        "started_monotonic_seconds": snapshot["started_monotonic_seconds"],
        "completed_monotonic_seconds": snapshot["completed_monotonic_seconds"],
        "scrape_seconds": snapshot["scrape_seconds"],
        "metrics": saved,
    }


def summarize_chain(
    name: str, baseline: list[dict[str, object]], final: list[dict[str, object]]
) -> dict[str, object]:
    height_before = one_value(baseline[0], HEIGHT)
    height_after = one_value(final[0], HEIGHT)
    height_delta = checked_delta(height_before, height_after, f"{name} designated finalized height")
    elapsed = (
        final[0]["completed_monotonic_seconds"] - baseline[0]["completed_monotonic_seconds"]
    )
    if elapsed <= 0:
        raise MeasurementError(f"{name}: non-positive measurement elapsed time")
    rate = height_delta / elapsed
    build_timings = {
        metric: aggregate_histogram(baseline, final, metric)
        for metric in BUILD_HISTOGRAMS
        if any(any(name.startswith(metric + "_") for name in node["metrics"])
               for node in [*baseline, *final])
    }
    return {
        "designated_height_node": baseline[0]["url"],
        "measurement_elapsed_seconds": elapsed,
        "finalized_height": {
            "baseline": height_before,
            "final": height_after,
            "delta": height_delta,
        },
        "finalized_blocks_per_second": rate,
        "build_timings": build_timings,
        "mean_finalized_interval_seconds": 1.0 / rate if rate else None,
        "notarization_latency_from_view_entry": aggregate_histogram(
            baseline, final, HISTOGRAMS[0]
        ),
        "finalization_latency_from_view_entry": aggregate_histogram(
            baseline, final, HISTOGRAMS[1]
        ),
        "handoff_event_deltas": aggregate_family_delta(baseline, final, EVENTS, "event"),
        "handoff_abandoned_deltas": aggregate_family_delta(
            baseline, final, ABANDONED, "reason"
        ),
        "snapshots": {
            "baseline": [serializable_snapshot(node) for node in baseline],
            "final": [serializable_snapshot(node) for node in final],
        },
    }


def number(value: object, digits: int = 3) -> str:
    return "-" if value is None else f"{float(value):.{digits}f}"


def print_table(chains: dict[str, dict[str, object]]) -> None:
    headers = (
        "chain",
        "blk/s",
        "interval ms",
        "notarize mean/p50/p95 ms",
        "finalize mean/p50/p95 ms",
        "handoffs req/returned/held/early/after",
        "abandoned",
    )
    rows = []
    for name, result in chains.items():
        notarize = result["notarization_latency_from_view_entry"]
        finalize = result["finalization_latency_from_view_entry"]
        events = result["handoff_event_deltas"]
        latency = lambda data: "/".join(  # noqa: E731 - compact table formatter
            number(None if data[key] is None else data[key] * 1000, 1)
            for key in ("mean_seconds", "p50_bucket_upper_bound_seconds", "p95_bucket_upper_bound_seconds")
        )
        rows.append((
            name,
            number(result["finalized_blocks_per_second"]),
            number(None if result["mean_finalized_interval_seconds"] is None else result["mean_finalized_interval_seconds"] * 1000, 1),
            latency(notarize),
            latency(finalize),
            "/".join(
                number(events.get(event, 0.0), 0)
                for event in (
                    "Requested",
                    "CandidateReturned",
                    "Held",
                    "PublishedBeforeCertification",
                    "PublishedAfterCertification",
                )
            ),
            number(sum(result["handoff_abandoned_deltas"].values()), 0),
        ))
    widths = [max(len(str(value)) for value in column) for column in zip(headers, *rows, strict=True)]
    print("  ".join(str(value).ljust(width) for value, width in zip(headers, widths, strict=True)))
    print("  ".join("-" * width for width in widths))
    for row in rows:
        print("  ".join(str(value).ljust(width) for value, width in zip(row, widths, strict=True)))
    print("Latency p50/p95 values are observed Prometheus bucket upper bounds (not exact quantiles).")


def positive(value: str) -> float:
    parsed = float(value)
    if not math.isfinite(parsed) or parsed <= 0:
        raise argparse.ArgumentTypeError("must be a finite number greater than zero")
    return parsed


def nonnegative(value: str) -> float:
    parsed = float(value)
    if not math.isfinite(parsed) or parsed < 0:
        raise argparse.ArgumentTypeError("must be a finite non-negative number")
    return parsed


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--chain", action="append", required=True, type=parse_chain,
        help="chain and every primary metrics endpoint: NAME=URL,URL,... (repeat for each mode)",
    )
    parser.add_argument("--warmup", type=nonnegative, default=30.0, help="warmup seconds (default: 30)")
    parser.add_argument("--duration", type=positive, default=300.0, help="measurement seconds (default: 300)")
    parser.add_argument("--timeout", type=positive, default=10.0, help="per-scrape timeout seconds (default: 10)")
    parser.add_argument("--output", type=Path, default=Path("handoff-comparison.json"), help="JSON output path")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    names = [name for name, _ in args.chain]
    try:
        validate_chains(args.chain)
        if args.warmup:
            print(f"Warming all chains for {args.warmup:g}s...", file=sys.stderr)
            time.sleep(args.warmup)
        baseline = scrape_all(args.chain, args.timeout)
        for name in names:
            validate_baseline(name, baseline[name])
        print(f"Measuring for {args.duration:g}s...", file=sys.stderr)
        time.sleep(args.duration)
        final = scrape_all(args.chain, args.timeout)
        summaries = {
            name: summarize_chain(name, baseline[name], final[name]) for name in names
        }
        report = {
            "schema_version": 1,
            "generated_at_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
            "expected_commonware_commit": "8d5a87ecf49130dab67fb1a062d4413fd8663995",
            "configuration": {
                "requested_warmup_seconds": args.warmup,
                "requested_duration_seconds": args.duration,
                "scrape_timeout_seconds": args.timeout,
                "height_source_rule": "first URL in each --chain",
                "latency_quantiles": "upper bound of the containing cumulative Prometheus bucket",
                "provenance_note": "expected source commit supplied by the operator; not discovered from endpoints",
            },
            "chains": summaries,
        }
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        print_table(summaries)
        print(f"JSON: {args.output}")
        return 0
    except (MeasurementError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
