import importlib.util
import io
import pathlib
import unittest
from contextlib import redirect_stdout


MODULE_PATH = pathlib.Path(__file__).with_name("compare_handoffs.py")
SPEC = importlib.util.spec_from_file_location("compare_handoffs", MODULE_PATH)
compare = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(compare)


def snapshot(url, text, completed=0.0):
    return {
        "url": url,
        "started_monotonic_seconds": completed - 0.01,
        "completed_monotonic_seconds": completed,
        "scrape_seconds": 0.01,
        "metrics": compare.parse_metrics(text),
    }


def metrics(height, count, total, buckets, events="", abandoned=""):
    lines = [f"{compare.HEIGHT} {height}"]
    for base in compare.HISTOGRAMS:
        lines.extend((f"{base}_count {count}", f"{base}_sum {total}"))
        lines.extend(f'{base}_bucket{{le="{bound}"}} {value}' for bound, value in buckets)
    if events:
        lines.append(f'{compare.EVENTS}{{event="Requested"}} {events}')
    if abandoned:
        lines.append(f'{compare.ABANDONED}{{reason="ViewExit"}} {abandoned}')
    return "\n".join(lines)


class CompareHandoffsTests(unittest.TestCase):
    def test_build_timings_capture_delay_and_reject_partial_fleet(self):
        def samples(height, count, total):
            text = metrics(height, count, total, [("0.1", count), ("+Inf", count)])
            for metric in compare.BUILD_HISTOGRAMS:
                text += (f'\n{metric}_count {count}\n{metric}_sum {total}'
                         f'\n{metric}_bucket{{le="0.1"}} {count}'
                         f'\n{metric}_bucket{{le="+Inf"}} {count}')
            return text
        before = [snapshot("a", samples(1, 1, .05), 1)]
        after = [snapshot("a", samples(3, 3, .15), 2)]
        result = compare.summarize_chain("baseline", before, after)
        self.assertAlmostEqual(result["build_timings"][compare.BUILD_HISTOGRAMS[1]]["mean_seconds"], .05)
        before.append(snapshot("b", metrics(1, 1, .05, [("0.1", 1), ("+Inf", 1)]), 1))
        after.append(snapshot("b", metrics(3, 3, .15, [("0.1", 3), ("+Inf", 3)]), 2))
        with self.assertRaisesRegex(compare.MeasurementError, "missing required histogram"):
            compare.summarize_chain("baseline", before, after)

    def test_chain_validation_allows_single_chain(self):
        compare.validate_chains([("baseline", ["http://a/metrics", "http://b/metrics"])])

    def test_chain_validation_rejects_unequal_node_counts(self):
        with self.assertRaisesRegex(compare.MeasurementError, "equal primary endpoint counts"):
            compare.validate_chains([
                ("baseline", ["http://a/metrics"]),
                ("early", ["http://b/metrics", "http://c/metrics"]),
            ])

    def test_chain_validation_rejects_cross_chain_endpoint_reuse(self):
        with self.assertRaisesRegex(compare.MeasurementError, "shared by chains"):
            compare.validate_chains([
                ("baseline", ["http://a/metrics"]),
                ("early", ["http://a/metrics"]),
            ])

    def test_aggregates_nodes_and_uses_actual_height_elapsed(self):
        before = [
            snapshot("a", metrics(100, 2, 0.3, [("0.1", 1), ("0.5", 2), ("+Inf", 2)], 3), 10),
            snapshot("b", metrics(99, 1, 0.2, [("0.1", 0), ("0.5", 1), ("+Inf", 1)], 2), 10),
        ]
        after = [
            snapshot("a", metrics(120, 5, 1.2, [("0.1", 2), ("0.5", 5), ("+Inf", 5)], 8), 20),
            snapshot("b", metrics(119, 3, 0.8, [("0.1", 1), ("0.5", 3), ("+Inf", 3)], 5, 1), 20.4),
        ]
        result = compare.summarize_chain("baseline", before, after)
        self.assertEqual(result["finalized_height"]["delta"], 20)
        self.assertEqual(result["finalized_blocks_per_second"], 2)
        histogram = result["notarization_latency_from_view_entry"]
        self.assertEqual(histogram["samples"], 5)
        self.assertAlmostEqual(histogram["mean_seconds"], 0.3)
        self.assertEqual(histogram["p50_bucket_upper_bound_seconds"], 0.5)
        self.assertEqual(result["handoff_event_deltas"], {"Requested": 8})
        self.assertEqual(result["handoff_abandoned_deltas"], {"ViewExit": 1})

    def test_counter_reset_is_rejected(self):
        before = snapshot("a", metrics(1, 2, 0.2, [("1", 2), ("+Inf", 2)], 5))
        after = snapshot("a", metrics(2, 3, 0.3, [("1", 3), ("+Inf", 3)], 4))
        with self.assertRaisesRegex(compare.MeasurementError, "reset"):
            compare.aggregate_family_delta([before], [after], compare.EVENTS, "event")

    def test_missing_histogram_is_not_zero(self):
        before = snapshot("a", metrics(1, 0, 0, [("1", 0), ("+Inf", 0)]))
        final_text = metrics(2, 1, 0.2, [("1", 1), ("+Inf", 1)])
        final_text = "\n".join(
            line for line in final_text.splitlines()
            if not line.startswith(compare.HISTOGRAMS[0] + "_bucket")
        )
        after = snapshot("a", final_text)
        with self.assertRaisesRegex(compare.MeasurementError, "missing required histogram"):
            compare.aggregate_histogram([before], [after], compare.HISTOGRAMS[0])

    def test_baseline_preflight_rejects_missing_histogram(self):
        text = metrics(1, 0, 0, [("1", 0), ("+Inf", 0)])
        text = "\n".join(
            line for line in text.splitlines()
            if not line.startswith(compare.HISTOGRAMS[1] + "_sum")
        )
        with self.assertRaisesRegex(compare.MeasurementError, "missing required histogram"):
            compare.validate_baseline("old-build", [snapshot("a", text)])

    def test_histogram_reset_is_rejected(self):
        before = snapshot("a", metrics(1, 3, 0.5, [("1", 3), ("+Inf", 3)]))
        after = snapshot("a", metrics(2, 2, 0.4, [("1", 2), ("+Inf", 2)]))
        with self.assertRaisesRegex(compare.MeasurementError, "reset"):
            compare.aggregate_histogram([before], [after], compare.HISTOGRAMS[0])

    def test_quantile_is_bucket_upper_bound_and_inf_is_unknown(self):
        buckets = [(0.1, 1), (0.5, 8), (float("inf"), 10)]
        self.assertEqual(compare.bucket_quantile_upper_bound(buckets, 10, 0.5), 0.5)
        self.assertIsNone(compare.bucket_quantile_upper_bound(buckets, 10, 0.95))
        self.assertIsNone(compare.bucket_quantile_upper_bound(buckets, 0, 0.5))

    def test_height_reset_is_rejected(self):
        before = [snapshot("a", metrics(10, 0, 0, [("1", 0), ("+Inf", 0)]), 1)]
        after = [snapshot("a", metrics(9, 0, 0, [("1", 0), ("+Inf", 0)]), 2)]
        with self.assertRaisesRegex(compare.MeasurementError, "reset"):
            compare.summarize_chain("x", before, after)

    def test_label_parser_handles_escapes(self):
        parsed = compare.parse_metrics('metric_ignored 1\n' + compare.EVENTS + r'{event="A\"B"} 2')
        self.assertEqual(next(iter(parsed[compare.EVENTS])), (("event", 'A"B'),))

    def test_nonfinite_durations_are_rejected(self):
        for value in ("nan", "inf", "-inf"):
            with self.assertRaises(Exception):
                compare.positive(value)
            with self.assertRaises(Exception):
                compare.nonnegative(value)

    def test_console_table_shows_handoff_lifecycle(self):
        result = {
            "finalized_blocks_per_second": 2.0,
            "mean_finalized_interval_seconds": 0.5,
            "notarization_latency_from_view_entry": {
                "mean_seconds": 0.1,
                "p50_bucket_upper_bound_seconds": 0.2,
                "p95_bucket_upper_bound_seconds": 0.5,
            },
            "finalization_latency_from_view_entry": {
                "mean_seconds": 0.2,
                "p50_bucket_upper_bound_seconds": 0.5,
                "p95_bucket_upper_bound_seconds": 1.0,
            },
            "handoff_event_deltas": {
                "Requested": 10,
                "CandidateReturned": 9,
                "Held": 8,
                "PublishedBeforeCertification": 7,
                "PublishedAfterCertification": 1,
            },
            "handoff_abandoned_deltas": {"ViewExit": 2},
        }
        output = io.StringIO()
        with redirect_stdout(output):
            compare.print_table({"build-and-broadcast": result})
        self.assertIn("handoffs req/returned/held/early/after", output.getvalue())
        self.assertIn("10/9/8/7/1", output.getvalue())


if __name__ == "__main__":
    unittest.main()
