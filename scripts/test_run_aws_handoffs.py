import importlib.util
import json
import pathlib
import subprocess
import sys
import tempfile
import unittest
from collections import Counter
from unittest import mock


MODULE_PATH = pathlib.Path(__file__).with_name("run_aws_handoffs.py")
SPEC = importlib.util.spec_from_file_location("run_aws_handoffs", MODULE_PATH)
runner = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
sys.modules[SPEC.name] = runner
SPEC.loader.exec_module(runner)


class RunAwsHandoffsTests(unittest.TestCase):
    def test_delay_treatment_requires_measured_evidence_on_each_node(self):
        names = ["engine_application_proposal_build_duration",
                 "engine_application_proposal_build_delay_duration"]
        def node(count, seconds):
            return {"metrics": {name + suffix: [{"value": value}]
                    for name in names for suffix, value in [("_count", count), ("_sum", seconds)]}}
        report = {"build_timings": {name: {} for name in names},
                  "snapshots": {"baseline": [node(1, .05)], "final": [node(3, .15)]}}
        runner.validate_build_delay(report, 50)
        with self.assertRaisesRegex(runner.RunnerError, "below"):
            runner.validate_build_delay(report, 100)
        report["snapshots"]["final"][0]["metrics"].pop(names[0] + "_sum")
        with self.assertRaisesRegex(runner.RunnerError, "absent"):
            runner.validate_build_delay(report, 50)
        report["build_timings"] = {}
        with self.assertRaisesRegex(runner.RunnerError, "absent"):
            runner.validate_build_delay(report, 50)

    def test_delay_treatment_rejects_omitted_config(self):
        with tempfile.TemporaryDirectory() as temporary:
            manifest = runner.load_manifest(self._manifest(pathlib.Path(temporary)))
            experiment = runner.Runner(manifest, 120, 600, 1, expected_build_delay_ms=50)
            with self.assertRaisesRegex(runner.RunnerError, "expected build delay"):
                experiment.freeze_configs()

    def test_default_schedule_runs_each_mode_once(self):
        args = runner.build_parser().parse_args(["--manifest", "/tmp/manifest.json"])
        self.assertEqual(runner.scheduled_runs(args.rounds, args.start_run), [
            (1, 1, "baseline"), (2, 1, "build_only"), (3, 1, "build_and_broadcast"),
        ])

    def test_rewrite_changes_only_mode_and_partition(self):
        source = (
            "private_key: secret\n"
            "handoff_mode: baseline\n"
            "partition_prefix: validator-0\n"
            "worker_threads: 2\n"
        )
        rendered = runner.rewrite_validator_config(
            source, "build_and_broadcast", "bench-run-01-00"
        )
        self.assertEqual(
            rendered,
            "private_key: secret\n"
            "handoff_mode: build_and_broadcast\n"
            "partition_prefix: bench-run-01-00\n"
            "worker_threads: 2\n",
        )

    def test_rewrite_requires_exactly_one_managed_field(self):
        with self.assertRaisesRegex(runner.RunnerError, "exactly one"):
            runner.rewrite_validator_config(
                "handoff_mode: baseline\n", "build_only", "bench-run"
            )

    def test_rotated_order(self):
        self.assertEqual(
            runner.rotated_runs(3),
            [
                (1, "baseline"), (1, "build_only"), (1, "build_and_broadcast"),
                (2, "build_only"), (2, "build_and_broadcast"), (2, "baseline"),
                (3, "build_and_broadcast"), (3, "baseline"), (3, "build_only"),
            ],
        )

    def test_start_run_selects_remaining_rotated_runs(self):
        self.assertEqual(
            runner.scheduled_runs(3, 2),
            [
                (2, 1, "build_only"), (3, 1, "build_and_broadcast"),
                (4, 2, "build_only"), (5, 2, "build_and_broadcast"),
                (6, 2, "baseline"), (7, 3, "build_and_broadcast"),
                (8, 3, "baseline"), (9, 3, "build_only"),
            ],
        )
        with self.assertRaisesRegex(runner.RunnerError, "between 1 and 9"):
            runner.scheduled_runs(3, 10)

    def _manifest(self, directory: pathlib.Path) -> pathlib.Path:
        key = directory / "key"
        key.write_text("test", encoding="utf-8")
        key.chmod(0o600)
        nodes = []
        for index in range(7):
            config = directory / f"node-{index}.yaml"
            config.write_text(
                f"private_key: secret-{index}\n"
                f"handoff_mode: baseline\npartition_prefix: validator-{index}\n",
                encoding="utf-8",
            )
            nodes.append({
                "name": f"node-{index}",
                "ip": f"192.0.2.{index + 1}",
                "region": ("us-east-1", "us-west-2", "eu-west-1", "ap-southeast-1")[index % 4],
                "config": str(config),
            })
        manifest = directory / "manifest.json"
        manifest.write_text(json.dumps({
            "tag": "handoff-test",
            "key": str(key),
            "monitor_ip": "198.51.100.1",
            "expected_binary_sha256": "a" * 64,
            "nodes": nodes,
            "output_dir": str(directory / "output"),
        }), encoding="utf-8")
        return manifest

    def test_manifest_validation_accepts_exact_contract(self):
        with tempfile.TemporaryDirectory() as temporary:
            manifest = runner.load_manifest(self._manifest(pathlib.Path(temporary)))
            self.assertEqual(len(manifest.nodes), 7)
            self.assertEqual(manifest.tag, "handoff-test")

    def test_manifest_validation_rejects_duplicate_ip(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = self._manifest(pathlib.Path(temporary))
            raw = json.loads(path.read_text(encoding="utf-8"))
            raw["nodes"][1]["ip"] = raw["nodes"][0]["ip"]
            path.write_text(json.dumps(raw), encoding="utf-8")
            with self.assertRaisesRegex(runner.RunnerError, "IPs must be unique"):
                runner.load_manifest(path)

    def test_supervision_must_remain_identical(self):
        text = (
            "MainPID=42\n"
            "ExecMainStartTimestampMonotonic=1234\n"
            "NRestarts=0\n"
            "ActiveState=active\n"
        )
        before = runner.parse_supervision(text)
        runner.verify_supervision(before, dict(before))
        after = dict(before)
        after["NRestarts"] = "1"
        with self.assertRaisesRegex(runner.RunnerError, "NRestarts"):
            runner.verify_supervision(before, after)

    def test_supervision_rejects_inactive_service(self):
        text = (
            "MainPID=0\n"
            "ExecMainStartTimestampMonotonic=1234\n"
            "NRestarts=1\n"
            "ActiveState=inactive\n"
        )
        with self.assertRaisesRegex(runner.RunnerError, "not actively supervised"):
            runner.parse_supervision(text)

    def test_stop_all_allows_systemd_timeout_stop_sec(self):
        with tempfile.TemporaryDirectory() as temporary:
            manifest = runner.load_manifest(self._manifest(pathlib.Path(temporary)))
            campaign = runner.Runner(manifest, 0, 1, 1)
            calls = []

            def fake_ssh(ip, argv, timeout=runner.SSH_TIMEOUT, check=True):
                calls.append((ip, argv, timeout, check))
                output = "inactive\n" if argv == ["systemctl", "is-active", "binary"] else ""
                return subprocess.CompletedProcess(argv, 0, output, "")

            campaign._ssh = fake_ssh
            campaign.stop_all()
            stops = [call for call in calls if call[1] == ["sudo", "systemctl", "stop", "binary"]]
            self.assertEqual(len(stops), 7)
            self.assertTrue(all(call[2] == 120.0 for call in stops))

    def test_configs_are_rendered_from_campaign_snapshot(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = pathlib.Path(temporary)
            manifest = runner.load_manifest(self._manifest(directory))
            campaign = runner.Runner(manifest, 0, 1, 1)
            original = manifest.nodes[0].config.read_bytes()
            campaign.freeze_configs()
            manifest.nodes[0].config.write_text(
                "private_key: changed\nhandoff_mode: baseline\n"
                "partition_prefix: changed\n",
                encoding="utf-8",
            )
            configs = campaign._make_configs(directory / "rendered", "build_only", 1)
            rendered = configs[manifest.nodes[0].name][0].read_text(encoding="utf-8")
            self.assertIn("private_key: secret-0\n", rendered)
            self.assertNotIn("private_key: changed\n", rendered)
            self.assertEqual(
                campaign.input_config_sha256[manifest.nodes[0].name],
                runner.hashlib.sha256(original).hexdigest(),
            )

    def test_each_run_hashes_binary_after_install_and_before_start(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = pathlib.Path(temporary)
            manifest = runner.load_manifest(self._manifest(directory))
            campaign = runner.Runner(manifest, 0, 1, 1)
            campaign.freeze_configs()
            events = []
            expected_hashes = {
                node.name: manifest.expected_binary_sha256 for node in manifest.nodes
            }

            campaign.stage_configs = lambda configs: events.append("stage")
            campaign.stop_all = lambda: events.append("stop")
            campaign.install_configs = lambda configs, mode: events.append("install")

            def verify_binaries():
                events.append("verify")
                return dict(expected_hashes)

            campaign.verify_binaries = verify_binaries
            campaign.start_all = lambda: events.append("start")
            campaign.await_readiness = lambda: [20.0] * 7
            supervision = {
                node.name: {
                    "MainPID": "42",
                    "ExecMainStartTimestampMonotonic": "1234",
                    "NRestarts": "0",
                    "ActiveState": "active",
                }
                for node in manifest.nodes
            }
            campaign.supervision = lambda: supervision
            campaign.collect = lambda run_dir, run_id, mode: None

            campaign.run_one(1, "baseline", 1)
            campaign.run_one(2, "build_only", 2)
            self.assertEqual(
                events,
                ["stage", "stop", "install", "verify", "start"] * 2,
            )
            for round_number, mode in ((1, "baseline"), (2, "build_only")):
                run_id = f"{campaign.campaign_id}-r{round_number:02d}-{mode}"
                status = json.loads(
                    (manifest.output_dir / run_id / "status.json").read_text(encoding="utf-8")
                )
                self.assertEqual(status["binary_sha256"], expected_hashes)
                self.assertEqual(
                    status["provenance"]["input_config_sha256"],
                    campaign.input_config_sha256,
                )
                self.assertNotIn("secret-0", json.dumps(status))

    def test_control_ssh_retries_exit_255(self):
        with tempfile.TemporaryDirectory() as temporary:
            manifest = runner.load_manifest(self._manifest(pathlib.Path(temporary)))
            campaign = runner.Runner(manifest, 0, 1, 1)
            results = iter([
                subprocess.CompletedProcess(["ssh"], 255, "", "timeout"),
                subprocess.CompletedProcess(["ssh"], 255, "", "timeout"),
                subprocess.CompletedProcess(["ssh"], 0, "ok\n", ""),
            ])
            calls = []

            def fake_run(argv, timeout, check=True):
                calls.append((argv, timeout, check))
                return next(results)

            campaign._run = fake_run
            with mock.patch.object(runner.time, "sleep") as sleep:
                result = campaign._ssh(manifest.nodes[0].ip, ["true"])
            self.assertEqual(result.stdout, "ok\n")
            self.assertEqual(len(calls), 3)
            self.assertEqual(sleep.call_count, 2)
            self.assertEqual(
                [item["reason"] for item in campaign.transport_retry_diagnostics],
                ["exit_255", "exit_255"],
            )
            self.assertNotIn("true", json.dumps(campaign.transport_retry_diagnostics))

    def test_collection_ssh_does_not_retry(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = pathlib.Path(temporary)
            manifest = runner.load_manifest(self._manifest(directory))
            campaign = runner.Runner(manifest, 0, 1, 1)
            calls = []

            def fake_run(argv, timeout, check=True):
                calls.append(argv)
                return subprocess.CompletedProcess(argv, 255, "", "timeout")

            campaign._run = fake_run
            with self.assertRaisesRegex(runner.RunnerError, "after 1 attempt"):
                campaign.collect(directory, "run-1", "baseline")
            self.assertEqual(len(calls), 1)
            self.assertEqual(campaign.transport_retry_diagnostics[0]["max_attempts"], 1)

    def test_install_config_is_repeatable_before_start(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = pathlib.Path(temporary)
            manifest = runner.load_manifest(self._manifest(directory))
            campaign = runner.Runner(manifest, 0, 1, 1)
            campaign.freeze_configs()
            configs = campaign._make_configs(directory / "rendered", "build_only", 1)
            scripts = []

            def fake_ssh(ip, argv, timeout=runner.SSH_TIMEOUT, check=True,
                         attempts=runner.TRANSPORT_ATTEMPTS):
                scripts.append(argv[-1])
                node = next(node for node in manifest.nodes if node.ip == ip)
                digest = runner._sha256(configs[node.name][0])
                return subprocess.CompletedProcess(argv, 0, f"{digest}  config.conf\n", "")

            campaign._ssh = fake_ssh
            campaign.install_configs(configs, "build_only")
            campaign.install_configs(configs, "build_only")
            self.assertEqual(len(scripts), 14)
            self.assertTrue(all("rm -f" not in script for script in scripts))
            self.assertTrue(all("test ! -e" in script for script in scripts))
            self.assertEqual(set(Counter(scripts).values()), {2})

    def test_campaign_records_start_run_and_skips_prior_sequences(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = pathlib.Path(temporary)
            manifest = runner.load_manifest(self._manifest(directory))
            campaign = runner.Runner(manifest, 0, 1, 3, start_run=2)
            observed = []
            campaign.enroll_hosts = lambda: None
            campaign.install_collector = lambda: None
            campaign.stop_all = lambda: None
            campaign.run_one = lambda round_number, mode, sequence: observed.append(
                (sequence, round_number, mode)
            )
            campaign.run()
            self.assertEqual(observed, runner.scheduled_runs(3, 2))
            status = json.loads(
                (manifest.output_dir / "campaign-status.json").read_text(encoding="utf-8")
            )
            self.assertEqual(status["start_run"], 2)
            self.assertEqual(status["state"], "completed")


if __name__ == "__main__":
    unittest.main()
