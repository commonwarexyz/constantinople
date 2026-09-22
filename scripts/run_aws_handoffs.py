#!/usr/bin/env python3
"""Run controlled handoff-mode benchmarks on an existing AWS deployment."""

from __future__ import annotations

import argparse
import concurrent.futures
import datetime as dt
import hashlib
import ipaddress
import json
import math
import os
import re
import secrets
import shlex
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, TypeVar


MODES = ("baseline", "build_only", "build_and_broadcast")
SAFE_NAME = re.compile(r"^[A-Za-z0-9_-]+$")
AWS_REGION = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)+$")
SHA256 = re.compile(r"^[0-9a-f]{64}$")
CONFIG_FIELD = re.compile(r"^(?P<indent>\s*)(?P<key>handoff_mode|partition_prefix):.*$")
REMOTE_COLLECTOR = "/home/ubuntu/compare_handoffs.py"
REMOTE_RESULTS = "/home/ubuntu/handoff-benchmark-results"
READINESS_TIMEOUT = 300.0
SSH_TIMEOUT = 45.0
TRANSPORT_ATTEMPTS = 3
TRANSPORT_RETRY_BACKOFF = 0.5


class RunnerError(RuntimeError):
    """The benchmark cannot proceed safely."""


@dataclass(frozen=True)
class Node:
    name: str
    ip: str
    region: str
    config: Path


@dataclass(frozen=True)
class Manifest:
    tag: str
    key: Path
    monitor_ip: str
    expected_binary_sha256: str
    nodes: tuple[Node, ...]
    output_dir: Path


def _absolute_path(value: object, field: str) -> Path:
    if not isinstance(value, str):
        raise RunnerError(f"{field} must be a string")
    path = Path(value)
    if not path.is_absolute():
        raise RunnerError(f"{field} must be an absolute path")
    return path


def load_manifest(path: Path) -> Manifest:
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise RunnerError(f"failed to load manifest: {exc}") from exc
    if not isinstance(raw, dict):
        raise RunnerError("manifest must be a JSON object")
    expected = {"tag", "key", "monitor_ip", "expected_binary_sha256", "nodes", "output_dir"}
    if set(raw) != expected:
        raise RunnerError(f"manifest fields must be exactly {sorted(expected)}")

    tag = raw["tag"]
    if not isinstance(tag, str) or not SAFE_NAME.fullmatch(tag):
        raise RunnerError("tag must match [A-Za-z0-9_-]+")
    key = _absolute_path(raw["key"], "key")
    output_dir = _absolute_path(raw["output_dir"], "output_dir")
    if not key.is_file():
        raise RunnerError("key does not exist or is not a file")
    digest = raw["expected_binary_sha256"]
    if not isinstance(digest, str) or not SHA256.fullmatch(digest):
        raise RunnerError("expected_binary_sha256 must be 64 lowercase hex characters")
    try:
        monitor_ip = str(ipaddress.IPv4Address(raw["monitor_ip"]))
    except (TypeError, ValueError) as exc:
        raise RunnerError("monitor_ip must be an IP address") from exc

    node_values = raw["nodes"]
    if not isinstance(node_values, list) or len(node_values) != 7:
        raise RunnerError("nodes must contain exactly seven validators")
    nodes: list[Node] = []
    for index, value in enumerate(node_values):
        if not isinstance(value, dict) or set(value) != {"name", "ip", "region", "config"}:
            raise RunnerError(
                f"nodes[{index}] fields must be exactly name, ip, region, config"
            )
        name = value["name"]
        if not isinstance(name, str) or not SAFE_NAME.fullmatch(name):
            raise RunnerError(f"nodes[{index}].name is unsafe")
        try:
            ip = str(ipaddress.IPv4Address(value["ip"]))
        except (TypeError, ValueError) as exc:
            raise RunnerError(f"nodes[{index}].ip must be an IP address") from exc
        region = value["region"]
        if not isinstance(region, str) or not AWS_REGION.fullmatch(region):
            raise RunnerError(f"nodes[{index}].region is invalid")
        config = _absolute_path(value["config"], f"nodes[{index}].config")
        if not config.is_file():
            raise RunnerError(f"nodes[{index}].config does not exist")
        nodes.append(Node(name, ip, region, config))
    if len({node.name for node in nodes}) != len(nodes):
        raise RunnerError("node names must be unique")
    if len({node.ip for node in nodes}) != len(nodes):
        raise RunnerError("node IPs must be unique")
    if len({node.config for node in nodes}) != len(nodes):
        raise RunnerError("node config paths must be unique")
    if monitor_ip in {node.ip for node in nodes}:
        raise RunnerError("monitor_ip must not be a validator IP")
    return Manifest(tag, key, monitor_ip, digest, tuple(nodes), output_dir)


def rotated_runs(rounds: int) -> list[tuple[int, str]]:
    if rounds < 1:
        raise RunnerError("rounds must be at least one")
    return [
        (round_index + 1, MODES[(offset + round_index) % len(MODES)])
        for round_index in range(rounds)
        for offset in range(len(MODES))
    ]


def scheduled_runs(rounds: int, start_run: int) -> list[tuple[int, int, str]]:
    runs = rotated_runs(rounds)
    if start_run < 1 or start_run > len(runs):
        raise RunnerError(f"start_run must be between 1 and {len(runs)}")
    return [
        (sequence, round_number, mode)
        for sequence, (round_number, mode) in enumerate(runs, 1)
        if sequence >= start_run
    ]


def rewrite_validator_config(text: str, mode: str, partition_prefix: str) -> str:
    if mode not in MODES:
        raise RunnerError(f"unsupported handoff mode: {mode}")
    if not SAFE_NAME.fullmatch(partition_prefix):
        raise RunnerError("partition_prefix is unsafe")
    counts = {"handoff_mode": 0, "partition_prefix": 0}
    rewritten: list[str] = []
    for line in text.splitlines(keepends=True):
        body = line.rstrip("\r\n")
        ending = line[len(body):]
        match = CONFIG_FIELD.fullmatch(body)
        if match is None:
            rewritten.append(line)
            continue
        key = match.group("key")
        counts[key] += 1
        value = mode if key == "handoff_mode" else partition_prefix
        rewritten.append(f"{match.group('indent')}{key}: {value}{ending}")
    if counts != {"handoff_mode": 1, "partition_prefix": 1}:
        raise RunnerError("config must contain exactly one handoff_mode and partition_prefix")
    return "".join(rewritten)


def parse_supervision(text: str) -> dict[str, str]:
    expected = {"MainPID", "ExecMainStartTimestampMonotonic", "NRestarts", "ActiveState"}
    values: dict[str, str] = {}
    for line in text.splitlines():
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        if key in expected:
            values[key] = value
    if set(values) != expected:
        raise RunnerError("systemd supervision output is incomplete")
    if values["ActiveState"] != "active" or values["MainPID"] in {"", "0"}:
        raise RunnerError("binary service is not actively supervised")
    return values


def verify_supervision(before: dict[str, str], after: dict[str, str]) -> None:
    for field in ("MainPID", "ExecMainStartTimestampMonotonic", "NRestarts", "ActiveState"):
        if before.get(field) != after.get(field):
            raise RunnerError(f"binary supervision changed during collection: {field}")
    if after.get("ActiveState") != "active":
        raise RunnerError("binary service was not active after collection")


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _timestamp() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat()


def _write_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    os.replace(temporary, path)


T = TypeVar("T")


def _parallel(items: tuple[Node, ...], operation: Callable[[Node], T]) -> dict[str, T]:
    results: dict[str, T] = {}
    errors: list[str] = []
    # Bound bursts of new SSH/SCP connections while preserving fleet barriers.
    with concurrent.futures.ThreadPoolExecutor(max_workers=min(2, len(items))) as executor:
        futures = {executor.submit(operation, node): node for node in items}
        for future in concurrent.futures.as_completed(futures):
            node = futures[future]
            try:
                results[node.name] = future.result()
            except Exception as exc:  # Preserve every failed host in the barrier report.
                errors.append(f"{node.name}: {exc}")
    if errors:
        raise RunnerError("fleet operation failed: " + "; ".join(sorted(errors)))
    return results


class Runner:
    def __init__(self, manifest: Manifest, warmup: float, duration: float, rounds: int,
                 start_run: int = 1, expected_build_delay_ms: int | None = None):
        scheduled_runs(rounds, start_run)
        self.manifest = manifest
        self.warmup = warmup
        self.duration = duration
        self.rounds = rounds
        self.start_run = start_run
        self.expected_build_delay_ms = expected_build_delay_ms
        self.known_hosts = manifest.output_dir / f"known_hosts-{manifest.tag}"
        self.collector = Path(__file__).with_name("compare_handoffs.py").resolve()
        self.campaign_id = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ") + "-" + secrets.token_hex(4)
        self.strict_hosts = False
        self.config_snapshots: dict[str, str] | None = None
        self.input_config_sha256: dict[str, str] | None = None
        self.transport_retry_diagnostics: list[dict[str, object]] = []

    def _run(self, argv: list[str], timeout: float, check: bool = True) -> subprocess.CompletedProcess[str]:
        try:
            result = subprocess.run(
                argv, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                timeout=timeout, check=False,
            )
        except subprocess.TimeoutExpired as exc:
            raise RunnerError(f"{argv[0]} timed out after {timeout:g}s") from exc
        except OSError as exc:
            raise RunnerError(f"{argv[0]} failed to execute: {exc}") from exc
        if check and result.returncode != 0:
            detail = result.stderr.strip().splitlines()[-1:] or ["no diagnostic"]
            raise RunnerError(f"{argv[0]} exited {result.returncode}: {detail[0]}")
        return result

    def _ssh_options(self) -> list[str]:
        checking = "yes" if self.strict_hosts else "accept-new"
        return [
            "-i", str(self.manifest.key), "-o", "IdentitiesOnly=yes",
            "-o", f"StrictHostKeyChecking={checking}",
            "-o", f"UserKnownHostsFile={self.known_hosts}",
            "-o", "BatchMode=yes", "-o", "ConnectTimeout=20",
            "-o", "ServerAliveInterval=30",
        ]

    def _transport_run(self, argv: list[str], timeout: float, check: bool,
                       attempts: int, operation: str,
                       target: str) -> subprocess.CompletedProcess[str]:
        if attempts < 1:
            raise RunnerError("transport attempts must be at least one")
        for attempt in range(1, attempts + 1):
            try:
                result = self._run(argv, timeout, check=False)
            except RunnerError as exc:
                if not isinstance(exc.__cause__, subprocess.TimeoutExpired):
                    raise
                reason = "timeout"
                result = None
            else:
                if result.returncode != 255:
                    if check and result.returncode != 0:
                        detail = result.stderr.strip().splitlines()[-1:] or ["no diagnostic"]
                        raise RunnerError(
                            f"{argv[0]} exited {result.returncode}: {detail[0]}"
                        )
                    return result
                reason = "exit_255"

            self.transport_retry_diagnostics.append({
                "at_utc": _timestamp(),
                "operation": operation,
                "target": target,
                "attempt": attempt,
                "max_attempts": attempts,
                "reason": reason,
            })
            if attempt < attempts:
                time.sleep(TRANSPORT_RETRY_BACKOFF * attempt)
        raise RunnerError(
            f"{operation} transport to {target} failed after {attempts} attempt(s)"
        )

    def _ssh(self, ip: str, remote_argv: list[str], timeout: float = SSH_TIMEOUT,
             check: bool = True,
             attempts: int = TRANSPORT_ATTEMPTS) -> subprocess.CompletedProcess[str]:
        command = shlex.join(remote_argv)
        return self._transport_run(
            ["ssh", *self._ssh_options(), f"ubuntu@{ip}", command],
            timeout, check, attempts, "ssh", ip,
        )

    def _scp_to(self, local: Path, ip: str, remote: str) -> None:
        self._transport_run(
            ["scp", *self._ssh_options(), str(local), f"ubuntu@{ip}:{remote}"],
            SSH_TIMEOUT, True, TRANSPORT_ATTEMPTS, "scp_to", ip,
        )

    def _scp_from(self, ip: str, remote: str, local: Path) -> None:
        self._transport_run(
            ["scp", *self._ssh_options(), f"ubuntu@{ip}:{remote}", str(local)],
            SSH_TIMEOUT, True, TRANSPORT_ATTEMPTS, "scp_from", ip,
        )

    def enroll_hosts(self) -> None:
        self.manifest.output_dir.mkdir(parents=True, exist_ok=True)
        self.known_hosts.touch(mode=0o600, exist_ok=True)
        self.known_hosts.chmod(0o600)
        for ip in (self.manifest.monitor_ip, *(node.ip for node in self.manifest.nodes)):
            self._ssh(ip, ["true"])
        self.strict_hosts = True

    def install_collector(self) -> None:
        if not self.collector.is_file():
            raise RunnerError("compare_handoffs.py is missing")
        self._scp_to(self.collector, self.manifest.monitor_ip, REMOTE_COLLECTOR)
        local_hash = _sha256(self.collector)
        remote_hash = self._ssh(
            self.manifest.monitor_ip, ["sha256sum", REMOTE_COLLECTOR]
        ).stdout.split()[0]
        if remote_hash != local_hash:
            raise RunnerError("remote collector hash mismatch")
        self._ssh(self.manifest.monitor_ip, ["mkdir", "-p", REMOTE_RESULTS])

    def verify_binaries(self) -> dict[str, str]:
        def verify(node: Node) -> str:
            output = self._ssh(node.ip, ["sha256sum", "/home/ubuntu/binary"]).stdout
            digest = output.split()[0] if output.split() else ""
            if digest != self.manifest.expected_binary_sha256:
                raise RunnerError("remote binary SHA-256 mismatch")
            return digest
        return _parallel(self.manifest.nodes, verify)

    def stop_all(self) -> None:
        def stop(node: Node) -> None:
            self._ssh(
                node.ip,
                ["sudo", "systemctl", "stop", "binary"],
                timeout=120.0,
            )
            self._ssh(node.ip, ["sudo", "systemctl", "reset-failed", "binary"], check=False)
            deadline = time.monotonic() + 90
            while time.monotonic() < deadline:
                state = self._ssh(
                    node.ip, ["systemctl", "is-active", "binary"], check=False
                ).stdout.strip()
                if state == "inactive":
                    return
                time.sleep(1)
            raise RunnerError("binary service did not become inactive")
        _parallel(self.manifest.nodes, stop)

    def freeze_configs(self) -> None:
        """Snapshot each input once so every run derives from identical bytes."""
        if self.config_snapshots is not None or self.input_config_sha256 is not None:
            raise RunnerError("input configs have already been frozen")
        snapshots: dict[str, str] = {}
        hashes: dict[str, str] = {}
        for node in self.manifest.nodes:
            raw = node.config.read_bytes()
            try:
                snapshots[node.name] = raw.decode("utf-8")
            except UnicodeDecodeError as exc:
                raise RunnerError(f"config for {node.name} is not UTF-8") from exc
            if self.expected_build_delay_ms is not None:
                values = re.findall(r"^proposal_build_delay_ms: (\d+)\s*$", snapshots[node.name], re.M)
                if len(values) != 1 or int(values[0]) != self.expected_build_delay_ms:
                    raise RunnerError(f"config for {node.name} does not match expected build delay")
            hashes[node.name] = hashlib.sha256(raw).hexdigest()
        self.config_snapshots = snapshots
        self.input_config_sha256 = hashes

    def provenance(self) -> dict[str, object]:
        if self.input_config_sha256 is None:
            raise RunnerError("input configs have not been frozen")
        return {
            "expected_binary_sha256": self.manifest.expected_binary_sha256,
            "input_config_sha256": dict(self.input_config_sha256),
        }

    def _make_configs(self, run_dir: Path, mode: str, sequence: int) -> dict[str, tuple[Path, str]]:
        if self.config_snapshots is None:
            raise RunnerError("input configs have not been frozen")
        configs: dict[str, tuple[Path, str]] = {}
        for index, node in enumerate(self.manifest.nodes):
            prefix = f"bench-{self.campaign_id}-{sequence:02d}-{index:02d}"
            source = self.config_snapshots[node.name]
            rendered = rewrite_validator_config(source, mode, prefix)
            destination = run_dir / "configs" / f"{node.name}.yaml"
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_text(rendered, encoding="utf-8")
            destination.chmod(0o600)
            configs[node.name] = (destination, prefix)
        return configs

    def stage_configs(self, configs: dict[str, tuple[Path, str]]) -> None:
        def stage(node: Node) -> None:
            local, _ = configs[node.name]
            self._scp_to(local, node.ip, "/home/ubuntu/config.conf.next")
            remote_hash = self._ssh(
                node.ip, ["sha256sum", "/home/ubuntu/config.conf.next"]
            ).stdout.split()[0]
            if remote_hash != _sha256(local):
                raise RunnerError("staged config SHA-256 mismatch")
        _parallel(self.manifest.nodes, stage)

    def install_configs(self, configs: dict[str, tuple[Path, str]], mode: str) -> None:
        def install(node: Node) -> None:
            local, prefix = configs[node.name]
            expected_hash = _sha256(local)
            script = (
                "set -eu; "
                "test \"$(systemctl is-active binary || true)\" = inactive; "
                f"test ! -e {shlex.quote('/home/ubuntu/' + prefix)}; "
                "install -m 0600 /home/ubuntu/config.conf.next /home/ubuntu/config.conf; "
                f"grep -Fx {shlex.quote('handoff_mode: ' + mode)} /home/ubuntu/config.conf >/dev/null; "
                f"grep -Fx {shlex.quote('partition_prefix: ' + prefix)} /home/ubuntu/config.conf >/dev/null; "
                "sha256sum /home/ubuntu/config.conf"
            )
            output = self._ssh(node.ip, ["sh", "-c", script]).stdout
            installed_hash = output.split()[0] if output.split() else ""
            if installed_hash != expected_hash:
                raise RunnerError("installed config SHA-256 mismatch")
        _parallel(self.manifest.nodes, install)

    def start_all(self) -> None:
        def start(node: Node) -> None:
            self._ssh(node.ip, ["sudo", "systemctl", "start", "binary"])
            deadline = time.monotonic() + 90
            while time.monotonic() < deadline:
                state = self._ssh(
                    node.ip, ["systemctl", "is-active", "binary"], check=False
                ).stdout.strip()
                if state == "active":
                    return
                time.sleep(1)
            raise RunnerError("binary service did not become active")
        _parallel(self.manifest.nodes, start)

    def await_readiness(self) -> list[float]:
        urls = [f"http://{node.ip}:9090/metrics" for node in self.manifest.nodes]
        code = """import importlib.util,json,sys
spec=importlib.util.spec_from_file_location("compare_handoffs",sys.argv[1])
module=importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
urls=json.loads(sys.argv[2]); chain=[("readiness",urls)]
snapshots=module.scrape_all(chain,10.0)["readiness"]
module.validate_baseline("readiness",snapshots)
print(json.dumps([module.one_value(node,module.HEIGHT) for node in snapshots]))
"""
        deadline = time.monotonic() + READINESS_TIMEOUT
        last_error = "not attempted"
        while time.monotonic() < deadline:
            result = self._ssh(
                self.manifest.monitor_ip,
                ["python3", "-c", code, REMOTE_COLLECTOR, json.dumps(urls)],
                timeout=90,
                check=False,
            )
            if result.returncode == 0:
                try:
                    heights = json.loads(result.stdout)
                    if len(heights) == len(urls) and all(float(height) >= 20 for height in heights):
                        return [float(height) for height in heights]
                    last_error = f"heights below 20: {heights}"
                except (TypeError, ValueError, json.JSONDecodeError):
                    last_error = "invalid readiness output"
            else:
                last_error = "collector preflight failed"
            time.sleep(5)
        raise RunnerError(f"readiness timed out: {last_error}")

    def supervision(self) -> dict[str, dict[str, str]]:
        properties = [
            "--property=MainPID", "--property=ExecMainStartTimestampMonotonic",
            "--property=NRestarts", "--property=ActiveState", "binary.service",
        ]
        return _parallel(
            self.manifest.nodes,
            lambda node: parse_supervision(
                self._ssh(node.ip, ["systemctl", "show", *properties]).stdout
            ),
        )

    def collect(self, run_dir: Path, run_id: str, mode: str) -> None:
        urls = ",".join(f"http://{node.ip}:9090/metrics" for node in self.manifest.nodes)
        remote_output = f"{REMOTE_RESULTS}/{run_id}.json"
        command = [
            "python3", REMOTE_COLLECTOR,
            "--chain", f"{mode}={urls}",
            "--warmup", str(self.warmup),
            "--duration", str(self.duration),
            "--output", remote_output,
        ]
        result = self._ssh(
            self.manifest.monitor_ip, command,
            timeout=self.warmup + self.duration + 180,
            attempts=1,
        )
        (run_dir / "collector.log").write_text(
            result.stdout + result.stderr, encoding="utf-8"
        )
        self._scp_from(
            self.manifest.monitor_ip, remote_output, run_dir / "comparison.json"
        )
        if self.expected_build_delay_ms is not None:
            validate_build_delay(
                json.loads((run_dir / "comparison.json").read_text())["chains"][mode],
                self.expected_build_delay_ms,
            )

    def run_one(self, round_number: int, mode: str, sequence: int) -> None:
        run_id = f"{self.campaign_id}-r{round_number:02d}-{mode}"
        run_dir = self.manifest.output_dir / run_id
        status_path = run_dir / "status.json"
        status: dict[str, object] = {
            "schema_version": 1, "campaign_id": self.campaign_id,
            "deployment_tag": self.manifest.tag, "run_id": run_id,
            "round": round_number, "mode": mode,
            "warmup_seconds": self.warmup, "duration_seconds": self.duration,
            "expected_build_delay_ms": self.expected_build_delay_ms,
            "provenance": self.provenance(),
            "state": "preparing", "started_at_utc": _timestamp(),
        }
        status["transport_retries"] = list(self.transport_retry_diagnostics)
        _write_json(status_path, status)
        try:
            # Validator configs contain private keys. Render them into a 0700 temporary
            # directory, stage them, and remove the local copies after installation.
            with tempfile.TemporaryDirectory(prefix="constantinople-handoffs-") as temporary:
                configs = self._make_configs(Path(temporary), mode, sequence)
                self.stage_configs(configs)
                status.update(state="stopping", configs_staged_at_utc=_timestamp())
                status["transport_retries"] = list(self.transport_retry_diagnostics)
                _write_json(status_path, status)
                self.stop_all()
                self.install_configs(configs, mode)
            binary_hashes = self.verify_binaries()
            status.update(
                state="starting", configs_installed_at_utc=_timestamp(),
                binary_sha256=binary_hashes,
            )
            status["transport_retries"] = list(self.transport_retry_diagnostics)
            _write_json(status_path, status)
            self.start_all()
            heights = self.await_readiness()
            status.update(state="collecting", ready_at_utc=_timestamp(), readiness_heights=heights)
            status["transport_retries"] = list(self.transport_retry_diagnostics)
            _write_json(status_path, status)
            before = self.supervision()
            status["supervision_before"] = before
            status["collection_started_at_utc"] = _timestamp()
            status["transport_retries"] = list(self.transport_retry_diagnostics)
            _write_json(status_path, status)
            self.collect(run_dir, run_id, mode)
            after = self.supervision()
            for node in self.manifest.nodes:
                verify_supervision(before[node.name], after[node.name])
            status.update(
                state="completed", collection_finished_at_utc=_timestamp(),
                supervision_after=after, completed_at_utc=_timestamp(),
            )
            status["transport_retries"] = list(self.transport_retry_diagnostics)
            _write_json(status_path, status)
        except BaseException as exc:
            status.update(state="failed", failed_at_utc=_timestamp(), error=str(exc))
            status["transport_retries"] = list(self.transport_retry_diagnostics)
            _write_json(status_path, status)
            raise

    def run(self) -> None:
        campaign_status = self.manifest.output_dir / "campaign-status.json"
        self.manifest.output_dir.mkdir(parents=True, exist_ok=True)
        self.freeze_configs()
        summary: dict[str, object] = {
            "schema_version": 1, "campaign_id": self.campaign_id,
            "deployment_tag": self.manifest.tag,
            "regions": sorted({node.region for node in self.manifest.nodes}),
            "state": "preparing", "started_at_utc": _timestamp(),
            "rounds": self.rounds,
            "start_run": self.start_run,
            "provenance": self.provenance(),
            "transport_retries": [],
        }
        _write_json(campaign_status, summary)
        error: BaseException | None = None
        try:
            self.enroll_hosts()
            self.install_collector()
            for sequence, round_number, mode in scheduled_runs(self.rounds, self.start_run):
                self.run_one(round_number, mode, sequence)
        except BaseException as exc:
            error = exc
            raise
        finally:
            stop_error: Exception | None = None
            try:
                # A partially completed host enrollment or setup must still leave the
                # existing fleet stopped. accept-new remains scoped to this deployment's
                # dedicated known_hosts file until enrollment completes.
                self.stop_all()
            except Exception as exc:
                stop_error = exc
            state = "failed" if error or stop_error else "completed"
            summary.update(
                state=state,
                finished_at_utc=_timestamp(),
                validators_stopped=stop_error is None,
                transport_retries=list(self.transport_retry_diagnostics),
            )
            if error:
                summary["error"] = str(error)
            if stop_error:
                summary["stop_error"] = str(stop_error)
            _write_json(campaign_status, summary)
            if error is None and stop_error is not None:
                raise stop_error


def validate_build_delay(result: dict[str, object], expected_ms: int) -> None:
    """Require per-validator evidence of completed synthetic delay and building."""
    metrics = ("engine_application_proposal_build_duration",
               "engine_application_proposal_build_delay_duration")
    if not all(metric in result.get("build_timings", {}) for metric in metrics):
        raise RunnerError("required build timing histograms are absent")
    snapshots = result["snapshots"]
    for before, after in zip(snapshots["baseline"], snapshots["final"], strict=True):
        for metric in metrics:
            def total(node: dict[str, object], suffix: str) -> float:
                samples = node["metrics"].get(metric + suffix, [])
                if not samples:
                    raise RunnerError("required per-validator build timing metric is absent")
                return sum(sample["value"] for sample in samples)
            count = total(after, "_count") - total(before, "_count")
            duration = total(after, "_sum") - total(before, "_sum")
            if count <= 0 or duration < 0:
                raise RunnerError("no valid completed build timing samples on a validator")
            if metric == metrics[1] and duration / count + 1e-6 < expected_ms / 1000:
                raise RunnerError("observed build delay is below the configured treatment")


def _finite_nonnegative(value: str) -> float:
    parsed = float(value)
    if not math.isfinite(parsed) or parsed < 0:
        raise argparse.ArgumentTypeError("must be finite and non-negative")
    return parsed


def _finite_positive(value: str) -> float:
    parsed = float(value)
    if not math.isfinite(parsed) or parsed <= 0:
        raise argparse.ArgumentTypeError("must be finite and greater than zero")
    return parsed


def _positive_int(value: str) -> int:
    parsed = int(value)
    if parsed < 1:
        raise argparse.ArgumentTypeError("must be at least one")
    return parsed


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", required=True, type=Path)
    parser.add_argument("--warmup", type=_finite_nonnegative, default=120.0)
    parser.add_argument("--duration", type=_finite_positive, default=600.0)
    parser.add_argument("--rounds", type=_positive_int, default=1)
    parser.add_argument("--start-run", type=_positive_int, default=1)
    parser.add_argument("--expected-build-delay-ms", type=_positive_int,
                        help="require this synthetic delay in configs and measured timings")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        manifest = load_manifest(args.manifest.resolve())
        Runner(
            manifest, args.warmup, args.duration, args.rounds, args.start_run,
            args.expected_build_delay_ms,
        ).run()
        return 0
    except (RunnerError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
