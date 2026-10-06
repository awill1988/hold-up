"""Portable socket contracts using actual sockets and isolated state."""

import concurrent.futures
import json
import os
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from holdup import adapters, locations, routes, transport
from holdup import decision as d
from holdup.socket_runtime import Runtime, SocketOwner


class SocketContracts(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.config = {"feeds": [{"name": "AWS"}]}
        self.runtime = Runtime(self.root, self.config)
        self.owner = SocketOwner(self.runtime)
        self.thread = threading.Thread(
            target=self.owner.serve_forever, kwargs={"poll_interval": 0.01}
        )
        self.thread.start()
        self.route = routes.normalize(
            {
                "tool_name": "Bash",
                "tool_input": {"command": "aws --region us-east-1 ec2 run-instances"},
            }
        )
        self.runtime.snapshot = {
            "fetched_at": time.time(),
            "qualified": True,
            "content": "fixture",
            "rules": {
                routes.key(self.route): {
                    "decision": "pause",
                    "reason": "fixture",
                    "evidence_ids": ["fixture"],
                    "providers": ["AWS"],
                }
            },
        }
        self.message = {
            "event": "PreToolUse",
            "agent": "codex",
            "namespace": "1" * 64,
            "correlation": "2" * 64,
            "action_key": "3" * 64,
            "route": self.route,
            "generation": self.runtime.generation,
            "config_hash": d.digest(self.config),
        }

    def tearDown(self):
        self.owner.shutdown()
        self.owner.server_close()
        self.thread.join()
        self.runtime.close()
        self.temp.cleanup()

    def request(self, **changes):
        return transport.request(self.root, {**self.message, **changes})

    def test_denial_retry_renewal_recovery(self):
        denied = self.request()
        self.assertEqual(denied["decision"], "pause")
        self.request(event="retry", decision_id=denied["decision_id"])
        self.assertEqual(self.request()["reason"], "retry_consumed")
        self.assertEqual(self.request()["decision"], "pause")
        self.runtime.snapshot = {
            **self.runtime.snapshot,
            "rules": {
                key: {**rule, "decision": "allow"}
                for key, rule in self.runtime.snapshot["rules"].items()
            },
        }
        self.assertEqual(self.request()["decision"], "allow")

    def test_retry_isolation_and_concurrent_consumption(self):
        denied = self.request()
        self.request(event="retry", decision_id=denied["decision_id"])
        self.assertEqual(self.request(namespace="4" * 64)["decision"], "pause")
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
            results = tuple(pool.map(lambda _: self.request(), range(4)))
        self.assertEqual(sum(r.get("reason") == "retry_consumed" for r in results), 1)
        self.assertEqual(self.request()["decision"], "pause")

    def test_decision_identity_does_not_depend_on_clock_resolution(self):
        now = time.time()
        rule = self.runtime.snapshot["rules"][routes.key(self.route)]
        identifiers = frozenset(
            self.runtime.state.save("namespace", "action", "evidence", rule, now, now + 300)
            for _ in range(10)
        )
        self.assertEqual(len(identifiers), 10)

    def test_unavailable_socket_emits_advice_without_denial(self):
        payload = {
            "tool_name": "Bash",
            "tool_input": {"command": "aws --region us-east-1 ec2 run-instances"},
        }
        with patch.object(self.runtime, "dispatch", return_value={"error": "runtime_busy"}):
            response = adapters.process("PreToolUse", payload, "codex", self.config, self.root)
        envelope = response["hookSpecificOutput"]
        self.assertNotIn("permissionDecision", envelope)
        self.assertIn("socket_unavailable", envelope["additionalContext"])

    def test_invalid_readiness_scope_and_freshness_cannot_deny(self):
        self.runtime.snapshot = {**self.runtime.snapshot, "qualified": False}
        self.assertEqual(self.request()["reason"], "model_unqualified")
        self.assertEqual(self.request(generation="changed")["reason"], "configuration_changed")
        self.assertEqual(self.request(route={"kind": "unknown"})["decision"], "advise")
        self.runtime.snapshot = {**self.runtime.snapshot, "fetched_at": time.time() - 301}
        self.assertEqual(self.request()["reason"], "evidence_incomplete")
        self.assertEqual(self.request(route={"kind": "local"})["decision"], "allow")

    def test_socket_frames_authentication_and_disconnects(self):
        for content in (
            struct.pack("!I", transport.MAX_FRAME + 1),
            b"\x00\x00",
            struct.pack("!I", 2) + b"[]",
        ):
            with socket.create_connection(self.owner.server_address, timeout=0.5) as sock:
                sock.sendall(content)
                sock.shutdown(socket.SHUT_WR)
                self.assertEqual(sock.recv(100), b"")
        with socket.create_connection(self.owner.server_address, timeout=0.5) as sock:
            deadline = time.monotonic() + 0.5
            transport.send(sock, {"version": 1, "secret": "wrong", "event": "status"}, deadline)
            self.assertEqual(sock.recv(100), b"")
        self.assertEqual(self.request()["decision"], "pause")

    def test_slow_sender_is_bounded(self):
        with socket.create_connection(self.owner.server_address, timeout=0.5) as sock:
            started = time.monotonic()
            sock.sendall(b"\x00")
            self.assertEqual(sock.recv(100), b"")
            self.assertLess(time.monotonic() - started, 0.5)

    def test_owner_is_exclusive_and_responses_are_authenticated(self):
        with self.assertRaisesRegex(ValueError, "already_running"):
            SocketOwner(self.runtime)
        signed = {"version": 1, "nonce": "fixture", "decision": "allow"}
        signature = transport.signature(signed, "secret")
        self.assertTrue(transport.authenticate({**signed, "signature": signature}, "secret"))
        self.assertFalse(
            transport.authenticate(
                {**signed, "decision": "pause", "signature": signature}, "secret"
            )
        )

    def test_native_python_launch_is_portable(self):
        config = self.root / "config.json"
        config.write_text(json.dumps({"feeds": []}))
        for client in ("claude", "codex", "antigravity"):
            payload = {"tool_name": "Bash", "tool_input": {"command": "pwd"}}
            if client == "antigravity":
                payload = {"toolCall": {"name": "run_command", "args": {"CommandLine": "pwd"}}}
            result = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "holdup",
                    "--client",
                    client,
                    "--event",
                    "PreToolUse",
                    "--config",
                    str(config),
                ],
                input=json.dumps(payload),
                capture_output=True,
                text=True,
                timeout=5,
                env={
                    **os.environ,
                    "HOLD_UP_STATE_DIR": str(self.root),
                    "PYTHONPATH": str(Path(__file__).resolve().parents[1] / "src"),
                },
            )
            self.assertEqual((result.returncode, result.stdout, result.stderr), (0, "", ""))

    def test_native_output_preserves_permissions(self):
        for program in ("claude", "codex", "antigravity"):
            self.assertIsNone(adapters.output(program, "PreToolUse", {"decision": "allow"}))
            output = adapters.output(
                program, "PreToolUse", {"decision": "pause", "reason": "affected_operation"}
            )
            self.assertEqual(
                output["decision"]
                if program == "antigravity"
                else output["hookSpecificOutput"]["permissionDecision"],
                "deny",
            )

    def test_no_hook_inference_or_feed_acquisition(self):
        payload = {
            "tool_name": "Bash",
            "tool_input": {
                "command": "aws --region us-east-1 ec2 run-instances --secret do-not-store"
            },
            "session_id": "private",
            "tool_use_id": "call",
        }
        with patch.object(d, "infer", side_effect=AssertionError("inference in hook")):
            result = adapters.process("PreToolUse", payload, "codex", self.config, self.root)
        self.assertEqual(result["hookSpecificOutput"]["permissionDecision"], "deny")
        self.runtime.telemetry.close()
        self.assertNotIn(b"do-not-store", self.runtime.telemetry.path.read_bytes())

    def test_statistics_are_per_program_and_deduplicated(self):
        self.request()
        self.request()
        self.request(event="PostToolUse", outcome="failed")
        self.runtime.telemetry.close()
        stats = self.request(event="stats", agent=None)
        codex = next(r for r in stats["agents"] if r["agent"] == "codex")
        claude = next(r for r in stats["agents"] if r["agent"] == "claude")
        self.assertEqual(codex["checks"], 1)
        self.assertEqual(codex["failures"], 1)
        self.assertEqual(claude["coverage"], "not observed")
        self.assertIsNone(codex["p95_ms"])

    def test_statistics_have_separate_inspection_deadline(self):
        original = self.runtime.telemetry.stats

        def delayed(*args):
            time.sleep(transport.DEADLINE * 2)
            return original(*args)

        with patch.object(self.runtime.telemetry, "stats", side_effect=delayed):
            report = self.request(event="stats", agent=None)
        self.assertEqual(len(report["agents"]), 4)

    def test_telemetry_failure_does_not_change_decision(self):
        with patch.object(
            self.runtime.telemetry,
            "connect",
            side_effect=__import__("sqlite3").OperationalError("locked"),
        ):
            self.assertEqual(self.request()["decision"], "pause")
            self.runtime.telemetry.close()
        self.assertGreaterEqual(self.runtime.telemetry.dropped, 1)


class ScopeAndLocations(unittest.TestCase):
    def test_aws_local_diagnostics_and_custom_endpoints(self):
        base = "aws --region us-east-1 ec2 run-instances"
        for suffix, kind in (
            ("--dry-run", "diagnostic"),
            ("--generate-cli-skeleton", "local"),
            ("--endpoint-url http://localhost:9000", "unknown"),
        ):
            self.assertEqual(
                routes.normalize(
                    {"tool_name": "Bash", "tool_input": {"command": base + " " + suffix}}
                )["kind"],
                kind,
            )

    def test_multiple_services_is_not_discarded_as_unrelated(self):
        route = {
            "kind": "remote",
            "service": "ec2",
            "operation": "run-instances",
            "region": "us-east-1",
        }
        reports = [
            {
                "id": "one",
                "provider": "AWS",
                "source_id": "arn:aws:health:us-east-1::event/MULTIPLE_SERVICES/issue/id",
                "region": "us-east-1",
                "fetched_at": time.time(),
            }
        ]
        classifier = Mock(
            return_value={
                "decision": "advise",
                "reason": "uncertain",
                "providers": [],
                "evidence_ids": [],
            }
        )
        routes.classify(route, reports, {}, predictor=classifier)
        classifier.assert_called_once()

    def test_xdg_and_state_override(self):
        with tempfile.TemporaryDirectory() as temp:
            with patch.dict(
                os.environ, {"XDG_STATE_HOME": temp, "XDG_RUNTIME_DIR": temp}, clear=True
            ):
                self.assertEqual(locations.directory("state"), Path(temp) / "hold-up")
                self.assertEqual(locations.directory("runtime"), Path(temp) / "hold-up")
                with patch.dict(os.environ, {"HOLD_UP_STATE_DIR": str(Path(temp) / "isolated")}):
                    self.assertEqual(
                        locations.directory("runtime"), Path(temp) / "isolated/runtime"
                    )

    def test_ambiguous_shell_and_regions_are_not_mapped(self):
        for command in (
            "aws ec2 run-instances",
            "aws --region us-east-1 ec2 run-instances | cat",
            "aws --region us-east-1 --region us-west-2 ec2 run-instances",
            "powershell -command aws ec2 run-instances",
            "aws --region us-east-1 ec2 invented",
        ):
            with patch.dict(os.environ, {}, clear=True):
                self.assertEqual(
                    routes.normalize({"tool_name": "Bash", "tool_input": {"command": command}}),
                    {"kind": "unknown"},
                )


if __name__ == "__main__":
    unittest.main()
