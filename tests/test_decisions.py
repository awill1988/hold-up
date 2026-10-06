"""Offline contracts for model authority, leases, redaction, and client denial."""

import concurrent.futures
import io
import json
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from holdup import decision as d
from holdup import engine as h
from holdup import evidence
from holdup.data import freeze, json_value


class Decisions(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        runner = self.root / "fixture-runner"
        runner.write_text("isolated test runner")
        (self.root / "runtime.json").write_text(
            json.dumps(
                {
                    "runner": str(runner),
                    "runner_sha256": d.hashlib.sha256(runner.read_bytes()).hexdigest(),
                    "model_sha256": d.MODEL_SHA256,
                }
            )
        )
        self.config = {"feeds": [{"name": "GitHub", "url": "https://example.invalid/status"}]}
        self.payload = {
            "client": "codex",
            "session_id": "one",
            "cwd": self.temp.name,
            "tool_name": "Bash",
            "tool_input": {"command": "git fetch"},
        }
        self.report = {
            "id": "incident-1",
            "provider": "GitHub",
            "title": "git operations unavailable",
            "status": "investigating",
            "fetched_at": time.time(),
        }
        self.result = {
            "decision": "pause",
            "reason": "git service unavailable",
            "evidence_ids": ["incident-1"],
            "providers": ["GitHub"],
        }
        self.snapshot()
        self.ready()

    def snapshot(self, unavailable=None, age=0):
        (self.root / "evidence.json").write_text(
            json.dumps(
                {
                    "version": 2,
                    "config_hash": d.digest(self.config),
                    "fetched_at": time.time() - age,
                    "reports": [self.report],
                    "unavailable": unavailable or [],
                }
            )
        )

    def ready(self, passed=True):
        (self.root / "readiness.json").write_text(
            json.dumps(
                {
                    "model_sha256": d.MODEL_SHA256,
                    "policy_version": d.POLICY_VERSION,
                    "policy_digest": d.policy_digest(),
                    "runtime_fingerprint": d.runtime_fingerprint(self.root),
                    "corpus_hash": d.corpus_hash(),
                    "qualification_version": d.QUALIFICATION_VERSION,
                    "passed": passed,
                }
            )
        )

    def call(self, result=None, payload=None):
        return d.pre_tool(
            payload or self.payload, self.config, self.root, lambda *args: result or self.result
        )

    def test_pause_is_native_pre_tool_denial(self):
        response = self.call()["hookSpecificOutput"]
        self.assertEqual(response["hookEventName"], "PreToolUse")
        self.assertEqual(response["permissionDecision"], "deny")
        self.assertIn("hold-up retry", response["permissionDecisionReason"])

    def test_no_readiness_no_block(self):
        self.ready(False)
        response = self.call()["hookSpecificOutput"]
        self.assertNotIn("permissionDecision", response)
        self.assertIn("without outage protection", response["additionalContext"])
        state = d.State(self.root)
        saved = json.loads(state.db.execute("SELECT result FROM decisions").fetchone()[0])
        self.assertEqual(saved["decision"], "advise")
        self.assertIn("git service unavailable", saved["reason"])
        state.close()

    def test_local_edits_cannot_be_paused(self):
        payload = {
            **self.payload,
            "tool_name": "apply_patch",
            "tool_input": {"command": "*** Update File: app.py\n+password=secret"},
        }
        action = d.normalize_action(payload)
        self.assertEqual(action["paths"], ("app.py",))
        self.assertNotIn("secret", json.dumps(action, default=json_value))
        self.assertNotIn("permissionDecision", self.call(payload=payload)["hookSpecificOutput"])

    def test_disabled_feeds_and_off_mode_do_not_infer(self):
        def unexpected(*args):
            self.fail("disabled guard must not call inference")

        self.assertIsNone(d.pre_tool(self.payload, {"feeds": []}, self.root, unexpected))
        with patch.dict("os.environ", {"HOLD_UP_MODE": "off"}):
            self.assertIsNone(d.pre_tool(self.payload, self.config, self.root, unexpected))

    def test_policy_change_revokes_readiness(self):
        with patch.object(d, "policy_digest", return_value="changed"):
            self.assertFalse(d.enforcement_ready(self.root))
            self.assertNotIn("permissionDecision", self.call()["hookSpecificOutput"])

    def test_runner_change_invalidates_readiness_and_cached_pause(self):
        self.call()
        (self.root / "fixture-runner").write_text("different runner")
        self.assertFalse(d.enforcement_ready(self.root))
        self.assertNotIn("permissionDecision", self.call()["hookSpecificOutput"])

    def test_legacy_snapshot_cannot_authorize_pause(self):
        path = self.root / "evidence.json"
        value = json.loads(path.read_text())
        value["version"] = 1
        path.write_text(json.dumps(value))
        self.assertNotIn("permissionDecision", self.call()["hookSpecificOutput"])

    def test_complete_evidence_overflow_is_explicit(self):
        self.report["summary"] = "x" * d.MAX_INPUT_BYTES
        self.snapshot()
        response = self.call()["hookSpecificOutput"]
        self.assertNotIn("permissionDecision", response)
        self.assertIn("evidence", response["additionalContext"])
        self.assertIn("overflow", response["additionalContext"])

    def test_aws_diagnostic_and_unaffected_region_cannot_pause(self):
        report = {**self.report, "provider": "AWS", "region": "us-east-1"}
        result = {**self.result, "providers": ["AWS"]}
        for command in (
            "aws --region us-east-1 ec2 describe-instances",
            "aws --region us-west-2 ec2 run-instances",
        ):
            action = d.normalize_action({"tool_name": "Bash", "tool_input": {"command": command}})
            with self.subTest(command=command), self.assertRaises(ValueError):
                d.validate_decision(result, action, [report])

    def test_retry_does_not_cross_client_workspace_or_session(self):
        self.call()
        state = d.State(self.root)
        identifier = state.db.execute("SELECT id FROM decisions").fetchone()[0]
        state.retry(identifier, time.time())
        state.close()
        for change in (
            {"client": "claude"},
            {"session_id": "other"},
            {"cwd": "/tmp/other-workspace"},
        ):
            self.assertIn(
                "permissionDecision",
                self.call(payload={**self.payload, **change})["hookSpecificOutput"],
            )
        self.assertIn("one-shot retry", self.call()["hookSpecificOutput"]["additionalContext"])

    def test_disappearance_preserves_pause_without_extending_lease(self):
        self.call()
        path = self.root / "evidence.json"
        snapshot = json.loads(path.read_text())
        snapshot["reports"] = []
        path.write_text(json.dumps(snapshot))
        state = d.State(self.root)
        before = state.db.execute("SELECT expires FROM decisions").fetchone()[0]
        state.close()
        self.assertIn("permissionDecision", self.call()["hookSpecificOutput"])
        state = d.State(self.root)
        self.assertEqual(before, state.db.execute("SELECT expires FROM decisions").fetchone()[0])
        state.close()

    def test_stale_individual_report_cannot_pause(self):
        self.report["fetched_at"] = time.time() - 301
        self.snapshot()
        self.assertNotIn("permissionDecision", self.call()["hookSpecificOutput"])

    def test_truncated_report_cannot_authorize_pause(self):
        self.report["truncated"] = True
        self.snapshot()
        self.assertNotIn("permissionDecision", self.call()["hookSpecificOutput"])

    def test_unrelated_feed_failure_does_not_hide_relevant_evidence(self):
        self.payload["tool_input"]["command"] = "gh repo clone example/project"
        self.snapshot(unavailable=["AWS"])
        self.assertIn("permissionDecision", self.call()["hookSpecificOutput"])

    def test_unknown_tool_has_no_scope(self):
        payload = {
            **self.payload,
            "tool_name": "mcp__custom__do",
            "tool_input": {"token": "secret"},
        }
        self.assertFalse(d.normalize_action(payload)["context_complete"])
        self.assertNotIn("secret", json.dumps(d.normalize_action(payload), default=json_value))
        self.assertNotIn("permissionDecision", self.call(payload=payload)["hookSpecificOutput"])

    def test_explicit_mcp_mapping(self):
        action = d.normalize_action(
            {
                "tool_name": "mcp__git__fetch",
                "tool_input": {"region": "us-east-1", "token": "secret"},
            },
            {"mcp__git__fetch": {"providers": ["GitHub"], "argument_keys": ["region"]}},
        )
        self.assertTrue(action["context_complete"])
        self.assertNotIn("secret", json.dumps(action, default=json_value))

    def test_invented_evidence_and_scope_rejected(self):
        action = d.normalize_action(self.payload)
        for replacement in (
            {"evidence_ids": ["fiction"]},
            {"providers": ["AWS"]},
            {"extra": True},
            {"reason": ""},
            {"decision": "execute"},
        ):
            with self.subTest(replacement=replacement), self.assertRaises(ValueError):
                d.validate_decision({**self.result, **replacement}, action, [self.report])

    def test_inference_rejects_truncated_or_missing_finish_reason(self):
        token = self.root / "fixture-token"
        token.write_text("test-only")
        for finish in ("length", None):
            body = json.dumps(
                {
                    "choices": [
                        {"message": {"content": json.dumps(self.result)}, "finish_reason": finish}
                    ]
                }
            ).encode()
            with (
                patch.object(
                    d.urllib.request.OpenerDirector, "open", return_value=io.BytesIO(body)
                ),
                self.assertRaises(d.ModelOutputError),
            ):
                d.infer({}, [], {"token_file": str(token)})

    def test_inference_preserves_raw_synthetic_response_and_finish_reason(self):
        token = self.root / "fixture-token"
        token.write_text("test-only")
        raw = json.dumps(self.result)
        body = json.dumps(
            {"choices": [{"message": {"content": raw}, "finish_reason": "stop"}]}
        ).encode()
        trace = {}
        with patch.object(d.urllib.request.OpenerDirector, "open", return_value=io.BytesIO(body)):
            self.assertEqual(
                d.infer({}, [], {"token_file": str(token), "trace": trace}), freeze(self.result)
            )
        self.assertEqual(trace["raw"], raw)
        self.assertEqual(trace["finish_reason"], "stop")

    def test_stale_and_missing_feeds_only_advise(self):
        self.snapshot(age=301)
        self.assertNotIn("permissionDecision", self.call()["hookSpecificOutput"])
        self.snapshot(unavailable=["GitHub"])
        with patch.object(d, "infer", side_effect=AssertionError("must not infer")):
            self.call()

    def test_retry_is_once_and_action_bound(self):
        self.call()
        state = d.State(self.root)
        identifier = state.db.execute("SELECT id FROM decisions").fetchone()[0]
        state.retry(identifier, time.time())
        state.close()
        different = {**self.payload, "tool_input": {"command": "git push"}}
        self.assertIn("permissionDecision", self.call(payload=different)["hookSpecificOutput"])
        self.assertIn("one-shot retry", self.call()["hookSpecificOutput"]["additionalContext"])
        self.assertIn("permissionDecision", self.call()["hookSpecificOutput"])

    def test_retry_consumption_is_atomic(self):
        state = d.State(self.root)
        identifier = state.save("ns", "act", "ev", self.result, time.time(), time.time() + 300)
        state.retry(identifier, time.time())
        state.close()

        def consume(_):
            state = d.State(self.root)
            try:
                return state.consume_retry("ns", "act", time.time())
            finally:
                state.close()

        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
            self.assertEqual(sum(pool.map(consume, range(4))), 1)

    def test_model_failure_preserves_only_existing_lease(self):
        self.call()
        state = d.State(self.root)
        before = state.db.execute("SELECT expires FROM decisions").fetchone()[0]
        state.close()
        self.snapshot(unavailable=["GitHub"])
        self.assertIn("permissionDecision", self.call()["hookSpecificOutput"])
        state = d.State(self.root)
        self.assertEqual(before, state.db.execute("SELECT expires FROM decisions").fetchone()[0])
        state.db.execute("UPDATE decisions SET expires=0")
        state.db.commit()
        state.close()
        self.assertNotIn("permissionDecision", self.call()["hookSpecificOutput"])

    def test_fresh_recovery_replaces_pause(self):
        self.call()
        self.report["status"] = "resolved"
        self.snapshot()
        result = {**self.result, "decision": "allow", "reason": "recovered"}
        self.assertIsNone(self.call(result))
        state = d.State(self.root)
        row = state.db.execute("SELECT namespace,action FROM decisions LIMIT 1").fetchone()
        self.assertIsNone(state.active(*row, time.time()))
        state.close()

    def test_namespaces_do_not_share_pause(self):
        self.call()
        self.snapshot(age=301)
        other = {**self.payload, "session_id": "two"}
        self.assertNotIn("permissionDecision", self.call(payload=other)["hookSpecificOutput"])

    def test_advisory_mode_never_denies(self):
        self.config["decision"] = {"mode": "advisory"}
        self.snapshot()
        self.assertNotIn("permissionDecision", self.call()["hookSpecificOutput"])

    def test_sanitizer_removes_secret_forms(self):
        for text in (
            "TOKEN=abc aws --password secret s3 ls",
            'curl -H "Authorization: Bearer secret" https://user:pass@example.com/a?token=secret',
            "gh --token=secret api test",
        ):
            cleaned, safe = d.sanitize(text)
            self.assertTrue(safe)
            self.assertNotIn("secret", cleaned.replace("[secret]", ""))
            self.assertNotIn("user:pass", cleaned)
        for text in ('python -c "print(secret)"', "cat <<EOF\nsecret", "echo $(cat key)"):
            self.assertEqual(d.sanitize(text), ("", False))

    def test_report_lifecycle_and_format_validation(self):
        feed = {"name": "GitHub", "url": "https://example.com", "format": "rss"}
        reports = evidence.parse(
            b"<rss><channel><item><guid>a</guid><title>Resolved incident</title><description>service restored</description></item></channel></rss>",
            feed,
            time.time(),
        )
        self.assertIn("restored", reports[0]["summary"])
        self.assertEqual(reports[0]["source_id"], "a")
        with self.assertRaises(ValueError):
            evidence.parse(b'<feed xmlns="http://www.w3.org/2005/Atom"/>', feed, time.time())

    def test_json_alias(self):
        import io

        with patch.object(h.urllib.request, "urlopen", return_value=io.BytesIO(b"[]")):
            self.assertEqual(
                h.fetch_feed({"name": "AWS", "url": "https://example.com", "format": "json"}), []
            )


if __name__ == "__main__":
    unittest.main()
