"""Qualification failures must never enable action denial."""

import contextlib
import io
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from holdup import decision as d
from holdup import evaluate


class EvaluationGate(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.case = {
            "name": "affected",
            "action": {"providers": ["GitHub"], "context_complete": True},
            "reports": [{"id": "one", "provider": "GitHub"}],
            "expected_pause": True,
        }
        self.result = {
            "decision": "pause",
            "reason": "affected operation",
            "evidence_ids": ["one"],
            "providers": ["GitHub"],
        }

    def run_gate(self, result=None):
        with (
            patch.object(evaluate, "cases", return_value=[self.case]),
            patch.object(evaluate, "qualification_cases", return_value=[self.case]),
            patch.object(d, "runtime_fingerprint", return_value="fixture"),
            patch.object(d, "infer", return_value=result or self.result),
            contextlib.redirect_stdout(io.StringIO()),
        ):
            status = evaluate.run(self.root, qualification=True)
        ready = json.loads((self.root / "readiness.json").read_text())
        return status, ready

    def test_passing_fixture_writes_policy_bound_readiness(self):
        status, ready = self.run_gate()
        self.assertEqual(status, 0)
        self.assertTrue(ready["passed"])
        self.assertEqual(ready["policy_digest"], d.policy_digest())
        self.assertEqual(ready["cases"], 3)

    def test_missed_pause_fails_qualification(self):
        status, ready = self.run_gate({**self.result, "decision": "allow"})
        self.assertEqual(status, 1)
        self.assertFalse(ready["passed"])
        self.assertEqual(ready["recall"], 0)

    def test_development_corpus_never_grants_readiness(self):
        with (
            patch.object(evaluate, "cases", return_value=[self.case]),
            patch.object(d, "infer", return_value=self.result),
            contextlib.redirect_stdout(io.StringIO()),
        ):
            self.assertEqual(evaluate.run(self.root), 1)
        self.assertFalse(d.enforcement_ready(self.root))

    def test_invalid_provider_fails_qualification(self):
        status, ready = self.run_gate({**self.result, "providers": ["AWS"]})
        self.assertEqual(status, 1)
        self.assertFalse(ready["passed"])

    def test_protected_pause_fails_even_if_other_gates_pass(self):
        self.case["protected"] = True
        status, ready = self.run_gate()
        self.assertEqual(status, 1)
        self.assertFalse(ready["passed"])
        self.assertEqual(ready["protected_pauses"], 3)

    def test_policy_changed_during_run_cannot_be_certified(self):
        with patch.object(d, "policy_digest", side_effect=["initial", "changed"]):
            status, ready = self.run_gate()
        self.assertEqual(status, 1)
        self.assertFalse(ready["passed"])
        self.assertEqual(ready["policy_digest"], "initial")


if __name__ == "__main__":
    unittest.main()
