"""AWS update selection, encoding, identity, and incomplete evidence contracts."""

import json
import sys
import time
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from holdup import aws, engine, evidence


class AwsEvidence(unittest.TestCase):
    def setUp(self):
        self.event = {
            "arn": "arn:aws:health:me-central-1::event/EC2/ISSUE/one",
            "region_name": "UAE",
            "summary": "old resolved issue",
            "status": "3",
            "date": 1,
            "event_log": [
                {
                    "timestamp": 20,
                    "summary": "current impact",
                    "message": "x" * 1400 + " launches still failing",
                    "status": 3,
                },
                {
                    "timestamp": "10",
                    "summary": "old",
                    "message": "network issue resolved",
                    "status": 2,
                },
            ],
        }
        self.feed = {
            "name": "AWS",
            "url": "https://health.aws.amazon.com/public/currentevents",
            "format": "aws-json",
        }

    def parse(self, event=None):
        return aws.normalize(json.dumps([event or self.event]).encode())[0]

    def test_encodings_envelopes_and_complete_latest_update(self):
        for encoding in ("utf-8", "utf-8-sig", "utf-16"):
            for envelope in ([self.event], {"current_events": [self.event]}):
                with self.subTest(encoding=encoding, envelope=type(envelope)):
                    report = evidence.parse(
                        json.dumps(envelope).encode(encoding), self.feed, time.time()
                    )[0]
                    self.assertEqual(report["summary"], self.event["event_log"][0]["message"])
                    self.assertEqual(report["region"], "me-central-1")
                    self.assertEqual(report["region_display"], "UAE")
                    self.assertEqual(report["source_id"], self.event["arn"])
                    self.assertEqual(report["status"], "unknown")
                    self.assertEqual(report["provider_status"], 3)
                    self.assertFalse(report["truncated"])

    def test_duplicates_and_conflicts(self):
        self.event["event_log"].append(dict(self.event["event_log"][0]))
        self.assertFalse(self.parse()["conflicting_updates"])
        self.event["event_log"][-1]["message"] = "service recovered"
        report = self.parse()
        self.assertTrue(report["conflicting_updates"])
        self.assertIn("service recovered", report["summary"])
        self.assertIn("launches still failing", report["summary"])

    def test_scope_conflict_is_not_silently_resolved(self):
        self.event["region"] = "us-west-2"
        report = self.parse()
        self.assertTrue(report["scope_uncertain"])
        self.assertEqual(report["region"], "")

    def test_malformed_logs_never_fall_back(self):
        for log in (
            None,
            [],
            {},
            [None],
            [{"timestamp": True}],
            [{"timestamp": "yesterday", "summary": "s", "message": "m"}],
            [{"timestamp": float("inf"), "summary": "s", "message": "m"}],
        ):
            with self.subTest(log=log), self.assertRaises(ValueError):
                self.parse({**self.event, "event_log": log})

    def test_absent_log_falls_back_and_explicit_recovery_normalizes(self):
        del self.event["event_log"]
        self.event.update(description="complete recovery", status_description="resolved")
        self.assertEqual(self.parse()["summary"], "complete recovery")
        self.assertEqual(self.parse()["status"], "resolved")

    def test_invalid_and_oversized_input(self):
        for raw in (b"\xff", b"{}", b"[null]", b" " * (aws.MAX_BYTES + 1)):
            with self.assertRaises(ValueError):
                aws.normalize(raw)

    def test_legacy_does_not_keyword_gate_or_drop_historical_recovery(self):
        reports = engine.parse_aws_json_feed(
            json.dumps([self.event]).encode(), "AWS", "cloud", ["absent-keyword"], ["aws"]
        )
        self.assertEqual(len(reports), 1)
        self.assertIn("current impact", reports[0]["title"])

    def test_public_capture(self):
        root = Path(__file__).with_name("fixtures")
        reports = evidence.parse(
            (root / "aws-public-2026-10-05.bin").read_bytes(), self.feed, time.time()
        )
        self.assertTrue(reports)
        self.assertTrue(all(report["source_id"].startswith("arn:") for report in reports))


if __name__ == "__main__":
    unittest.main()
