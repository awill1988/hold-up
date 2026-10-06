"""adversarial regressions for scope, feed trust, cache, and execution limits."""

import contextlib
import io
import json
import subprocess
import sys
import time
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import hold_up as h


class TestAdversarial(unittest.TestCase):
    def test_executable_position_and_unsupported_syntax(self):
        for command in (
            "echo aws",
            "printf '%s' git",
            "cat /tmp/aws",
            "aws s3 ls; echo ok",
            "git fetch | cat",
            "echo $(aws s3 ls)",
            "command -v aws",
        ):
            with self.subTest(command=command):
                self.assertEqual(h.command_providers(command, h.EMBEDDED_DEFAULT_FEEDS), set())
        for command in (
            "aws s3 ls",
            "/usr/bin/aws s3 ls",
            "env AWS_REGION=us-east-1 aws s3 ls",
            "command -- aws s3 ls",
        ):
            self.assertEqual(h.command_providers(command, h.EMBEDDED_DEFAULT_FEEDS), {"AWS"})

    def test_region_and_profile_precedence(self):
        env = {"AWS_REGION": "us-east-1", "AWS_PROFILE": "inherited"}
        with patch.object(h, "resolve_aws_profile_region", return_value="eu-west-1") as lookup:
            scope = h.extract_scope_from_command(
                "AWS_REGION=ap-southeast-2 AWS_PROFILE=local aws --profile selected --region us-west-2 s3 ls",
                env=env,
            )
            self.assertEqual(scope["regions"], {"us-west-2"})
            self.assertEqual(scope["profiles"], {"selected"})
            lookup.assert_not_called()
            scope = h.extract_scope_from_command("aws --profile selected s3 ls", env={})
            self.assertEqual(scope["regions"], {"eu-west-1"})
            lookup.assert_called_with("selected", None)
        scope = h.extract_scope_from_command("AWS_DEFAULT_REGION=us-west-2 aws s3 ls", env=env)
        self.assertEqual(scope["regions"], {"us-west-2"})

    def test_gcp_and_azure_flags_override_environment(self):
        scope = h.extract_scope_from_command(
            "gcloud --project selected --zone us-west1-a compute instances list",
            env={"GCP_PROJECT": "old", "CLOUDSDK_COMPUTE_REGION": "us-east1"},
        )
        self.assertEqual(scope["regions"], {"us-west1"})
        self.assertEqual(scope["projects"], {"selected"})
        scope = h.extract_scope_from_command(
            "az --location westus vm list", env={"ARM_LOCATION": "eastus"}
        )
        self.assertEqual(scope["regions"], {"westus"})

    def test_prompt_aliases_and_global_token_boundaries(self):
        for prompt, provider in (
            ("GitHub is down", "GitHub"),
            ("GCP incident", "Google Cloud"),
            ("Amazon Web Services latency", "AWS"),
            ("Azure unavailable", "Microsoft Azure"),
        ):
            self.assertEqual(
                h.extract_scope_from_command(prompt=prompt, env={})["providers"], {provider}
            )
        self.assertEqual(
            h.extract_scope_from_command(prompt="githubish task", env={})["providers"], set()
        )
        for title in ("us-east-1 costs delayed", "entrance unavailable", "requests slow"):
            self.assertFalse(h.is_global_infrastructure_incident({"title": title}))
        self.assertTrue(
            h.is_global_infrastructure_incident({"title": "AWS STS authentication failures"})
        )

    def test_format_mismatch_is_unavailable_not_empty_success(self):
        pairs = [
            ("rss", b'<feed xmlns="http://www.w3.org/2005/Atom"/>'),
            ("atom", b"<rss><channel/></rss>"),
            ("rss", b"<rss/>"),
            ("rss", b"<html/>"),
            ("aws-json", b'{"unexpected": []}'),
            ("aws-json", b"[{}]"),
            ("aws-json", b'[{"summary": "outage", "status_description": []}]'),
            ("unknown", b"[]"),
        ]
        for fmt, content in pairs:
            feed = {"name": "example", "url": "https://example.invalid", "format": fmt}
            with (
                self.subTest(fmt=fmt, content=content),
                patch.object(h.urllib.request, "urlopen", return_value=io.BytesIO(content)),
            ):
                with contextlib.redirect_stderr(io.StringIO()):
                    data = h.refresh_cache([feed])
                self.assertEqual(data["unavailable_providers"], ["example"])

    def test_valid_empty_feeds_and_malformed_xml(self):
        for fmt, content in (
            ("rss", b"<rss><channel/></rss>"),
            ("atom", b'<feed xmlns="http://www.w3.org/2005/Atom"/>'),
            ("aws-json", b'{"current_events": []}'),
        ):
            with patch.object(h.urllib.request, "urlopen", return_value=io.BytesIO(content)):
                self.assertEqual(
                    h.fetch_feed(
                        {"name": "example", "url": "https://example.invalid", "format": fmt}
                    ),
                    [],
                )
        with patch.object(h.urllib.request, "urlopen", return_value=io.BytesIO(b"<rss>")):
            with self.assertRaises(Exception):
                h.fetch_feed({"name": "example", "url": "https://example.invalid"})

    def test_size_limit_and_interrupted_read(self):
        feed = {"name": "example", "url": "https://example.invalid"}
        for response in (io.BytesIO(b"x" * (h.MAX_FEED_BYTES + 1)),):
            with patch.object(h.urllib.request, "urlopen", return_value=response):
                with self.assertRaisesRegex(ValueError, "size limit"):
                    h.fetch_feed(feed)
        with patch.object(h.urllib.request, "urlopen", side_effect=TimeoutError("interrupted")):
            with contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(h.refresh_cache([feed])["unavailable_providers"], ["example"])

    def test_cache_schema_rejects_corruption(self):
        good = {
            "version": 1,
            "timestamp": time.time(),
            "active_incidents": [],
            "unavailable_providers": [],
        }
        feeds = [{"name": "example"}]
        self.assertTrue(h.valid_cache(good, feeds))
        for replacement in (
            {"version": True},
            {"version": 2},
            {"timestamp": float("nan")},
            {"timestamp": "now"},
            {"active_incidents": [{}]},
            {"active_incidents": [{"provider": "example", "title": [], "status": "active"}]},
            {"unavailable_providers": ["unknown"]},
        ):
            self.assertFalse(h.valid_cache({**good, **replacement}, feeds))

    def test_invalid_fresh_cache_is_refreshed(self):
        cached = {
            "version": 1,
            "timestamp": time.time(),
            "active_incidents": [{}],
            "unavailable_providers": [],
        }
        refreshed = {**cached, "active_incidents": []}
        with patch.object(Path, "read_text", return_value=json.dumps(cached)):
            with patch.object(h, "refresh_cache", return_value=refreshed) as refresh:
                self.assertEqual(h.get_status_data([], {}, Path("unused.json")), refreshed)
                refresh.assert_called_once()

    def test_supervisor_kills_blocked_worker_without_output(self):
        original = subprocess.Popen
        workers = []

        def blocked_worker(*args, **kwargs):
            process = original(
                [sys.executable, "-c", "import time; time.sleep(30)"],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            workers.append(process)
            return process

        stdout, stderr = io.StringIO(), io.StringIO()
        with patch.object(h.subprocess, "Popen", side_effect=blocked_worker):
            with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                started = time.monotonic()
                self.assertEqual(h.supervise_hook([], timeout=0.1), 0)
        self.assertLess(time.monotonic() - started, 3)
        self.assertIsNotNone(workers[0].poll())
        self.assertEqual(stdout.getvalue(), "")
        self.assertIn("status unavailable", stderr.getvalue())


if __name__ == "__main__":
    unittest.main()
