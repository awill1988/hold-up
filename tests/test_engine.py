#!/usr/bin/env python3
"""unit tests for claude provider status hook engine."""

import unittest
from pathlib import Path
import sys

# add scripts/ to python path
SCRIPTS_DIR = Path(__file__).resolve().parent.parent / "scripts"
sys.path.insert(0, str(SCRIPTS_DIR))

import provider_status  # noqa: E402

FIXTURES_DIR = Path(__file__).resolve().parent / "fixtures"


class TestStatusEngine(unittest.TestCase):
    def setUp(self) -> None:
        self.maxDiff = None

    def test_aws_json_parsing(self) -> None:
        raw_content = (FIXTURES_DIR / "aws_health.json").read_bytes()
        incidents = provider_status.parse_aws_json_feed(
            raw_content,
            provider="AWS",
            category="cloud",
            keywords=["ec2", "s3"],
            tool_matchers=["aws", "terraform"],
        )
        self.assertEqual(len(incidents), 1)
        inc = incidents[0]
        self.assertEqual(inc["provider"], "AWS")
        self.assertIn("Amazon Elastic Compute Cloud", inc["title"])
        self.assertEqual(inc["status"], "Degraded")
        self.assertIn("investigating increased API error rates", inc["summary"])
        self.assertEqual(inc["tool_matchers"], ["aws", "terraform"])

    def test_atom_parsing(self) -> None:
        raw_content = (FIXTURES_DIR / "gcp_status.atom").read_bytes()
        incidents = provider_status.parse_atom_feed(
            raw_content,
            provider="Google Cloud",
            category="cloud",
            keywords=["gke", "cloud storage"],
            tool_matchers=["gcloud", "kubectl"],
            max_age_hours=100000,
        )
        self.assertEqual(len(incidents), 1)
        inc = incidents[0]
        self.assertEqual(inc["provider"], "Google Cloud")
        self.assertIn("Google Kubernetes Engine", inc["title"])
        self.assertIn("GKE control plane latencies", inc["summary"])

    def test_rss_parsing_azure(self) -> None:
        raw_content = (FIXTURES_DIR / "azure_status.rss").read_bytes()
        incidents = provider_status.parse_rss_feed(
            raw_content,
            provider="Microsoft Azure",
            category="cloud",
            keywords=["virtual machines", "cosmos"],
            tool_matchers=["az", "terraform"],
            max_age_hours=100000,
        )
        self.assertEqual(len(incidents), 1)
        inc = incidents[0]
        self.assertEqual(inc["provider"], "Microsoft Azure")
        self.assertIn("Virtual Machines", inc["title"])
        self.assertEqual(inc["status"], "Investigating")

    def test_rss_parsing_github(self) -> None:
        raw_content = (FIXTURES_DIR / "github_status.rss").read_bytes()
        incidents = provider_status.parse_rss_feed(
            raw_content,
            provider="GitHub",
            category="vcs",
            keywords=["actions", "git operations"],
            tool_matchers=["git", "gh"],
            max_age_hours=100000,
        )
        self.assertEqual(len(incidents), 1)
        inc = incidents[0]
        self.assertEqual(inc["provider"], "GitHub")
        self.assertIn("GitHub Actions", inc["title"])
        self.assertEqual(inc["status"], "Investigating")

    def test_clean_html(self) -> None:
        html_input = "<p>Test <strong>alert</strong> with <a href='https://example.com'>link</a> &amp; special chars.</p>"
        cleaned = provider_status.clean_html(html_input)
        self.assertEqual(cleaned, "Test alert with link & special chars.")

    def test_filter_incidents_for_command(self) -> None:
        mock_incidents = [
            {
                "provider": "GitHub",
                "category": "vcs",
                "title": "GitHub Actions outage",
                "tool_matchers": ["git", "gh"],
            },
            {
                "provider": "AWS",
                "category": "cloud",
                "title": "EC2 API errors",
                "tool_matchers": ["aws", "terraform"],
            },
            {
                "provider": "Google Cloud",
                "category": "cloud",
                "title": "GKE control plane down",
                "tool_matchers": ["gcloud", "kubectl"],
            },
        ]

        # git command matches GitHub
        git_matches = provider_status.filter_incidents_for_command("git push origin main", mock_incidents)
        self.assertEqual(len(git_matches), 1)
        self.assertEqual(git_matches[0]["provider"], "GitHub")

        # aws command matches AWS
        aws_matches = provider_status.filter_incidents_for_command("aws s3 ls", mock_incidents)
        self.assertEqual(len(aws_matches), 1)
        self.assertEqual(aws_matches[0]["provider"], "AWS")

        # terraform matches cloud providers (AWS, GCP)
        tf_matches = provider_status.filter_incidents_for_command("terraform apply -auto-approve", mock_incidents)
        self.assertTrue(any(i["provider"] == "AWS" for i in tf_matches))
        self.assertTrue(any(i["provider"] == "Google Cloud" for i in tf_matches))
        self.assertFalse(any(i["provider"] == "GitHub" for i in tf_matches))

    def test_format_advisory_context(self) -> None:
        incidents = [
            {
                "provider": "GitHub",
                "category": "vcs",
                "title": "GitHub Actions queue degradation",
                "status": "Investigating",
                "summary": "Queued jobs are experiencing delayed execution.",
                "link": "https://www.githubstatus.com/incidents/gha-001",
            }
        ]
        context = provider_status.format_advisory_context(incidents, trigger_context="git push")
        self.assertIn("<provider_status_advisory>", context)
        self.assertIn("git push", context)
        self.assertIn("GitHub Actions queue degradation", context)
        self.assertIn("https://www.githubstatus.com/incidents/gha-001", context)
        self.assertIn("</provider_status_advisory>", context)


if __name__ == "__main__":
    unittest.main()
