#!/usr/bin/env python3
"""unit tests for claude provider status hook engine."""

import unittest
from pathlib import Path
import sys

SCRIPTS_DIR = Path(__file__).resolve().parent.parent / "scripts"
sys.path.insert(0, str(SCRIPTS_DIR))

import hold_up as provider_status  # noqa: E402

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

    def test_extract_scope_aws(self) -> None:
        # CLI flags
        scope = provider_status.extract_scope_from_command(
            "aws --profile staging --region us-west-2 s3 ls",
            env={},
        )
        self.assertIn("AWS", scope["providers"])
        self.assertIn("us-west-2", scope["regions"])
        self.assertIn("s3", scope["services"])
        self.assertIn("staging", scope["profiles"])

        # Canonical environment variables
        scope_env = provider_status.extract_scope_from_command(
            "aws ec2 describe-instances",
            env={"AWS_REGION": "eu-west-1", "AWS_PROFILE": "prod"},
        )
        self.assertIn("AWS", scope_env["providers"])
        self.assertIn("eu-west-1", scope_env["regions"])
        self.assertIn("ec2", scope_env["services"])
        self.assertIn("prod", scope_env["profiles"])

    def test_extract_scope_gcp(self) -> None:
        scope = provider_status.extract_scope_from_command(
            "gcloud compute instances list --project my-gcp-prod --zone us-central1-a",
            env={},
        )
        self.assertIn("Google Cloud", scope["providers"])
        self.assertIn("us-central1", scope["regions"])
        self.assertIn("compute engine", scope["services"])
        self.assertIn("my-gcp-prod", scope["projects"])

    def test_extract_scope_azure(self) -> None:
        scope = provider_status.extract_scope_from_command(
            "az aks get-credentials --resource-group prod-rg --name prod-cluster --location eastus",
            env={},
        )
        self.assertIn("Microsoft Azure", scope["providers"])
        self.assertIn("eastus", scope["regions"])
        self.assertIn("aks", scope["services"])

    def test_classify_incident_relevance(self) -> None:
        scope_virginia = {
            "providers": {"AWS"},
            "regions": {"us-east-1"},
            "services": {"s3"},
        }

        # 1. Direct regional match
        inc_va = {
            "provider": "AWS",
            "title": "Amazon S3 - us-east-1: Increased Error Rates",
            "summary": "Investigating elevated errors in Northern Virginia.",
        }
        tier, _ = provider_status.classify_incident_relevance(inc_va, scope_virginia)
        self.assertEqual(tier, "direct")

        # 2. Disjoint region (Sydney outage when targeting Virginia)
        inc_sydney = {
            "provider": "AWS",
            "title": "Amazon EC2 - ap-southeast-2: Latency Issues",
            "summary": "Investigating instance launch issues in Sydney.",
        }
        tier, _ = provider_status.classify_incident_relevance(inc_sydney, scope_virginia)
        self.assertEqual(tier, "disjoint_region")

        # 3. Global infrastructure outage (IAM)
        inc_iam = {
            "provider": "AWS",
            "title": "AWS IAM - Global: Authentication Delays",
            "summary": "IAM token generation latency globally.",
        }
        tier, _ = provider_status.classify_incident_relevance(inc_iam, scope_virginia)
        self.assertEqual(tier, "provider_global")

        # 4. Unrelated provider
        inc_gcp = {
            "provider": "Google Cloud",
            "title": "GKE control plane degraded in us-central1",
            "summary": "Latency in us-central1.",
        }
        tier, _ = provider_status.classify_incident_relevance(inc_gcp, scope_virginia)
        self.assertEqual(tier, "unrelated")

    def test_filter_incidents_with_scope_suppression(self) -> None:
        mock_incidents = [
            {
                "provider": "AWS",
                "category": "cloud",
                "title": "Amazon S3 - us-east-1: Increased Errors",
                "summary": "Error rates elevated in Northern Virginia.",
                "tool_matchers": ["aws", "terraform"],
            },
            {
                "provider": "AWS",
                "category": "cloud",
                "title": "Amazon RDS - ap-southeast-2: Failover Delays",
                "summary": "Investigating RDS failover delays in Sydney.",
                "tool_matchers": ["aws", "terraform"],
            },
            {
                "provider": "AWS",
                "category": "cloud",
                "title": "AWS IAM: Global Authentication Latency",
                "summary": "Investigating elevated latencies for IAM requests globally.",
                "tool_matchers": ["aws", "terraform"],
            },
            {
                "provider": "GitHub",
                "category": "vcs",
                "title": "GitHub Actions queue degradation",
                "summary": "Queued jobs delayed.",
                "tool_matchers": ["git", "gh"],
            },
        ]

        # Command targets AWS in us-east-1
        cmd = "aws --region us-east-1 s3 ls"
        kept, scope = provider_status.filter_incidents_for_command(cmd, mock_incidents, env={})

        self.assertIn("AWS", scope["providers"])
        self.assertIn("us-east-1", scope["regions"])

        # Should keep us-east-1 S3 and Global IAM; should suppress Sydney RDS and GitHub Actions
        kept_titles = [i["title"] for i in kept]
        self.assertIn("Amazon S3 - us-east-1: Increased Errors", kept_titles)
        self.assertIn("AWS IAM: Global Authentication Latency", kept_titles)
        self.assertNotIn("Amazon RDS - ap-southeast-2: Failover Delays", kept_titles)
        self.assertNotIn("GitHub Actions queue degradation", kept_titles)

    def test_format_advisory_context(self) -> None:
        incidents = [
            {
                "provider": "AWS",
                "category": "cloud",
                "title": "Amazon S3 - us-east-1: Increased Errors",
                "status": "Investigating",
                "summary": "Error rates elevated.",
                "link": "https://health.aws.amazon.com",
                "_relevance_tier": "direct",
            }
        ]
        scope = {
            "providers": {"AWS"},
            "regions": {"us-east-1"},
            "services": {"s3"},
            "profiles": set(),
        }
        context = provider_status.format_advisory_context(
            incidents,
            trigger_context="aws --region us-east-1 s3 ls",
            scope=scope,
        )
        self.assertIn("<provider_status_advisory>", context)
        self.assertIn("[DIRECT IMPACT]", context)
        self.assertIn("aws --region us-east-1 s3 ls", context)
        self.assertIn("us-east-1", context)
        self.assertIn("</provider_status_advisory>", context)


if __name__ == "__main__":
    unittest.main()
