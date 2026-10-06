#!/usr/bin/env python3
"""cloud and vcs infrastructure status hook for claude code.

monitors upstream status feeds for cloud providers (aws, gcp, azure)
and vcs providers (github, gitlab, bitbucket) configured in status_feeds.json.
maintains an atomic disk cache and injects advisory context into claude code
lifecycle events (SessionStart, UserPromptSubmit, PostToolUseFailure).
intercepts CLI flags, subcommands, prompt tokens, and canonical environment
variables to perform precision scope and regional relevance filtering.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import email.utils
import html
import json
import os
import re
import sys
import time
import urllib.request
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

DEFAULT_CACHE_TTL_SECONDS = 300
DEFAULT_TIMEOUT_SECONDS = 2.5
MAX_INCIDENT_AGE_HOURS = 72

AWS_REGION_ALIASES = {
    "n. virginia": "us-east-1",
    "northern virginia": "us-east-1",
    "ohio": "us-east-2",
    "oregon": "us-west-2",
    "n. california": "us-west-1",
    "northern california": "us-west-1",
    "ireland": "eu-west-1",
    "london": "eu-west-2",
    "paris": "eu-west-3",
    "frankfurt": "eu-central-1",
    "tokyo": "ap-northeast-1",
    "seoul": "ap-northeast-2",
    "singapore": "ap-southeast-1",
    "sydney": "ap-southeast-2",
    "sao paulo": "sa-east-1",
    "mumbai": "ap-south-1",
}

AZURE_LOCATION_ALIASES = {
    "east us": "eastus",
    "east us 2": "eastus2",
    "west us": "westus",
    "west us 2": "westus2",
    "west us 3": "westus3",
    "central us": "centralus",
    "north central us": "northcentralus",
    "south central us": "southcentralus",
    "west europe": "westeurope",
    "north europe": "northeurope",
    "uk south": "uksouth",
    "uk west": "ukwest",
}

EMBEDDED_DEFAULT_FEEDS = [
    {
        "name": "GitHub",
        "category": "vcs",
        "url": "https://www.githubstatus.com/history.rss",
        "format": "rss",
        "enabled": True,
        "tool_matchers": ["git", "gh"],
        "keywords": ["actions", "git operations", "api requests", "webhooks", "codespaces", "pull requests"],
    },
    {
        "name": "GitLab",
        "category": "vcs",
        "url": "https://status.gitlab.com/pages/5b36dc6502d06804c08349f7/rss",
        "format": "rss",
        "enabled": True,
        "tool_matchers": ["git", "gitlab", "glab"],
        "keywords": ["ci/cd", "git operations", "runners", "api", "repositories"],
    },
    {
        "name": "Bitbucket",
        "category": "vcs",
        "url": "https://bitbucket.status.atlassian.com/history.rss",
        "format": "rss",
        "enabled": True,
        "tool_matchers": ["git", "bb"],
        "keywords": ["pipelines", "git", "api", "cloud"],
    },
    {
        "name": "AWS",
        "category": "cloud",
        "url": "https://health.aws.amazon.com/public/currentevents",
        "format": "aws-json",
        "enabled": True,
        "tool_matchers": ["aws", "terraform", "tofu", "cdk", "serverless", "sam", "pulumi"],
        "keywords": ["ec2", "s3", "lambda", "ecs", "eks", "rds", "dynamodb", "iam", "cloudformation", "route53", "vpc"],
    },
    {
        "name": "Google Cloud",
        "category": "cloud",
        "url": "https://status.cloud.google.com/feed.atom",
        "format": "atom",
        "enabled": True,
        "tool_matchers": ["gcloud", "gsutil", "bq", "terraform", "tofu", "kubectl", "helm"],
        "keywords": ["compute engine", "gke", "cloud storage", "cloud run", "networking", "iam", "bigquery"],
    },
    {
        "name": "Microsoft Azure",
        "category": "cloud",
        "url": "https://azure.status.microsoft/en-us/status/feed/",
        "format": "rss",
        "enabled": True,
        "tool_matchers": ["az", "terraform", "tofu", "bicep", "arm", "kubectl", "helm"],
        "keywords": ["virtual machines", "aks", "storage", "entra", "functions", "cosmos"],
    },
]


def resolve_cache_paths(explicit_dir: Optional[str] = None) -> Tuple[Path, Path]:
    """resolves cache directory and status cache file path."""
    if explicit_dir:
        base_dir = Path(explicit_dir)
    elif os.environ.get("CLAUDE_CACHE_DIR"):
        base_dir = Path(os.environ["CLAUDE_CACHE_DIR"]) / "provider-status"
    else:
        base_dir = Path.home() / ".cache" / "claude-provider-status"

    try:
        base_dir.mkdir(parents=True, exist_ok=True)
    except Exception:
        base_dir = Path("/tmp") / "claude-provider-status"
        base_dir.mkdir(parents=True, exist_ok=True)

    return base_dir, base_dir / "status_cache.json"


def resolve_aws_profile_region(profile_name: str, config_path: Optional[Path] = None) -> Optional[str]:
    """parses ~/.aws/config to resolve default region for a specified profile."""
    if not profile_name:
        return None
    cfg_file = config_path or Path(os.environ.get("AWS_CONFIG_FILE", Path.home() / ".aws" / "config"))
    if not cfg_file.is_file():
        return None
    try:
        import configparser
        parser = configparser.RawConfigParser()
        parser.read(str(cfg_file), encoding="utf-8")
        section = f"profile {profile_name}" if profile_name != "default" else "default"
        if parser.has_section(section) and parser.has_option(section, "region"):
            return parser.get(section, "region").strip()
    except Exception:
        pass
    return None


def extract_scope_from_command(
    command: str = "",
    prompt: str = "",
    env: Optional[Dict[str, str]] = None,
    aws_config_path: Optional[Path] = None,
) -> Dict[str, Any]:
    """intercepts CLI tokens, flags, and canonical environment variables to infer target scope."""
    if env is None:
        env = dict(os.environ)

    scope: Dict[str, Any] = {
        "providers": set(),
        "services": set(),
        "regions": set(),
        "profiles": set(),
        "projects": set(),
        "detected_via": [],
    }

    full_text = f"{command} {prompt}".strip()
    full_lower = full_text.lower()

    # 1. Detect Primary CLI Binary
    cmd_tokens = [tok.lower().strip() for tok in re.split(r"[\s/]+", command) if tok.strip()]
    primary_cli = None
    if "aws" in cmd_tokens:
        primary_cli = "AWS"
        scope["providers"].add("AWS")
    elif any(tok in cmd_tokens for tok in ("gcloud", "gsutil", "bq")):
        primary_cli = "Google Cloud"
        scope["providers"].add("Google Cloud")
    elif "az" in cmd_tokens:
        primary_cli = "Microsoft Azure"
        scope["providers"].add("Microsoft Azure")
    elif any(tok in cmd_tokens for tok in ("git", "gh")):
        primary_cli = "GitHub"
        scope["providers"].add("GitHub")
    elif "glab" in cmd_tokens:
        primary_cli = "GitLab"
        scope["providers"].add("GitLab")
    elif "bb" in cmd_tokens:
        primary_cli = "Bitbucket"
        scope["providers"].add("Bitbucket")

    # 2. Inspect Environment Variables (scoped to primary_cli if known, else check all)
    # AWS
    if primary_cli in (None, "AWS"):
        aws_env_reg = env.get("AWS_REGION") or env.get("AWS_DEFAULT_REGION")
        if aws_env_reg:
            reg_clean = aws_env_reg.lower().strip()
            scope["regions"].add(reg_clean)
            if not primary_cli:
                scope["providers"].add("AWS")
            scope["detected_via"].append(f"env:AWS_REGION={reg_clean}")

        aws_env_prof = env.get("AWS_PROFILE") or env.get("AWS_DEFAULT_PROFILE")
        if aws_env_prof:
            prof_clean = aws_env_prof.strip()
            scope["profiles"].add(prof_clean)
            if not primary_cli:
                scope["providers"].add("AWS")
            resolved_reg = resolve_aws_profile_region(prof_clean, aws_config_path)
            if resolved_reg:
                scope["regions"].add(resolved_reg.lower().strip())
                scope["detected_via"].append(f"env:AWS_PROFILE={prof_clean} -> region:{resolved_reg}")

    # Google Cloud
    if primary_cli in (None, "Google Cloud"):
        gcp_env_reg = env.get("CLOUDSDK_COMPUTE_REGION") or env.get("CLOUDSDK_CORE_REGION")
        if gcp_env_reg:
            reg_clean = gcp_env_reg.lower().strip()
            scope["regions"].add(reg_clean)
            if not primary_cli:
                scope["providers"].add("Google Cloud")
            scope["detected_via"].append(f"env:CLOUDSDK_COMPUTE_REGION={reg_clean}")

        gcp_env_proj = env.get("CLOUDSDK_CORE_PROJECT") or env.get("GOOGLE_CLOUD_PROJECT") or env.get("GCP_PROJECT")
        if gcp_env_proj:
            proj_clean = gcp_env_proj.strip()
            scope["projects"].add(proj_clean)
            if not primary_cli:
                scope["providers"].add("Google Cloud")
            scope["detected_via"].append(f"env:GCP_PROJECT={proj_clean}")

    # Azure
    if primary_cli in (None, "Microsoft Azure"):
        az_env_loc = env.get("AZURE_DEFAULTS_LOCATION") or env.get("AZURE_DEFAULT_LOCATION") or env.get("ARM_LOCATION")
        if az_env_loc:
            norm_az = az_env_loc.lower().replace(" ", "").strip()
            scope["regions"].add(norm_az)
            if not primary_cli:
                scope["providers"].add("Microsoft Azure")
            scope["detected_via"].append(f"env:AZURE_DEFAULTS_LOCATION={az_env_loc}")

    # 3. Extract Flags & Services based on context
    # AWS
    if primary_cli == "AWS" or (primary_cli is None and "aws" in full_lower):
        aws_flags_prof = re.findall(r"--profile[ =]([a-zA-Z0-9._-]+)", command)
        for p in aws_flags_prof:
            scope["profiles"].add(p)
            scope["providers"].add("AWS")
            resolved = resolve_aws_profile_region(p, aws_config_path)
            if resolved:
                scope["regions"].add(resolved.lower().strip())
                scope["detected_via"].append(f"flag:--profile {p} -> region:{resolved}")
            else:
                scope["detected_via"].append(f"flag:--profile {p}")

        aws_flags_reg = re.findall(r"(?:--region|-r)[ =]([a-z0-9-]+)", command)
        for r in aws_flags_reg:
            scope["regions"].add(r.lower().strip())
            scope["providers"].add("AWS")
            scope["detected_via"].append(f"flag:--region {r}")

        aws_services = [
            "s3", "ec2", "lambda", "ecs", "eks", "rds", "dynamodb", "iam",
            "route53", "cloudformation", "sqs", "sns", "sts", "secretsmanager",
            "ssm", "stepfunctions", "bedrock", "vpc",
        ]
        for s in aws_services:
            if s in cmd_tokens:
                scope["services"].add(s)

    # Google Cloud
    if primary_cli == "Google Cloud" or (primary_cli is None and any(t in full_lower for t in ("gcloud", "gcp", "google cloud"))):
        gcp_flags_proj = re.findall(r"--project[ =]([a-zA-Z0-9._-]+)", command)
        for proj in gcp_flags_proj:
            scope["projects"].add(proj)
            scope["providers"].add("Google Cloud")
            scope["detected_via"].append(f"flag:--project {proj}")

        gcp_flags_reg = re.findall(r"--region[ =]([a-z0-9-]+)", command)
        for r in gcp_flags_reg:
            scope["regions"].add(r.lower().strip())
            scope["providers"].add("Google Cloud")
            scope["detected_via"].append(f"flag:--region {r}")

        gcp_flags_zone = re.findall(r"--zone[ =]([a-z0-9-]+)", command)
        for z in gcp_flags_zone:
            reg_part = re.sub(r"-[a-z]$", "", z.lower().strip())
            scope["regions"].add(reg_part)
            scope["providers"].add("Google Cloud")
            scope["detected_via"].append(f"flag:--zone {z} -> region:{reg_part}")

        gcp_services = {
            "compute": "compute engine", "container": "gke", "gke": "gke",
            "storage": "cloud storage", "gsutil": "cloud storage", "run": "cloud run",
            "bigquery": "bigquery", "bq": "bigquery", "iam": "iam",
            "functions": "cloud functions", "pubsub": "pubsub",
        }
        for tok in cmd_tokens:
            if tok in gcp_services:
                scope["services"].add(gcp_services[tok])

    # Azure
    if primary_cli == "Microsoft Azure" or (primary_cli is None and any(t in full_lower for t in ("azure", " az "))):
        az_flags_loc = re.findall(r"(?:--location|-l)[ =]([a-zA-Z0-9-]+)", command)
        for loc in az_flags_loc:
            norm_l = loc.lower().replace(" ", "").strip()
            scope["regions"].add(norm_l)
            scope["providers"].add("Microsoft Azure")
            scope["detected_via"].append(f"flag:--location {loc}")

        az_services = {
            "vm": "virtual machines", "aks": "aks", "storage": "storage",
            "cosmosdb": "cosmos", "functionapp": "functions", "webapp": "app service",
        }
        for tok in cmd_tokens:
            if tok in az_services:
                scope["services"].add(az_services[tok])

    # VCS
    if primary_cli == "GitHub":
        if "gh" in cmd_tokens:
            if any(t in cmd_tokens for t in ("run", "workflow", "actions")):
                scope["services"].add("actions")
            if "pr" in cmd_tokens:
                scope["services"].add("pull requests")
            if "issue" in cmd_tokens:
                scope["services"].add("issues")

    # IaC & Containers (if no primary_cli)
    if primary_cli is None:
        if any(tok in cmd_tokens for tok in ("terraform", "tofu", "terragrunt", "pulumi")):
            if not scope["providers"]:
                scope["providers"].update(["AWS", "Google Cloud", "Microsoft Azure"])
        if any(tok in cmd_tokens for tok in ("kubectl", "helm")):
            if not scope["providers"]:
                scope["providers"].update(["AWS", "Google Cloud", "Microsoft Azure"])

    # 4. Extract standard region regex patterns from prompt / text if still unscoped
    if not scope["regions"]:
        aws_pattern = re.findall(r"\b([a-z]{2}-(?:north|south|east|west|central)-\d+)\b", full_lower)
        for r in aws_pattern:
            scope["regions"].add(r)
            if not primary_cli:
                scope["providers"].add("AWS")

        gcp_pattern = re.findall(r"\b([a-z]+-(?:central|east|west|north|south|northeast|southeast)\d+)\b", full_lower)
        for r in gcp_pattern:
            scope["regions"].add(r)
            if not primary_cli:
                scope["providers"].add("Google Cloud")

        for alias, slug in AWS_REGION_ALIASES.items():
            if alias in full_lower:
                scope["regions"].add(slug)
                if not primary_cli:
                    scope["providers"].add("AWS")

        for alias, slug in AZURE_LOCATION_ALIASES.items():
            if alias in full_lower:
                scope["regions"].add(slug)
                if not primary_cli:
                    scope["providers"].add("Microsoft Azure")

    return scope


def extract_incident_regions(incident: Dict[str, Any]) -> List[str]:
    """extracts region identifiers from incident title, summary, or metadata."""
    found: List[str] = []
    haystack = f"{incident.get('title', '')} {incident.get('summary', '')}".lower()

    aws_matches = re.findall(r"\b([a-z]{2}-(?:north|south|east|west|central)-\d+)\b", haystack)
    found.extend(aws_matches)
    for alias, slug in AWS_REGION_ALIASES.items():
        if alias in haystack:
            found.append(slug)

    gcp_matches = re.findall(r"\b([a-z]+-(?:central|east|west|north|south|northeast|southeast)\d+)\b", haystack)
    found.extend(gcp_matches)

    for alias, slug in AZURE_LOCATION_ALIASES.items():
        if alias in haystack:
            found.append(slug)
    az_slug_matches = re.findall(r"\b(eastus2?|westus[23]?|centralus|westeurope|northeurope|uksouth|ukwest)\b", haystack)
    found.extend(az_slug_matches)

    return list(dict.fromkeys(found))


def is_global_infrastructure_incident(incident: Dict[str, Any]) -> bool:
    """checks if the incident affects global, cross-region infrastructure (IAM, DNS, Route53, etc.)."""
    haystack = f"{incident.get('title', '')} {incident.get('summary', '')}".lower()
    global_terms = [
        "iam", "route53", "route 53", "cloudfront", "global", "entra",
        "active directory", "dns", "billing", "management console", "sts",
    ]
    return any(term in haystack for term in global_terms)


def classify_incident_relevance(incident: Dict[str, Any], scope: Dict[str, Any]) -> Tuple[str, str]:
    """classifies incident relevance against target scope."""
    prov = incident.get("provider", "")
    target_providers = scope.get("providers", set())

    if target_providers and prov not in target_providers:
        return "unrelated", f"provider mismatch (incident: {prov}, target: {', '.join(target_providers)})"

    if is_global_infrastructure_incident(incident):
        return "provider_global", "global infrastructure dependency"

    target_regions = scope.get("regions", set())
    incident_regions = extract_incident_regions(incident)

    if target_regions:
        if incident_regions:
            matching_regions = set(incident_regions) & target_regions
            if matching_regions:
                return "direct", f"region match: {', '.join(matching_regions)}"
            else:
                return "disjoint_region", f"incident in {', '.join(incident_regions)}, target is {', '.join(target_regions)}"

    target_services = scope.get("services", set())
    if target_services:
        haystack = f"{incident.get('title', '')} {incident.get('summary', '')}".lower()
        matching_services = [s for s in target_services if s in haystack]
        if matching_services:
            return "direct", f"service match: {', '.join(matching_services)}"

    if not target_regions:
        return "provider_regional", "matches provider scope"

    return "provider_regional", "provider incident (region unconfirmed)"


def load_configuration(
    explicit_path: Optional[str] = None,
    cwd: Optional[Path] = None,
) -> Tuple[Dict[str, Any], List[Dict[str, Any]]]:
    """loads configuration, checking explicit path, plugin root, project root, and global fallbacks."""
    config_paths: List[Path] = []

    if explicit_path:
        config_paths.append(Path(explicit_path))

    plugin_root = os.environ.get("CLAUDE_PLUGIN_ROOT")
    if plugin_root:
        config_paths.append(Path(plugin_root) / "config" / "status_feeds.json")

    repo_config = Path(__file__).resolve().parent.parent / "config" / "status_feeds.json"
    config_paths.append(repo_config)

    if cwd:
        config_paths.append(cwd / ".claude" / "status_feeds.json")

    project_dir = os.environ.get("CLAUDE_PROJECT_DIR")
    if project_dir:
        config_paths.append(Path(project_dir) / ".claude" / "status_feeds.json")

    global_config = Path.home() / ".claude" / "hooks" / "status_feeds.json"
    config_paths.append(global_config)

    config_data: Dict[str, Any] = {}
    feeds_list: List[Dict[str, Any]] = []

    for path in config_paths:
        if path.is_file():
            try:
                loaded = json.loads(path.read_text(encoding="utf-8"))
                config_data = loaded
                feeds_list = loaded.get("feeds", [])
                if feeds_list:
                    break
            except Exception as e:
                sys.stderr.write(f"warning: failed to parse config at {path}: {e}\n")

    if not feeds_list:
        config_data = {
            "version": 1,
            "cache_ttl_seconds": DEFAULT_CACHE_TTL_SECONDS,
            "timeout_seconds": DEFAULT_TIMEOUT_SECONDS,
            "max_incident_age_hours": MAX_INCIDENT_AGE_HOURS,
        }
        feeds_list = EMBEDDED_DEFAULT_FEEDS

    return config_data, feeds_list


def clean_html(raw_html: str) -> str:
    """removes html tags, unescapes entities, and normalizes whitespace."""
    if not raw_html:
        return ""
    unescaped = html.unescape(raw_html)
    cleaned = re.sub(r"<[^>]+>", " ", unescaped)
    cleaned = re.sub(r"\s+([.,;:!?])", r"\1", cleaned)
    return " ".join(cleaned.split())


def is_incident_resolved(status_tokens: List[str], title: str, description: str) -> bool:
    """determines whether an incident is marked resolved, completed, or future scheduled."""
    lower_tokens = [tok.lower().strip() for tok in status_tokens]
    if any(tok in ("resolved", "completed") for tok in lower_tokens):
        return True
    if lower_tokens and lower_tokens[0] == "scheduled":
        return True
    lower_title = title.lower()
    if any(sig in lower_title for sig in ("[resolved]", "resolved -", "resolved:", "[completed]")):
        return True
    return False


def parse_rfc822_date(date_str: str) -> Optional[datetime]:
    """parses rfc 822 / rfc 2822 date string into a timezone-aware datetime."""
    try:
        dt = email.utils.parsedate_to_datetime(date_str)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except Exception:
        return None


def parse_iso8601_date(date_str: str) -> Optional[datetime]:
    """parses iso 8601 date string into a timezone-aware datetime."""
    try:
        clean_str = date_str.replace("Z", "+00:00")
        return datetime.fromisoformat(clean_str)
    except Exception:
        return None


def parse_rss_feed(
    content: bytes,
    provider: str,
    category: str,
    keywords: List[str],
    tool_matchers: List[str],
    max_age_hours: int = MAX_INCIDENT_AGE_HOURS,
) -> List[Dict[str, Any]]:
    """parses rss 2.0 xml feeds (github, gitlab, bitbucket, azure, cloudflare, docker)."""
    incidents = []
    now = datetime.now(timezone.utc)

    try:
        tree = ET.fromstring(content)
        items = tree.findall(".//item")

        for item in items[:15]:
            title = item.findtext("title", default="").strip()
            pub_date_str = item.findtext("pubDate", default="").strip()
            link = item.findtext("link", default="").strip()
            raw_desc = item.findtext("description", default="").strip()

            pub_dt = parse_rfc822_date(pub_date_str)
            if pub_dt:
                age_hours = (now - pub_dt).total_seconds() / 3600.0
                if age_hours > max_age_hours:
                    continue

            status_tokens = re.findall(r"<(?:strong|b)>([^<]+)</(?:strong|b)>", raw_desc)
            if is_incident_resolved(status_tokens, title, raw_desc):
                continue

            summary_text = clean_html(raw_desc)
            if len(summary_text) > 320:
                summary_text = summary_text[:317] + "..."

            relevant = True
            if keywords:
                full_haystack = f"{title} {summary_text}".lower()
                relevant = any(kw in full_haystack for kw in keywords)

            if relevant:
                latest_status = status_tokens[0] if status_tokens else "Active"
                incidents.append({
                    "provider": provider,
                    "category": category,
                    "title": title,
                    "status": latest_status,
                    "date": pub_date_str,
                    "link": link,
                    "summary": summary_text,
                    "tool_matchers": tool_matchers,
                })
    except Exception as e:
        sys.stderr.write(f"error parsing {provider.lower()} rss: {e}\n")

    return incidents


def parse_atom_feed(
    content: bytes,
    provider: str,
    category: str,
    keywords: List[str],
    tool_matchers: List[str],
    max_age_hours: int = MAX_INCIDENT_AGE_HOURS,
) -> List[Dict[str, Any]]:
    """parses atom 1.0 xml feeds (google cloud status)."""
    incidents = []
    now = datetime.now(timezone.utc)

    try:
        tree = ET.fromstring(content)
        for elem in tree.iter():
            if "}" in elem.tag:
                elem.tag = elem.tag.split("}", 1)[1]

        entries = tree.findall(".//entry")
        for entry in entries[:15]:
            title = entry.findtext("title", default="").strip()
            updated_str = entry.findtext("updated", default="").strip()
            raw_summary = entry.findtext("summary", default="").strip() or entry.findtext("content", default="").strip()

            link_elem = entry.find("link")
            link = ""
            if link_elem is not None:
                link = link_elem.attrib.get("href", "")

            updated_dt = parse_iso8601_date(updated_str)
            if updated_dt:
                age_hours = (now - updated_dt).total_seconds() / 3600.0
                if age_hours > max_age_hours:
                    continue

            summary_text = clean_html(raw_summary)
            lower_summary = summary_text.lower()
            if any(term in lower_summary for term in ("resolved", "incident is closed", "service has been restored")):
                continue
            if title.lower().startswith("[resolved]") or "resolved" in title.lower():
                continue

            if len(summary_text) > 320:
                summary_text = summary_text[:317] + "..."

            relevant = True
            if keywords:
                full_haystack = f"{title} {summary_text}".lower()
                relevant = any(kw in full_haystack for kw in keywords)

            if relevant:
                incidents.append({
                    "provider": provider,
                    "category": category,
                    "title": title,
                    "status": "Active Issue",
                    "date": updated_str,
                    "link": link,
                    "summary": summary_text,
                    "tool_matchers": tool_matchers,
                })
    except Exception as e:
        sys.stderr.write(f"error parsing {provider.lower()} atom: {e}\n")

    return incidents


def parse_aws_json_feed(
    content: bytes,
    provider: str,
    category: str,
    keywords: List[str],
    tool_matchers: List[str],
) -> List[Dict[str, Any]]:
    """parses aws health public events json feed."""
    incidents = []
    try:
        data = json.loads(content.decode("utf-8"))
        if not isinstance(data, list):
            data = data.get("current_events", [])

        for item in data:
            status_desc = item.get("status_description", "")
            summary = item.get("summary", "")
            service_name = item.get("service_name", item.get("service", ""))
            region = item.get("region_name", item.get("region", ""))
            date_num = item.get("date", 0)

            title_parts = [p for p in (service_name, region) if p]
            title = f"{' - '.join(title_parts)}: {summary}" if title_parts else summary

            if not title:
                continue

            clean_summary = clean_html(item.get("description", summary))
            lower_haystack = f"{title} {clean_summary}".lower()
            if any(term in lower_haystack for term in ("resolved", "operating normally", "service restored")):
                continue

            if len(clean_summary) > 320:
                clean_summary = clean_summary[:317] + "..."

            relevant = True
            if keywords:
                relevant = any(kw in lower_haystack for kw in keywords)

            if relevant:
                date_str = str(date_num)
                if date_num:
                    try:
                        date_str = datetime.fromtimestamp(int(date_num), tz=timezone.utc).isoformat()
                    except Exception:
                        pass

                incidents.append({
                    "provider": provider,
                    "category": category,
                    "title": title,
                    "status": status_desc or "Active Disruption",
                    "date": date_str,
                    "link": "https://health.aws.amazon.com",
                    "summary": clean_summary,
                    "tool_matchers": tool_matchers,
                })
    except Exception as e:
        sys.stderr.write(f"error parsing {provider.lower()} aws json: {e}\n")

    return incidents


def fetch_feed(feed: Dict[str, Any], timeout: float = DEFAULT_TIMEOUT_SECONDS) -> List[Dict[str, Any]]:
    """fetches a single feed over https and routes to the appropriate parser."""
    url = feed.get("url")
    provider = feed.get("name", "Unknown")
    category = feed.get("category", "general")
    feed_format = feed.get("format", "rss")
    keywords = feed.get("keywords", [])
    tool_matchers = feed.get("tool_matchers", [])

    if not url:
        return []

    req = urllib.request.Request(
        url,
        headers={
            "User-Agent": "Claude-Code-Provider-Status/1.0",
            "Accept": "application/rss+xml, application/atom+xml, application/json, text/xml;q=0.9, */*;q=0.8",
        },
    )

    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            content = resp.read()
    except Exception as e:
        sys.stderr.write(f"status check timeout/error for {provider.lower()}: {e}\n")
        return []

    if feed_format == "rss":
        return parse_rss_feed(content, provider, category, keywords, tool_matchers)
    elif feed_format == "atom":
        return parse_atom_feed(content, provider, category, keywords, tool_matchers)
    elif feed_format in ("aws-json", "json"):
        return parse_aws_json_feed(content, provider, category, keywords, tool_matchers)
    else:
        sys.stderr.write(f"unsupported format '{feed_format}' for {provider}\n")
        return []


def refresh_cache(
    feeds: List[Dict[str, Any]],
    timeout: float = DEFAULT_TIMEOUT_SECONDS,
    cache_file: Optional[Path] = None,
) -> Dict[str, Any]:
    """concurrently polls enabled status feeds and writes an atomic cache file."""
    if cache_file is None:
        _, cache_file = resolve_cache_paths()

    enabled_feeds = [f for f in feeds if f.get("enabled", True)]
    all_incidents: List[Dict[str, Any]] = []

    with concurrent.futures.ThreadPoolExecutor(max_workers=min(8, len(enabled_feeds) or 1)) as executor:
        future_map = {executor.submit(fetch_feed, f, timeout): f for f in enabled_feeds}
        for future in concurrent.futures.as_completed(future_map):
            try:
                results = future.result()
                all_incidents.extend(results)
            except Exception as e:
                feed_name = future_map[future].get("name", "unknown")
                sys.stderr.write(f"error processing feed {feed_name}: {e}\n")

    payload = {
        "timestamp": time.time(),
        "active_incidents": all_incidents,
    }

    try:
        temp_cache = cache_file.with_suffix(".json.tmp")
        temp_cache.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        temp_cache.replace(cache_file)
    except Exception as e:
        sys.stderr.write(f"warning: failed to write status cache: {e}\n")

    return payload


def get_status_data(
    feeds: List[Dict[str, Any]],
    config: Dict[str, Any],
    cache_file: Optional[Path] = None,
    force_refresh: bool = False,
) -> Dict[str, Any]:
    """retrieves status data from local cache or triggers a background/inline refresh."""
    if cache_file is None:
        _, cache_file = resolve_cache_paths()

    ttl = config.get("cache_ttl_seconds", DEFAULT_CACHE_TTL_SECONDS)
    timeout = config.get("timeout_seconds", DEFAULT_TIMEOUT_SECONDS)

    if not force_refresh and cache_file.is_file():
        try:
            cached_text = cache_file.read_text(encoding="utf-8")
            data = json.loads(cached_text)
            cached_time = data.get("timestamp", 0)
            if time.time() - cached_time < ttl:
                return data
        except Exception:
            pass

    return refresh_cache(feeds, timeout, cache_file)


def filter_incidents_for_command(
    command: str,
    incidents: List[Dict[str, Any]],
    prompt: str = "",
    env: Optional[Dict[str, str]] = None,
    aws_config_path: Optional[Path] = None,
) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    """matches failed bash command tokens with provider tool matchers and keywords using scope inference."""
    if not command and not prompt:
        return incidents, {}

    scope = extract_scope_from_command(command, prompt, env, aws_config_path)

    if not scope["providers"] and not scope["regions"]:
        cmd_tokens = [tok.lower().strip() for tok in re.split(r"[\s/]+", command) if tok.strip()]
        matched = []
        for inc in incidents:
            tool_matchers = [m.lower() for m in inc.get("tool_matchers", [])]
            if any(tok in tool_matchers for tok in cmd_tokens):
                matched.append(inc)
                continue
            prov_lower = inc.get("provider", "").lower()
            if any(prov_lower in tok for tok in cmd_tokens):
                matched.append(inc)
                continue
            if inc.get("category") == "cloud":
                cloud_indicators = ["terraform", "tofu", "terragrunt", "kubectl", "helm", "docker", "cdk", "pulumi"]
                if any(ind in cmd_tokens for ind in cloud_indicators):
                    matched.append(inc)
        return (matched if matched else incidents), scope

    kept = []
    for inc in incidents:
        tier, reason = classify_incident_relevance(inc, scope)
        if tier in ("direct", "provider_global", "provider_regional"):
            inc_copy = dict(inc)
            inc_copy["_relevance_tier"] = tier
            inc_copy["_relevance_reason"] = reason
            kept.append(inc_copy)

    tier_order = {"direct": 0, "provider_global": 1, "provider_regional": 2}
    kept.sort(key=lambda x: tier_order.get(x.get("_relevance_tier", "provider_regional"), 3))

    return kept, scope


def format_advisory_context(
    incidents: List[Dict[str, Any]],
    trigger_context: Optional[str] = None,
    scope: Optional[Dict[str, Any]] = None,
) -> str:
    """formats structured, authoritative markdown advisory for claude code."""
    if not incidents:
        return ""

    lines = [
        "<provider_status_advisory>",
        "### Upstream Infrastructure Status Advisory",
        "",
    ]
    if trigger_context:
        lines.append(f"**Trigger**: Tool failure detected on `{trigger_context}`.")
        if scope and (scope.get("regions") or scope.get("profiles") or scope.get("services")):
            parts = []
            if scope.get("providers"):
                parts.append(f"Provider: **{', '.join(sorted(scope['providers']))}**")
            if scope.get("regions"):
                parts.append(f"Target Region: **{', '.join(sorted(scope['regions']))}**")
            if scope.get("services"):
                parts.append(f"Service: **{', '.join(sorted(scope['services']))}**")
            if scope.get("profiles"):
                parts.append(f"Profile: **{', '.join(sorted(scope['profiles']))}**")
            lines.append(f"**Inferred Scope**: {', '.join(parts)}")
        lines.append("Active upstream cloud/VCS incidents were identified that may explain this failure:")
    else:
        lines.append("The following active upstream incidents were detected on monitored providers:")
    lines.append("")

    for inc in incidents:
        tier = inc.get("_relevance_tier")
        badge = ""
        if tier == "direct":
            badge = " [DIRECT IMPACT]"
        elif tier == "provider_global":
            badge = " [GLOBAL DEPENDENCY]"

        lines.append(f"- **[{inc['provider']} ({inc.get('category', 'infra')})]{badge}** {inc['title']}")
        lines.append(f"  - **Status**: {inc['status']}")
        if inc.get("summary"):
            lines.append(f"  - **Details**: {inc['summary']}")
        if inc.get("link"):
            lines.append(f"  - **URL**: {inc['link']}")
        lines.append("")

    lines.append(
        "**Guidance**: If related network, build, deployment, or authentication failures occur, "
        "verify whether the root cause is upstream before attempting redundant code modifications or configuration changes."
    )
    lines.append("</provider_status_advisory>")
    return "\n".join(lines)


def process_event(
    event_name: str,
    stdin_payload: Dict[str, Any],
    config_path: Optional[str] = None,
    cwd: Optional[Path] = None,
    cache_file: Optional[Path] = None,
) -> None:
    """dispatches hook event lifecycle and prints claude code output if incidents exist."""
    config, feeds = load_configuration(config_path, cwd or Path.cwd())
    status_data = get_status_data(feeds, config, cache_file)
    incidents = status_data.get("active_incidents", [])

    if not incidents:
        sys.exit(0)

    if event_name in ("SessionStart", "UserPromptSubmit"):
        prompt_text = stdin_payload.get("prompt", "")
        scope = extract_scope_from_command(command="", prompt=prompt_text)
        matched_incidents: List[Dict[str, Any]] = []

        if scope.get("regions") or scope.get("providers"):
            for inc in incidents:
                tier, reason = classify_incident_relevance(inc, scope)
                if tier != "unrelated":
                    inc_copy = dict(inc)
                    inc_copy["_relevance_tier"] = tier
                    inc_copy["_relevance_reason"] = reason
                    matched_incidents.append(inc_copy)
            tier_order = {"direct": 0, "provider_global": 1, "provider_regional": 2, "disjoint_region": 3}
            matched_incidents.sort(key=lambda x: tier_order.get(x.get("_relevance_tier", "provider_regional"), 4))
        else:
            matched_incidents = incidents

        if matched_incidents:
            context = format_advisory_context(matched_incidents, scope=scope if scope.get("regions") else None)
            response = {
                "hookSpecificOutput": {
                    "hookEventName": event_name,
                    "additionalContext": context,
                }
            }
            print(json.dumps(response))
            sys.exit(0)

    elif event_name == "PostToolUseFailure":
        tool_input = stdin_payload.get("tool_input", {})
        command = tool_input.get("command", "")

        matched_incidents, scope = filter_incidents_for_command(command, incidents)
        if matched_incidents:
            context = format_advisory_context(
                matched_incidents,
                trigger_context=command,
                scope=scope,
            )
            response = {
                "hookSpecificOutput": {
                    "hookEventName": "PostToolUseFailure",
                    "additionalContext": context,
                }
            }
            print(json.dumps(response))
            sys.exit(0)

    sys.exit(0)


def main() -> None:
    parser = argparse.ArgumentParser(description="claude code cloud and vcs status hook")
    parser.add_argument("--event", default="UserPromptSubmit", help="hook event name")
    parser.add_argument("--config", default=None, help="path to status_feeds.json configuration file")
    parser.add_argument("--cache-dir", default=None, help="path to directory for cache storage")
    parser.add_argument("--refresh", action="store_true", help="force cache refresh")
    parser.add_argument("--status", action="store_true", help="print active incidents summary and exit")
    parser.add_argument("--list-feeds", action="store_true", help="list configured feeds and exit")
    parser.add_argument("--test-feed", help="test fetching and parsing a specific feed by name")
    parser.add_argument("--test-scope", help="test CLI scope and regional inference from a command string")
    args = parser.parse_args()

    _, cache_file = resolve_cache_paths(args.cache_dir)
    config, feeds = load_configuration(args.config, Path.cwd())

    if args.test_scope:
        scope = extract_scope_from_command(args.test_scope)
        print("detected scope:")
        print(f"  providers: {', '.join(sorted(scope['providers'])) or 'none'}")
        print(f"  regions:   {', '.join(sorted(scope['regions'])) or 'none'}")
        print(f"  services:  {', '.join(sorted(scope['services'])) or 'none'}")
        print(f"  profiles:  {', '.join(sorted(scope['profiles'])) or 'none'}")
        print(f"  projects:  {', '.join(sorted(scope['projects'])) or 'none'}")
        print("  detected via:")
        for d in scope["detected_via"]:
            print(f"    - {d}")
        sys.exit(0)

    if args.list_feeds:
        print(f"loaded {len(feeds)} feeds from configuration:")
        for idx, f in enumerate(feeds, 1):
            status = "enabled" if f.get("enabled", True) else "disabled"
            tools = ", ".join(f.get("tool_matchers", []))
            print(f"[{idx}] {f.get('name')} ({f.get('category', 'general')}) - {status}")
            print(f"    format: {f.get('format', 'rss')} | url: {f.get('url')}")
            print(f"    tools: {tools}")
        sys.exit(0)

    if args.test_feed:
        target_name = args.test_feed.lower()
        matched_feed = next((f for f in feeds if f.get("name", "").lower() == target_name), None)
        if not matched_feed:
            print(f"error: feed '{args.test_feed}' not found in configuration")
            sys.exit(1)
        timeout = config.get("timeout_seconds", DEFAULT_TIMEOUT_SECONDS)
        print(f"testing feed '{matched_feed.get('name')}' ({matched_feed.get('url')})...")
        results = fetch_feed(matched_feed, timeout)
        print(f"found {len(results)} active incident(s):")
        for res in results:
            print(f"- {res['title']} ({res['status']})")
            print(f"  {res['summary']}")
            print(f"  link: {res['link']}")
        sys.exit(0)

    if args.status:
        data = get_status_data(feeds, config, cache_file, force_refresh=args.refresh)
        incidents = data.get("active_incidents", [])
        print(f"status cache timestamp: {data.get('timestamp')}")
        print(f"active incidents count: {len(incidents)}")
        for inc in incidents:
            print(f"- [{inc['provider']} / {inc.get('category', 'infra')}] {inc['title']} ({inc['status']})")
            print(f"  {inc['summary']}")
            print(f"  url: {inc['link']}")
        sys.exit(0)

    if args.refresh:
        refresh_cache(feeds, config.get("timeout_seconds", DEFAULT_TIMEOUT_SECONDS), cache_file)
        print("status cache refreshed")
        sys.exit(0)

    stdin_payload: Dict[str, Any] = {}
    if not sys.stdin.isatty():
        try:
            raw_input = sys.stdin.read().strip()
            if raw_input:
                stdin_payload = json.loads(raw_input)
        except Exception:
            pass

    event_name = stdin_payload.get("hook_event_name", args.event)
    process_event(event_name, stdin_payload, args.config, Path.cwd(), cache_file)


if __name__ == "__main__":
    main()
