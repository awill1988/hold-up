#!/usr/bin/env python3
"""cloud and vcs infrastructure status hook for claude code.

monitors upstream status feeds for cloud providers (aws, gcp, azure)
and vcs providers (github, gitlab, bitbucket) configured in status_feeds.json.
maintains an atomic disk cache and injects advisory context into claude code
lifecycle events (SessionStart, UserPromptSubmit, PostToolUseFailure).
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
from typing import Any, Dict, List, Optional, Tuple

DEFAULT_CACHE_TTL_SECONDS = 300
DEFAULT_TIMEOUT_SECONDS = 2.5
MAX_INCIDENT_AGE_HOURS = 72

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


def filter_incidents_for_command(command: str, incidents: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """matches failed bash command tokens with provider tool matchers and keywords."""
    if not command:
        return incidents

    cmd_tokens = [tok.lower().strip() for tok in re.split(r"[\s/]+", command) if tok.strip()]
    if not cmd_tokens:
        return incidents

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
                continue

    return matched if matched else incidents


def format_advisory_context(incidents: List[Dict[str, Any]], trigger_context: Optional[str] = None) -> str:
    """formats structured, authoritative markdown advisory for claude code."""
    if not incidents:
        return ""

    lines = [
        "<provider_status_advisory>",
        "### Upstream Infrastructure Status Advisory",
        "",
    ]
    if trigger_context:
        lines.append(f"**Trigger**: Tool failure detected on {trigger_context}.")
        lines.append("Active upstream cloud/VCS incidents were identified that may explain this failure:")
    else:
        lines.append("The following active upstream incidents were detected on monitored providers:")
    lines.append("")

    for inc in incidents:
        lines.append(f"- **[{inc['provider']} ({inc.get('category', 'infra')})]** {inc['title']}")
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
        context = format_advisory_context(incidents)
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

        matched_incidents = filter_incidents_for_command(command, incidents)
        if matched_incidents:
            context = format_advisory_context(
                matched_incidents,
                trigger_context=f"failed command `{command}`",
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
    args = parser.parse_args()

    _, cache_file = resolve_cache_paths(args.cache_dir)
    config, feeds = load_configuration(args.config, Path.cwd())

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
