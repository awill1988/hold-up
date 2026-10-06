"""Provider-only evidence snapshots with explicit acquisition and lifecycle metadata."""

import concurrent.futures
import time
import urllib.request
import xml.etree.ElementTree as ET

from .aws import VERSION, normalize
from .decision import digest

MAX_BYTES = 1024 * 1024  # 1 MiB


def parse(content, feed, fetched_at):
    from . import engine

    fmt = feed.get("format", "rss")
    records = []
    if fmt in ("json", "aws-json"):
        records = normalize(content)
    else:
        root = ET.fromstring(content)
        if fmt == "rss":
            if root.tag != "rss" or root.find("channel") is None:
                raise ValueError("invalid rss evidence")
            for item in root.findall("channel/item"):
                records.append(
                    {
                        "source_id": item.findtext("guid", item.findtext("link", "")),
                        "title": item.findtext("title", ""),
                        "summary": item.findtext("description", ""),
                        "published_at": item.findtext("pubDate", ""),
                        "updated_at": "",
                        "status": "unknown",
                    }
                )
        elif fmt == "atom":
            ns = "{http://www.w3.org/2005/Atom}"
            if root.tag != ns + "feed":
                raise ValueError("invalid atom evidence")
            for item in root.findall(ns + "entry"):
                records.append(
                    {
                        "source_id": item.findtext(ns + "id", ""),
                        "title": item.findtext(ns + "title", ""),
                        "summary": item.findtext(ns + "content", item.findtext(ns + "summary", "")),
                        "published_at": item.findtext(ns + "published", ""),
                        "updated_at": item.findtext(ns + "updated", ""),
                        "status": "unknown",
                    }
                )
        else:
            raise ValueError("unsupported evidence format")
    result = []
    for record in records:
        if not record["title"] or not all(isinstance(record[k], str) for k in ("title", "summary")):
            raise ValueError("invalid provider report fields")
        summary = engine.clean_html(record["summary"])
        title = engine.clean_html(record["title"])
        record["truncated"] = False
        record["summary"] = summary
        record["title"] = title
        record.update(provider=feed["name"], source_url=feed["url"], fetched_at=fetched_at)
        record["id"] = digest([feed["name"], record["source_id"] or record["title"]])[:24]
        result.append(record)
    return result


def fetch(feed):
    with urllib.request.urlopen(
        urllib.request.Request(feed["url"], headers={"User-Agent": "hold-up/2.0"}), timeout=2.5
    ) as response:
        content = response.read(MAX_BYTES + 1)
    if len(content) > MAX_BYTES:
        raise ValueError("oversized provider response")
    return parse(content, feed, time.time())


def collect(config, feeds, root):
    from .engine import atomic_json_write

    reports, unavailable, failures = [], [], {}
    enabled = [f for f in feeds if f.get("enabled", True)]
    with concurrent.futures.ThreadPoolExecutor(max_workers=min(8, len(enabled) or 1)) as pool:
        tasks = {pool.submit(fetch, feed): feed for feed in enabled}
        for task in concurrent.futures.as_completed(tasks):
            try:
                reports.extend(task.result())
            except Exception as error:
                name = tasks[task]["name"]
                unavailable.append(name)
                failures[name] = (
                    "feed_decode_failed"
                    if isinstance(error, (ValueError, ET.ParseError))
                    else "feed_unavailable"
                )
    snapshot = {
        "version": VERSION,
        "config_hash": digest(config),
        "fetched_at": time.time(),
        "reports": sorted(reports, key=lambda r: r["id"]),
        "unavailable": sorted(unavailable),
        "failures": failures,
    }
    atomic_json_write(root / "evidence.json", snapshot)
    return snapshot
