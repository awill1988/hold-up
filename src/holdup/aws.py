"""Lossless current-update normalization for public AWS Health evidence."""

import json
import math
import re

from .data import immutable_result

VERSION = 2
MAX_BYTES = 1024 * 1024  # 1 MiB
REGION = re.compile(r"(?:af|ap|ca|cn|eu|il|me|mx|sa|us)(?:-[a-z]+)+-\d+")
LIFECYCLES = frozenset(
    ("open", "active", "investigating", "identified", "monitoring", "resolved", "closed")
)


def timestamp(value):
    if isinstance(value, bool) or not isinstance(value, (str, int, float)):
        raise ValueError("feed_decode_failed")
    try:
        number = float(value)
    except ValueError as error:
        raise ValueError("feed_decode_failed") from error
    if not math.isfinite(number) or number < 0:
        raise ValueError("feed_decode_failed")
    return number


@immutable_result
def normalize(content):
    if len(content) > MAX_BYTES:
        raise ValueError("feed_decode_failed")
    try:
        events = json.loads(content)
        if isinstance(events, dict):
            events = events["current_events"]
        if not isinstance(events, list):
            raise ValueError("feed_decode_failed")
        return [normalize_event(event) for event in events]
    except (ValueError, KeyError, TypeError, UnicodeError) as error:
        raise ValueError("feed_decode_failed") from error


@immutable_result
def normalize_event(event):
    if not isinstance(event, dict):
        raise ValueError("feed_decode_failed")
    for key in (
        "arn",
        "id",
        "summary",
        "description",
        "region",
        "region_name",
        "service",
        "service_name",
        "status_description",
    ):
        if key in event and not isinstance(event[key], str):
            raise ValueError("feed_decode_failed")
    updates = []
    if "event_log" in event:
        if not isinstance(event["event_log"], list) or not event["event_log"]:
            raise ValueError("feed_decode_failed")
        for update in event["event_log"]:
            if not isinstance(update, dict) or not all(
                isinstance(update.get(k), str) and update[k] for k in ("message", "summary")
            ):
                raise ValueError("feed_decode_failed")
            item = {
                "timestamp": timestamp(update["timestamp"]),
                "summary": update["summary"],
                "message": update["message"],
                "provider_status": update.get("status"),
            }
            if item not in updates:
                updates.append(item)
        updates.sort(key=lambda item: (item["timestamp"], json.dumps(item, sort_keys=True)))
        latest = [item for item in updates if item["timestamp"] == updates[-1]["timestamp"]]
    else:
        latest = []
    arn = event.get("arn", event.get("id", ""))
    parts = arn.split(":")
    arn_region = parts[3] if len(parts) > 5 and parts[2] == "health" else ""
    regions = {
        value.lower()
        for value in (arn_region, event.get("region", ""), event.get("region_name", ""))
        if REGION.fullmatch(value.lower())
    }
    conflict = len(regions) > 1
    log_conflict = len({item["timestamp"] for item in updates}) != len(updates)
    title = latest[0]["summary"] if latest else event.get("summary", "")
    if not title:
        raise ValueError("feed_decode_failed")
    raw_status = latest[0]["provider_status"] if latest else event.get("status")
    lifecycle = (
        raw_status
        if isinstance(raw_status, str) and raw_status in LIFECYCLES
        else event.get("status_description", "").lower()
    )
    return {
        "source_id": arn,
        "title": title,
        "summary": "\n\n".join(item["message"] for item in latest)
        if latest
        else event.get("description", title),
        "status": lifecycle if lifecycle in LIFECYCLES and not log_conflict else "unknown",
        "provider_status": raw_status,
        "provider_event_status": event.get("status"),
        "provider_status_description": event.get("status_description", ""),
        "service": event.get("service_name", event.get("service", "")),
        "region": next(iter(regions)) if len(regions) == 1 else "",
        "region_display": event.get("region_name", ""),
        "regions": sorted(regions),
        "scope_uncertain": conflict,
        "conflicting_updates": log_conflict,
        "latest_updates": latest,
        "published_at": str(event.get("date", "")),
        "updated_at": str(latest[0]["timestamp"])
        if latest
        else str(event.get("lastUpdatedTime", "")),
    }
