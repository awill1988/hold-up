"""Finite operation catalogue: unknown syntax never acquires a blocking rule."""

import os
import re
import shlex
import time
from collections.abc import Mapping

from . import decision as d
from .data import freeze, immutable_result

VERSION = 1
OPERATIONS = freeze(
    {
        "ec2": ("run-instances", "start-instances", "stop-instances", "terminate-instances"),
        "s3api": ("put-object", "get-object", "delete-object"),
        "lambda": ("invoke", "update-function-code"),
        "cloudformation": ("create-stack", "update-stack", "delete-stack"),
    }
)
REGION = re.compile(r"[a-z]{2}(?:-[a-z]+)+-\d+")


@immutable_result
def normalize(payload, mappings=None):
    tool, args = payload.get("tool_name"), payload.get("tool_input", {})
    unknown = {"kind": "unknown"}
    if not isinstance(args, Mapping):
        return unknown
    if tool in ("Read", "Edit", "Write", "apply_patch", "read_file", "write_file"):
        return {"kind": "local"}
    if tool not in ("Bash", "exec_command", "shell_command"):
        mapping = (mappings or {}).get(tool, {})
        service = mapping.get("service")
        operation = mapping.get("operation")
        region = args.get(mapping.get("region_key", "region"))
        if (
            operation in OPERATIONS.get(service, ())
            and isinstance(region, str)
            and REGION.fullmatch(region)
        ):
            return {"kind": "remote", "service": service, "operation": operation, "region": region}
        return unknown
    command = args.get("command", args.get("cmd", ""))
    if not isinstance(command, str) or len(command.encode()) > d.MAX_INPUT_BYTES:
        return unknown
    # Expansion, pipelines, and embedded programs need a shell parser, not an outage guess.
    if re.search(r"[\r\n`$;&|<>%]", command):
        return unknown
    try:
        tokens = shlex.split(command)
    except ValueError:
        return unknown
    if not tokens:
        return unknown
    executable = tokens.pop(0).replace("\\", "/").rsplit("/", 1)[-1].lower()
    executable = executable.removesuffix(".exe")
    if executable in ("pwd", "ls", "echo", "true", "false") or (
        executable in ("git", "hold-up")
        and tokens
        and tokens[0] in ("status", "stats", "diff", "log", "show")
    ):
        return {"kind": "local"}
    if executable != "aws":
        return unknown
    if "--generate-cli-skeleton" in tokens or any(
        t.startswith("--generate-cli-skeleton=") for t in tokens
    ):
        return {"kind": "local"}
    if "--dry-run" in tokens:
        return {"kind": "diagnostic"}
    if any(t == "--endpoint-url" or t.startswith("--endpoint-url=") for t in tokens) or any(
        k.startswith("AWS_ENDPOINT_URL") and v for k, v in os.environ.items()
    ):
        return unknown
    regions = []
    positional = []
    index = 0
    while index < len(tokens):
        token = tokens[index]
        if token in ("--region", "--profile"):
            if index + 1 >= len(tokens):
                return unknown
            if token == "--region":
                regions.append(tokens[index + 1])
            index += 2
            continue
        if token.startswith("--region="):
            regions.append(token.split("=", 1)[1])
        else:
            positional.append(token)
        index += 1
    if len(positional) < 2 or positional[0].startswith("-"):
        return unknown
    service, operation = positional[:2]
    if operation.startswith(("describe-", "list-")) or (service == "s3" and operation == "ls"):
        return {"kind": "diagnostic"}
    if service == "s3" and operation == "cp" and len(positional) >= 4:
        source, destination = positional[2:4]
        if source.startswith("s3://") == destination.startswith("s3://"):
            return unknown
        service, operation = (
            "s3api",
            "put-object" if destination.startswith("s3://") else "get-object",
        )
    if operation not in OPERATIONS.get(service, ()):
        return unknown
    if not regions:
        regions = [os.environ.get("AWS_REGION") or os.environ.get("AWS_DEFAULT_REGION", "")]
    if len(set(regions)) != 1 or not REGION.fullmatch(regions[0]):
        return unknown
    return {"kind": "remote", "service": service, "operation": operation, "region": regions[0]}


def key(route):
    return d.digest(route)


@immutable_result
def action(route):
    service = "s3" if route["service"] == "s3api" else route["service"]
    return {
        "tool": "operation",
        "text": f"aws {route['service']} {route['operation']}",
        "providers": ["AWS"],
        "services": [service],
        "regions": [route["region"]],
        "context_complete": True,
    }


@immutable_result
def classify(route, reports, runtime, predictor=None):
    if route.get("kind") in ("local", "diagnostic"):
        return {
            "decision": "allow",
            "reason": "protected_action",
            "evidence_ids": [],
            "providers": [],
        }
    if route.get("kind") != "remote":
        return {
            "decision": "advise",
            "reason": "operation_unmapped",
            "evidence_ids": [],
            "providers": [],
        }
    relevant = [r for r in reports if r.get("provider") == "AWS"]
    now = time.time()
    if any(
        type(r.get("fetched_at")) not in (int, float) or not 0 <= now - r["fetched_at"] < 300
        for r in relevant
    ):
        raise ValueError("evidence_incomplete")
    scoped = []
    for report in relevant:
        arn = report.get("source_id", "").split(":", 5)
        service = (
            arn[5].split("/")[1].lower() if len(arn) == 6 and arn[5].startswith("event/") else ""
        )
        expected_service = "s3" if route["service"] == "s3api" else route["service"]
        if service and service != "multiple_services" and service != expected_service:
            continue
        if report.get("scope_uncertain") or report.get("conflicting_updates"):
            return {
                "decision": "advise",
                "reason": "uncertain_dependency",
                "evidence_ids": [],
                "providers": [],
            }
        if report.get("region") and report["region"] != route["region"]:
            continue
        scoped.append(report)
    if not scoped:
        return {
            "decision": "allow",
            "reason": "no_affected_operation",
            "evidence_ids": [],
            "providers": [],
        }
    # Summary already contains complete latest messages; retain the raw log in evidence storage.
    relevant = [{k: v for k, v in r.items() if k != "latest_updates"} for r in scoped]
    value = (predictor or d.infer)(action(route), relevant, runtime)
    return d.validate_decision(value, action(route), relevant)
