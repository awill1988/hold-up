"""Native event translation; an outage pass never overrides client permissions."""

import hashlib
import hmac
import json
import os
import sys
import time

from . import decision as d
from . import routes, transport
from .locations import runtime_directory


def canonical(payload, client):
    if client != "antigravity":
        return payload
    call = payload.get("toolCall", {})
    args = call.get("args", {})
    return {
        "tool_name": "Bash" if call.get("name") == "run_command" else call.get("name"),
        "tool_input": {"command": args.get("CommandLine", "")}
        if call.get("name") == "run_command"
        else args,
        "cwd": args.get("Cwd", ""),
        "session_id": payload.get("conversationId", ""),
        "tool_use_id": str(payload["stepIdx"]) if "stepIdx" in payload else "",
    }


def output(client, event, result):
    reason = "hold-up: " + result.get("reason", "evidence_incomplete")
    if result.get("decision_id"):
        reason += "; human retry: hold-up retry " + result["decision_id"]
    if client == "antigravity":
        if event == "PreInvocation" and result.get("advisory"):
            return {"injectSteps": [{"ephemeralMessage": "hold-up: " + result["advisory"]}]}
        if result.get("decision") == "pause":
            return {"decision": "deny", "reason": reason}
        # Empty stdout preserves the native permission flow; never return automatic allow.
        return None
    if result.get("decision") == "pause":
        return {
            "hookSpecificOutput": {
                "hookEventName": event,
                "permissionDecision": "deny",
                "permissionDecisionReason": reason,
            }
        }
    if result.get("decision") == "advise" and result.get("emitted", True):
        return {
            "hookSpecificOutput": {
                "hookEventName": event,
                "additionalContext": reason
                + "; continue diagnostics or unrelated work; reassess the affected dependency",
            }
        }
    return None


def process(event, payload, client, config, root=None):
    if event not in ("PreToolUse", "PostToolUse", "PostToolUseFailure", "PreInvocation"):
        return None
    root = root or d.state_root()
    start = time.monotonic()
    try:
        normalized = canonical(payload, client)
        metadata = json.loads(
            (runtime_directory(root) / "endpoint.json").read_text(encoding="utf-8")
        )
        salt = metadata["secret"].encode()

        def opaque(value):
            return hmac.new(
                salt, json.dumps(value, sort_keys=True).encode(), hashlib.sha256
            ).hexdigest()

        session = [
            client,
            normalized.get("session_id"),
            os.environ.get("HOLD_UP_PROFILE", os.environ.get("DEVELOPER_PROFILE", "default")),
        ]
        namespace = (
            opaque(session + [normalized.get("cwd", "")])
            if client != "antigravity"
            else opaque(session + [payload.get("workspacePaths", [])])
        )
        correlation = (
            opaque(session + [normalized["tool_use_id"]]) if normalized.get("tool_use_id") else ""
        )
        message = {
            "event": event,
            "agent": client,
            "namespace": namespace,
            "correlation": correlation,
        }
        if event == "PreToolUse":
            message.update(
                route=routes.normalize(normalized, config.get("tool_mappings", {})),
                action_key=opaque([normalized.get("tool_name"), normalized.get("tool_input")]),
                generation=d.policy_digest(),
                config_hash=d.digest(config),
                mode=os.environ.get(
                    "HOLD_UP_MODE", config.get("decision", {}).get("mode", "guard")
                ),
            )
        if event in ("PostToolUse", "PostToolUseFailure"):
            outcome = "unknown"
            if event == "PostToolUseFailure" or payload.get("error"):
                outcome = "failed"
            elif client in ("claude", "antigravity"):
                outcome = "completed"
            else:
                response = payload.get("tool_response")
                if isinstance(response, dict):
                    code = response.get("exit_code")
                    if type(code) is int:
                        outcome = "completed" if code == 0 else "failed"
            message["outcome"] = outcome
        result = transport.request(root, message)
        if event == "PreToolUse":
            try:
                transport.request(
                    root,
                    {
                        "event": "hook_timing",
                        "agent": client,
                        "namespace": namespace,
                        "correlation": correlation,
                        "seconds": time.monotonic() - start,
                    },
                )
            except (OSError, ValueError):
                sys.stderr.write("hold-up: telemetry_unavailable\n")
        return output(client, event, result)
    except (OSError, ValueError, KeyError, TypeError):
        sys.stderr.write("hold-up: socket_unavailable\n")
        return (
            output(client, event, {"decision": "advise", "reason": "socket_unavailable"})
            if event == "PreToolUse"
            else None
        )
