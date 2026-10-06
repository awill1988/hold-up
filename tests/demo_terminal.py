"""Replayable terminal presentation of real socket hooks with isolated fixture decisions."""

import argparse
import json
import os
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

from holdup import routes
from holdup.data import freeze, json_value
from holdup.engine import atomic_json_write, validate_configuration
from holdup.socket_runtime import Runtime, SocketOwner


def run(scenario, client):
    command = "aws --region us-east-1 ec2 run-instances --image-id fixture"
    with tempfile.TemporaryDirectory(prefix="hold-up-demo-") as directory:
        root = Path(directory)
        config, _ = validate_configuration(
            {"feeds": [{"name": "AWS", "url": "https://example.invalid", "format": "aws-json"}]}
        )
        atomic_json_write(root / "config.json", config)
        payload = freeze(
            {
                "tool_name": "Bash",
                "tool_input": {"command": command},
                "session_id": "demo",
                "tool_use_id": "remote",
                "cwd": directory,
            }
        )
        route = routes.normalize(payload)
        runtime = Runtime(root, config)
        runtime.snapshot = {
            "fetched_at": time.time(),
            "content": "isolated-demo-fixture",
            "qualified": scenario == "block",
            "rules": {
                routes.key(route): {
                    "decision": "pause",
                    "reason": "fixture outage",
                    "evidence_ids": ("fixture",),
                    "providers": ("AWS",),
                }
            },
        }
        environment = {
            key: value
            for key, value in os.environ.items()
            if not key.startswith(("AWS_", "AMAZON_", "HOLD_UP_"))
        }
        environment["HOLD_UP_STATE_DIR"] = directory

        def hook(event, item):
            native = item
            if client == "antigravity":
                native = {
                    "conversationId": "demo",
                    "workspacePaths": (directory,),
                    "stepIdx": 1 if item["tool_use_id"] == "remote" else 2,
                    "toolCall": {
                        "name": "run_command" if item["tool_name"] == "Bash" else "read_file",
                        "args": {"CommandLine": command, "Cwd": directory},
                    },
                }
            completed = subprocess.run(
                (
                    sys.executable,
                    "-m",
                    "holdup",
                    "--client",
                    client,
                    "--event",
                    event,
                    "--config",
                    str(root / "config.json"),
                ),
                input=json.dumps(native, default=json_value),
                capture_output=True,
                text=True,
                env=environment,
                check=True,
                timeout=5,
            )
            assert not completed.stderr, completed.stderr
            return freeze(json.loads(completed.stdout) if completed.stdout else {})

        with SocketOwner(runtime) as owner:
            worker = threading.Thread(target=owner.serve_forever, kwargs={"poll_interval": 0.01})
            worker.start()
            try:
                result = hook("PreToolUse", payload)
                denied = (
                    result.get("decision") == "deny"
                    or result.get("hookSpecificOutput", {}).get("permissionDecision") == "deny"
                )
                assert denied == (scenario == "block")
                if scenario == "advisory":
                    if client == "antigravity":
                        result = hook("PreInvocation", payload)
                    assert "model_unqualified" in json.dumps(result, default=json_value)
                sentinel = root / "aws_sentinel.py"
                sentinel.write_text(
                    "import sys\nfrom pathlib import Path\n"
                    "assert sys.argv[1:] == ['fixture']\n"
                    f"Path({str(root / 'executed')!r}).write_text('1')\n"
                    "print('aws sentinel: executed once; no cloud request')\n",
                    encoding="utf-8",
                )
                if not denied:
                    subprocess.run(
                        (sys.executable, str(sentinel), "fixture"),
                        env=environment,
                        capture_output=True,
                        check=True,
                        timeout=5,
                    )
                    hook("PostToolUse", payload)
                executions = int((root / "executed").exists())
                assert executions == (0 if denied else 1)
                local = freeze(
                    {**payload, "tool_name": "Read", "tool_input": {}, "tool_use_id": "local"}
                )
                assert not hook("PreToolUse", local)
                runtime.telemetry.close()
                stats = next(
                    row for row in runtime.telemetry.stats()["agents"] if row["agent"] == client
                )
                assert stats["checks"] == 2
                assert stats["denials_issued"] == int(denied)
            finally:
                owner.shutdown()
                worker.join()
                runtime.close()
    color = "31" if denied else "33"
    outcome = "BLOCKED  affected_operation" if denied else "ADVISORY  model_unqualified"
    lines = (
        (0.0, "\x1b[2J\x1b[H\x1b[1;36mhold-up  /  " + scenario + "\x1b[0m\r\n"),
        (0.1, f"\x1b[90msimulated {client} terminal | actual hook + socket\r\n"),
        (0.2, "fixture decisions | AWS execution stubbed\x1b[0m\r\n\r\n"),
        (1.0, f"\x1b[36magent >\x1b[0m {command}\r\n"),
        (2.0, f"\x1b[1;{color}mhold-up: {outcome}\x1b[0m\r\n"),
        (3.0, "execution prevented\r\n" if denied else "advice delivered; execution permitted\r\n"),
        (4.0, f"\x1b[1mAWS sentinel executions: {executions}\x1b[0m\r\n\r\n"),
        (5.0, "\x1b[36magent >\x1b[0m inspect a local file\r\n"),
        (6.0, "\x1b[32mlocal action remains available\x1b[0m\r\n\r\n"),
        (
            7.0,
            f"{client}: checks {stats['checks']} | advice {stats['advisories_emitted']} | denials {stats['denials_issued']}\r\n",
        ),
        (
            8.0,
            "\x1b[90mblocking shown with fixture readiness only.\r\nlive model is unqualified; production remains advisory.\x1b[0m\r\n",
        ),
    )
    return freeze({"version": 2, "width": 82, "height": 18, "title": f"hold-up {scenario}"}), tuple(
        (stamp, "o", text) for stamp, text in lines
    )


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("scenario", choices=("advisory", "block"))
    parser.add_argument("--client", choices=("claude", "codex", "antigravity"), default="claude")
    args = parser.parse_args()
    header, events = run(args.scenario, args.client)
    for item in (header, *events):
        print(json.dumps(item, default=json_value))
