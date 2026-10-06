"""Native pre-tool denial, one-shot retry, and recovery against a loopback model stub.

Only temporary homes, synthetic reports, and a harmless local gh stub are used.
"""

import argparse
import json
import os
import shlex
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from holdup import decision as d
from holdup import evidence
from holdup.engine import atomic_json_write, validate_configuration


def hook(root):
    start = time.monotonic()
    settings = json.loads((root / "fixture.json").read_text())
    config = settings["config"]
    payload = json.load(sys.stdin)
    payload["client"] = settings["client"]
    report = {
        "id": "fixture",
        "provider": "AWS",
        "title": "ec2 instance launches unavailable in me-central-1",
        "status": "resolved" if (root / "recovered").exists() else "investigating",
        "fetched_at": time.time(),
    }
    atomic_json_write(
        root / "evidence.json",
        {
            "version": 2,
            "config_hash": d.digest(config),
            "fetched_at": time.time(),
            "reports": [report] if settings["mode"] == "contract" else settings["reports"],
            "unavailable": [],
        },
    )
    if settings["mode"] == "contract":
        atomic_json_write(
            root / "readiness.json",
            {
                "passed": True,
                "model_sha256": d.MODEL_SHA256,
                "policy_version": d.POLICY_VERSION,
                "policy_digest": d.policy_digest(),
                "runtime_fingerprint": d.runtime_fingerprint(root),
                "corpus_hash": d.corpus_hash(),
                "qualification_version": 1,
            },
        )
    predictor = (
        (
            lambda *args: {
                "decision": "allow" if report["status"] == "resolved" else "pause",
                "reason": "fixture outage",
                "evidence_ids": ["fixture"],
                "providers": ["AWS"],
            }
        )
        if settings["mode"] == "contract"
        else d.infer
    )
    if settings["mode"] == "contract":
        result = d.pre_tool(payload, config, root, predictor=predictor)
    else:
        completed = subprocess.run(
            [
                str(Path(sys.executable).with_name("hold-up")),
                "--client",
                settings["client"],
                "--event",
                "PreToolUse",
                "--config",
                str(root / "config.json"),
            ],
            input=json.dumps(payload),
            capture_output=True,
            text=True,
            timeout=6,
            check=True,
        )
        result = json.loads(completed.stdout) if completed.stdout.strip() else None
    with (root / "hooks.jsonl").open("a") as stream:
        stream.write(
            json.dumps({"payload": payload, "result": result, "seconds": time.monotonic() - start})
            + "\n"
        )
    if result:
        print(json.dumps(result))


def run(client, binary, mode="contract", source="capture", output_dir=None):
    runtime_root = d.state_root()
    reports = []
    region = "me-central-1"
    feed = {
        "name": "AWS",
        "url": "https://health.aws.amazon.com/public/currentevents",
        "format": "aws-json",
    }
    config, _ = validate_configuration({"feeds": [feed]})
    if mode == "real":
        feed = {
            "name": "AWS",
            "url": "https://health.aws.amazon.com/public/currentevents",
            "format": "aws-json",
        }
        acquired = time.time()
        if source == "live":
            with urllib.request.urlopen(feed["url"], timeout=2.5) as response:
                content = response.read(evidence.MAX_BYTES + 1)
        else:
            content = (Path(__file__).parent / "fixtures/aws-public-2026-10-05.bin").read_bytes()
        reports = evidence.parse(content, feed, acquired)
        if output_dir:
            output_dir.mkdir(parents=True, exist_ok=True)
            (output_dir / f"{client}-{source}.bin").write_bytes(content)
            atomic_json_write(
                output_dir / f"{client}-{source}-acquisition.json",
                {
                    "url": feed["url"],
                    "acquired_at": acquired,
                    "encoding": json.detect_encoding(content),
                    "sha256": d.hashlib.sha256(content).hexdigest(),
                    "source": source,
                },
            )
        regions = sorted({r["region"] for r in reports if r["region"] and not r["scope_uncertain"]})
        if not regions:
            print(
                json.dumps({"client": client, "mode": mode, "source": source, "available": False})
            )
            return
        region = regions[0]
    with tempfile.TemporaryDirectory(prefix="hold-up-native-") as directory:
        root = Path(directory)
        bin_dir = root / "bin"
        bin_dir.mkdir()
        stub = bin_dir / "aws"
        arguments = [
            "--region",
            region,
            "ec2",
            "run-instances",
            "--image-id",
            "fixture",
            "--instance-type",
            "t3.micro",
        ]
        other_arguments = ["--region", "us-west-2", *arguments[2:]]
        diagnostic = ["--region", region, "ec2", "describe-instances"]
        allowed = [arguments, other_arguments, diagnostic]
        stub.write_text(
            f"#!{sys.executable}\nimport sys\nfrom pathlib import Path\nassert sys.argv[1:] in {allowed!r}, 'unscripted command rejected'\nwith Path({str(root / 'executed')!r}).open('a') as f: f.write('executed\\n')\nprint('fixture action executed')\n"
        )
        stub.chmod(0o700)
        local = bin_dir / "git"
        local.write_text(
            f"#!{sys.executable}\nimport sys\nfrom pathlib import Path\nassert sys.argv[1:] == ['status']\nwith Path({str(root / 'executed')!r}).open('a') as f: f.write('executed\\n')\nprint('fixture local inspection')\n"
        )
        local.chmod(0o700)
        if mode == "real":
            for filename in ("runtime.json", "inference.key", "readiness.json"):
                if (runtime_root / filename).exists():
                    shutil.copyfile(runtime_root / filename, root / filename)
        else:
            atomic_json_write(
                root / "runtime.json",
                {
                    "runner": str(stub),
                    "runner_sha256": d.hashlib.sha256(stub.read_bytes()).hexdigest(),
                    "model_sha256": d.MODEL_SHA256,
                },
            )
        atomic_json_write(
            root / "fixture.json",
            {"client": client, "mode": mode, "reports": reports, "config": config},
        )
        atomic_json_write(root / "config.json", config)
        hook_command = shlex.join(
            [sys.executable, str(Path(__file__).resolve()), "hook", str(root)]
        )
        hooks = {
            "hooks": {
                "PreToolUse": [
                    {"matcher": ".*", "hooks": [{"type": "command", "command": hook_command}]}
                ]
            }
        }
        calls = []

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def do_POST(self):
                body = json.loads(
                    self.rfile.read(int(self.headers.get("Content-Length", 0))) or b"{}"
                )
                if self.path.endswith("count_tokens"):
                    self.send_response(200)
                    self.end_headers()
                    self.wfile.write(b'{"input_tokens":10}')
                    return
                if client == "claude" and not any(
                    t.get("name") == "Bash" for t in body.get("tools", [])
                ):
                    answer = {
                        "id": "auxiliary",
                        "type": "message",
                        "role": "assistant",
                        "model": "claude-sonnet-4-6",
                        "content": [{"type": "text", "text": "fixture"}],
                        "stop_reason": "end_turn",
                        "usage": {"input_tokens": 1, "output_tokens": 1},
                    }
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.end_headers()
                    self.wfile.write(json.dumps(answer).encode())
                    return
                index = len(calls)
                calls.append(body)
                if mode == "contract" and index == 1:
                    state = d.State(root)
                    row = state.db.execute(
                        "SELECT id FROM decisions ORDER BY rowid DESC LIMIT 1"
                    ).fetchone()
                    if row:
                        state.retry(row[0], time.time())
                    state.close()
                if mode == "contract" and index == 3:
                    (root / "recovered").touch()
                commands = (
                    [[str(stub), *arguments]] * 4
                    if mode == "contract"
                    else [
                        [str(stub), *arguments],
                        [str(stub), *other_arguments],
                        [str(local), "status"],
                        [str(stub), *diagnostic],
                    ]
                )
                command = shlex.join(commands[min(index, 3)])
                if client == "claude":
                    item = (
                        {
                            "type": "tool_use",
                            "id": f"call_{index}",
                            "name": "Bash",
                            "input": {"command": command},
                        }
                        if index < 4
                        else {"type": "text", "text": "fixture complete"}
                    )
                    answer = {
                        "id": f"msg_{index}",
                        "type": "message",
                        "role": "assistant",
                        "model": "claude-sonnet-4-6",
                        "content": [item],
                        "stop_reason": "tool_use" if index < 4 else "end_turn",
                        "stop_sequence": None,
                        "usage": {"input_tokens": 10, "output_tokens": 10},
                    }
                    self.send_response(200)
                    self.send_header(
                        "Content-Type",
                        "text/event-stream" if body.get("stream") else "application/json",
                    )
                    self.end_headers()
                    if body.get("stream"):
                        block = {**item, "input": {}} if index < 4 else {"type": "text", "text": ""}
                        delta = (
                            {"type": "input_json_delta", "partial_json": json.dumps(item["input"])}
                            if index < 4
                            else {"type": "text_delta", "text": item["text"]}
                        )
                        events = [
                            {
                                "type": "message_start",
                                "message": {**answer, "content": [], "stop_reason": None},
                            },
                            {"type": "content_block_start", "index": 0, "content_block": block},
                            {"type": "content_block_delta", "index": 0, "delta": delta},
                            {"type": "content_block_stop", "index": 0},
                            {
                                "type": "message_delta",
                                "delta": {
                                    "stop_reason": answer["stop_reason"],
                                    "stop_sequence": None,
                                },
                                "usage": {"output_tokens": 10},
                            },
                            {"type": "message_stop"},
                        ]
                        for event in events:
                            self.wfile.write(
                                (
                                    "event: "
                                    + event["type"]
                                    + "\ndata: "
                                    + json.dumps(event)
                                    + "\n\n"
                                ).encode()
                            )
                    else:
                        self.wfile.write(json.dumps(answer).encode())
                else:
                    item = (
                        {
                            "type": "function_call",
                            "id": f"fc_{index}",
                            "call_id": f"call_{index}",
                            "name": "exec_command",
                            "arguments": json.dumps({"cmd": command, "yield_time_ms": 1000}),
                        }
                        if index < 4
                        else {
                            "type": "message",
                            "id": f"msg_{index}",
                            "role": "assistant",
                            "status": "completed",
                            "content": [
                                {
                                    "type": "output_text",
                                    "text": "fixture complete",
                                    "annotations": [],
                                }
                            ],
                        }
                    )
                    response = {
                        "id": f"resp_{index}",
                        "object": "response",
                        "status": "completed",
                        "output": [item],
                        "usage": {"input_tokens": 10, "output_tokens": 10, "total_tokens": 20},
                    }
                    events = [
                        {
                            "type": "response.created",
                            "response": {**response, "status": "in_progress", "output": []},
                        },
                        {"type": "response.output_item.added", "output_index": 0, "item": item},
                        {"type": "response.output_item.done", "output_index": 0, "item": item},
                        {"type": "response.completed", "response": response},
                    ]
                    self.send_response(200)
                    self.send_header("Content-Type", "text/event-stream")
                    self.end_headers()
                    for event in events:
                        self.wfile.write(
                            (
                                "event: " + event["type"] + "\ndata: " + json.dumps(event) + "\n\n"
                            ).encode()
                        )
                    self.wfile.flush()

        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        endpoint = f"http://127.0.0.1:{server.server_port}"
        env = {
            "HOME": directory,
            "PATH": str(bin_dir) + os.pathsep + os.environ["PATH"],
            "HOLD_UP_STATE_DIR": directory,
            "TMPDIR": directory,
            "DISABLE_TELEMETRY": "1",
            "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC": "1",
        }
        if client == "codex":
            home = root / "codex"
            home.mkdir()
            (home / "hooks.json").write_text(json.dumps(hooks))
            (home / "config.toml").write_text(
                f'model = "fixture"\nmodel_provider = "fixture"\n[features]\nhooks = true\nplugins = false\n[model_providers.fixture]\nname = "fixture"\nbase_url = "{endpoint}/v1"\nwire_api = "responses"\n'
            )
            env["CODEX_HOME"] = str(home)
            # Vetted test-only hooks, isolated HOME; no persistent user trust is changed.
            command = [
                binary,
                "exec",
                "--skip-git-repo-check",
                "--ephemeral",
                "--dangerously-bypass-hook-trust",
                "--sandbox",
                "danger-full-access",
                "--json",
                "run the supplied fixture actions",
            ]
        else:
            home = root / "claude"
            home.mkdir()
            (home / "settings.json").write_text(json.dumps(hooks))
            env.update(
                CLAUDE_CONFIG_DIR=str(home),
                ANTHROPIC_API_KEY="fixture-only",
                ANTHROPIC_BASE_URL=endpoint,
            )
            command = [
                binary,
                "-p",
                "--model",
                "claude-sonnet-4-6",
                "--permission-mode",
                "bypassPermissions",
                "--output-format",
                "json",
                "run the supplied fixture actions",
            ]
        try:
            result = subprocess.run(
                command, cwd=root, env=env, capture_output=True, text=True, timeout=60
            )
            records = (
                [json.loads(line) for line in (root / "hooks.jsonl").read_text().splitlines()]
                if (root / "hooks.jsonl").exists()
                else []
            )
            executions = (
                (root / "executed").read_text().splitlines() if (root / "executed").exists() else []
            )
            summary = {
                "client": client,
                "mode": mode,
                "source": source if mode == "real" else "synthetic",
                "model_qualified": d.enforcement_ready(root) if mode == "real" else None,
                "exit_code": result.returncode,
                "model_requests": len(calls),
                "hook_calls": len(records),
                "executions": len(executions),
            }
            print(json.dumps(summary))
            if output_dir:
                output_dir.mkdir(parents=True, exist_ok=True)
                atomic_json_write(
                    output_dir / f"{client}-{mode}-{source}.json", {**summary, "records": records}
                )
            expected_executions = (
                2
                if mode == "contract"
                else sum(
                    not (r["result"] or {}).get("hookSpecificOutput", {}).get("permissionDecision")
                    == "deny"
                    for r in records
                )
            )
            if result.returncode or len(executions) != expected_executions or len(records) != 4:
                print(result.stdout[-6000:])
                print(result.stderr[-2000:])
                raise AssertionError("native denial/retry/recovery contract failed")
            decisions = [
                r["result"].get("hookSpecificOutput", {}).get("permissionDecision")
                if r["result"]
                else None
                for r in records
            ]
            if mode == "contract":
                assert decisions == ["deny", None, "deny", None], decisions
            else:
                assert decisions[1:] == [None, None, None], decisions
                summary["blocking_verified"] = bool(
                    d.enforcement_ready(root) and decisions[0] == "deny"
                )
                print(json.dumps(summary))
            assert all(r["seconds"] < 5 for r in records), "hook exceeded deadline"
        finally:
            server.shutdown()
            server.server_close()


if __name__ == "__main__":
    if sys.argv[1] == "hook":
        hook(Path(sys.argv[2]))
    else:
        parser = argparse.ArgumentParser()
        parser.add_argument("client", choices=["codex", "claude"])
        parser.add_argument("binary")
        parser.add_argument("--mode", choices=["contract", "real"], default="contract")
        parser.add_argument("--source", choices=["capture", "live"], default="capture")
        parser.add_argument("--output-dir", type=Path)
        args = parser.parse_args()
        run(args.client, args.binary, args.mode, args.source, args.output_dir)
