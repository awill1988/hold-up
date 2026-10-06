"""Measure installed hook processes independently of native client inference."""

import argparse
import concurrent.futures
import json
import os
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

from holdup import routes
from holdup.engine import validate_configuration
from holdup.socket_runtime import Runtime, SocketOwner


def benchmark(samples=100, parallel=1):
    with tempfile.TemporaryDirectory(prefix="hold-up-benchmark-") as directory:
        root = Path(directory)
        config, _ = validate_configuration(
            {"feeds": [{"name": "AWS", "url": "https://example.invalid", "format": "aws-json"}]}
        )
        (root / "config.json").write_text(json.dumps(config))
        runtime = Runtime(root, config)
        payload = {
            "session_id": "benchmark",
            "tool_name": "Bash",
            "tool_input": {"command": "aws --region us-east-1 ec2 run-instances"},
        }
        route = routes.normalize(payload)
        runtime.snapshot = {
            "qualified": False,
            "fetched_at": time.time(),
            "content": "benchmark",
            "rules": {
                routes.key(route): {
                    "decision": "pause",
                    "evidence_ids": ["fixture"],
                    "providers": ["AWS"],
                }
            },
        }
        with SocketOwner(runtime) as owner:
            thread = threading.Thread(target=owner.serve_forever, kwargs={"poll_interval": 0.01})
            thread.start()
            try:
                result = {}
                for agent in ("claude", "codex", "antigravity"):

                    def attempt(index):
                        command = [
                            sys.executable,
                            "-m",
                            "holdup",
                            "--client",
                            agent,
                            "--event",
                            "PreToolUse",
                            "--config",
                            str(root / "config.json"),
                        ]
                        event = {**payload, "tool_use_id": str(index)}
                        if agent == "antigravity":
                            event = {
                                "conversationId": "benchmark",
                                "stepIdx": index,
                                "toolCall": {
                                    "name": "run_command",
                                    "args": {"CommandLine": payload["tool_input"]["command"]},
                                },
                            }
                        started = time.monotonic()
                        process = subprocess.run(
                            command,
                            input=json.dumps(event),
                            text=True,
                            capture_output=True,
                            timeout=5,
                            env={**os.environ, "HOLD_UP_STATE_DIR": directory},
                        )
                        return {
                            "seconds": time.monotonic() - started,
                            "socket_failed": "socket_unavailable" in process.stderr,
                            "exit_code": process.returncode,
                        }

                    with concurrent.futures.ThreadPoolExecutor(max_workers=parallel) as pool:
                        rows = list(pool.map(attempt, range(samples)))
                    elapsed = sorted(r["seconds"] for r in rows)
                    result[agent] = {
                        "samples": samples,
                        "parallel": parallel,
                        "p50_ms": elapsed[int(samples * 0.5)] * 1000,
                        "p95_ms": elapsed[int(samples * 0.95)] * 1000,
                        "max_ms": elapsed[-1] * 1000,
                        "socket_failures": sum(r["socket_failed"] for r in rows),
                        "rows": rows,
                    }
                return {
                    "kind": "installed_package_processes",
                    "model_qualification": "not tested",
                    "agents": result,
                    "target_passed": all(
                        r["p95_ms"] < 100 and r["socket_failures"] == 0 for r in result.values()
                    ),
                }
            finally:
                owner.shutdown()
                thread.join()
                runtime.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--samples", type=int, default=100)
    parser.add_argument("--parallel", type=int, default=1)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    report = benchmark(args.samples, args.parallel)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + "\n")
    print(
        json.dumps(
            {
                "target_passed": report["target_passed"],
                "agents": {
                    k: {key: value for key, value in v.items() if key != "rows"}
                    for k, v in report["agents"].items()
                },
            }
        )
    )
