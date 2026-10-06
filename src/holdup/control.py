"""Operator controls and explicit model provisioning; never execute a pending action."""

import argparse
import hashlib
import json
import os
import secrets
import shutil
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

from . import decision


def main(argv):
    parser = argparse.ArgumentParser(prog="hold-up")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("status")
    for name in ("retry", "wait"):
        sub.add_parser(name).add_argument("decision_id")
    sub.add_parser("provision")
    serve = sub.add_parser("serve")
    serve.add_argument("--runner", default="llama-server")
    collector = sub.add_parser("collect")
    collector.add_argument("--config")
    collector.add_argument("--once", action="store_true")
    args = parser.parse_args(argv)
    root = decision.state_root()
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    if args.command == "provision":
        model = root / decision.MODEL_FILE
        temporary = root / (decision.MODEL_FILE + ".download")
        if model.exists():
            with model.open("rb") as stream:
                checksum = (
                    hashlib.file_digest(stream, "sha256").hexdigest()
                    if hasattr(hashlib, "file_digest")
                    else file_hash(stream)
                )
            if checksum == decision.MODEL_SHA256:
                print("model already provisioned")
                return 0
            raise ValueError("existing checkpoint has incorrect checksum; inspect before replacing")
        url = f"https://huggingface.co/{decision.MODEL_REPO}/resolve/{decision.MODEL_REVISION}/{decision.MODEL_FILE}"
        checksum = hashlib.sha256()
        with urllib.request.urlopen(url, timeout=30) as response, temporary.open("xb") as stream:
            while block := response.read(1024 * 1024):
                checksum.update(block)
                stream.write(block)
        if checksum.hexdigest() != decision.MODEL_SHA256:
            raise ValueError("checkpoint checksum mismatch; download retained for inspection")
        temporary.replace(model)
        print("model provisioned and checksum verified")
        return 0
    if args.command == "serve":
        model = root / decision.MODEL_FILE
        with model.open("rb") as stream:
            if file_hash(stream) != decision.MODEL_SHA256:
                raise ValueError("model checksum mismatch")
        key = root / "inference.key"
        if not key.exists():
            fd = os.open(key, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "w") as stream:
                stream.write(secrets.token_urlsafe(32))
        runner = str(Path(shutil.which(args.runner) or args.runner).resolve())
        arguments = [
            runner,
            "-m",
            str(model),
            "--alias",
            "hold-up",
            "--host",
            "127.0.0.1",
            "--port",
            "18473",
            "--api-key-file",
            str(key),
            "--ctx-size",
            "8192",
            "--parallel",
            "1",
            "--jinja",
            "--reasoning-budget",
            "0",
            "--log-disable",
        ]
        from .engine import atomic_json_write

        atomic_json_write(
            root / "runtime.json",
            {
                "runner": runner,
                "runner_sha256": hashlib.sha256(Path(runner).read_bytes()).hexdigest(),
                "model_sha256": decision.MODEL_SHA256,
                "arguments": arguments,
            },
        )
        os.execv(runner, arguments)
    if args.command == "collect":
        from . import evidence
        from .engine import load_configuration

        config, feeds = load_configuration(args.config)
        while True:
            # Isolate slow-drip sockets and executor shutdown from the refresh schedule.
            if args.once:
                evidence.collect(config, feeds, root)
                return 0
            command = [sys.executable, "-m", "holdup", "collect", "--once"]
            if args.config:
                command += ["--config", args.config]
            try:
                subprocess.run(
                    command,
                    timeout=10,
                    check=True,
                    env={
                        **os.environ,
                        "PYTHONPATH": str(Path(__file__).resolve().parent.parent)
                        + os.pathsep
                        + os.environ.get("PYTHONPATH", ""),
                    },
                )
            except (subprocess.TimeoutExpired, subprocess.CalledProcessError):
                sys.stderr.write("warning: evidence refresh failed\n")
            time.sleep(60)
    state = decision.State(root)
    try:
        if args.command == "retry":
            state.retry(args.decision_id, time.time())
            print("one retry approved; ask the agent to try the same action again")
        elif args.command == "status":
            for row in state.db.execute(
                "SELECT id,result,expires FROM decisions WHERE expires>?", (time.time(),)
            ):
                print(json.dumps({"id": row[0], **json.loads(row[1]), "expires_at": row[2]}))
            print(
                "enforcement evaluation: "
                + ("passed" if decision.enforcement_ready(root) else "not validated")
            )
        else:
            while True:
                row = state.db.execute(
                    "SELECT namespace,action,expires,retry_until FROM decisions WHERE id=?",
                    (args.decision_id,),
                ).fetchone()
                if not row:
                    raise ValueError("unknown pause decision")
                if (
                    row[2] <= time.time()
                    or row[3] > time.time()
                    or not state.active(row[0], row[1], time.time())
                ):
                    print("pause released; retry requires a new pre-tool check")
                    break
                time.sleep(1)
    finally:
        state.close()
    return 0


def file_hash(stream):
    checksum = hashlib.sha256()
    while block := stream.read(1024 * 1024):
        checksum.update(block)
    return checksum.hexdigest()
