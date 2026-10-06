"""A local socket owner; inference runs only in its disposable preparation process."""

import json
import os
import socketserver
import sqlite3
import subprocess
import sys
import threading
import time
from collections.abc import Mapping

from . import decision as d
from . import routes, transport
from .data import freeze, immutable_result, json_value
from .telemetry import AGENTS, Telemetry


def prepare(config, feeds, root):
    from . import evidence
    from .engine import atomic_json_write

    snapshot = evidence.collect(config, feeds, root)
    generation = d.policy_digest()
    ready = d.enforcement_ready(root)
    try:
        fingerprint = d.runtime_fingerprint(root)
    except (OSError, ValueError, KeyError):
        fingerprint = None
    content = d.digest(
        [{k: v for k, v in r.items() if k != "fetched_at"} for r in snapshot["reports"]]
    )
    previous = {}
    try:
        previous = json.loads((root / "prepared.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        pass
    reusable = all(
        previous.get(k) == v
        for k, v in {
            "content": content,
            "generation": generation,
            "fingerprint": fingerprint,
        }.items()
    )
    rules = {}
    started = time.monotonic()
    regions = sorted(
        {
            r["region"]
            for r in snapshot["reports"]
            if isinstance(r.get("region"), str) and routes.REGION.fullmatch(r["region"])
        }
    )
    failure = None
    for region in regions[:32]:
        for service, operations in routes.OPERATIONS.items():
            for operation in operations:
                route = {
                    "kind": "remote",
                    "service": service,
                    "operation": operation,
                    "region": region,
                }
                key = routes.key(route)
                if reusable and key in previous.get("rules", {}):
                    rules[key] = previous["rules"][key]
                    continue
                if failure or time.monotonic() - started > 45:
                    continue
                try:
                    rules[key] = routes.classify(
                        route, snapshot["reports"], config.get("decision", {})
                    )
                except Exception as error:
                    failure = (
                        str(error)
                        if str(error) in ("evidence_incomplete", "evidence_context_overflow")
                        else "model_output_invalid"
                    )
    atomic_json_write(
        root / "prepared.json",
        {
            **snapshot,
            "generation": generation,
            "fingerprint": fingerprint,
            "content": content,
            "qualified": ready,
            "rules": rules,
            "failure": failure,
        },
    )


class Runtime:
    def __init__(self, root, config):
        self.root, self.config = root, freeze(config)
        transport.private_directory(root)
        self.generation = d.policy_digest()
        self.snapshot = {}
        self.lock = threading.Lock()
        self.state = d.State(root)
        self.state.db.close()
        self.state.db = sqlite3.connect(
            root / "decisions.sqlite3", timeout=0.005, check_same_thread=False
        )
        self.state.db.execute("PRAGMA synchronous=NORMAL")
        self.telemetry = Telemetry(root)
        self.pending = {}
        self.notices = {}
        self.correlations = {}

    @property
    def snapshot(self):
        return self._snapshot

    @snapshot.setter
    def snapshot(self, value):
        self._snapshot = freeze(value)

    def close(self):
        self.telemetry.close()
        self.state.close()

    def reload(self):
        try:
            path = self.root / "prepared.json"
            if path.stat().st_size > 1024 * 1024:  # 1 MiB
                raise ValueError("snapshot_oversized")
            value = json.loads(path.read_text(encoding="utf-8"))
            if value.get("generation") != self.generation or value.get("config_hash") != d.digest(
                self.config
            ):
                raise ValueError("snapshot_invalid")
            self.snapshot = value
        except (OSError, ValueError, AttributeError):
            self.snapshot = {}

    def dispatch(self, message):
        if message.get("event") in ("stats", "status"):
            return self.handle(message)
        if not self.lock.acquire(timeout=0.025):
            return {"error": "runtime_busy"}
        try:
            return self.handle(message)
        finally:
            self.lock.release()

    @immutable_result
    def handle(self, message):
        event = message.get("event")
        if event == "status":
            return {
                "generation": self.generation,
                "qualified": self.snapshot.get("qualified", False),
                "evidence_age_seconds": time.time() - self.snapshot.get("fetched_at", 0),
                **self.telemetry.stats(),
            }
        if event == "stats":
            since = message.get("since", 86400)
            agent = message.get("agent")
            if (
                type(since) not in (int, float)
                or not 0 < since <= 30 * 86400
                or agent not in (*AGENTS, None)
            ):
                raise ValueError("invalid_stats_request")
            return self.telemetry.stats(since, agent)
        if event == "retry":
            self.state.retry(str(message.get("decision_id")), time.time())
            return {"approved": True}
        agent = message.get("agent")
        if agent not in AGENTS:
            raise ValueError("invalid_agent")
        correlation = message.get("correlation", "")
        namespace = message.get("namespace", "")
        if not all(
            isinstance(v, str)
            and (not v or len(v) == 64 and all(c in "0123456789abcdef" for c in v))
            for v in (correlation, namespace, message.get("action_key", ""))
        ):
            raise ValueError("invalid_identifier")
        now = time.time()
        for store in (self.pending, self.notices, self.correlations):
            if len(store) > 10000:
                store.clear()
        self.correlations = {k: v for k, v in self.correlations.items() if now - v < 300}
        if event == "hook_timing":
            elapsed = message.get("seconds")
            if type(elapsed) not in (float, int) or not 0 <= elapsed <= 5:
                raise ValueError("invalid_timing")
            self.telemetry.emit(agent, event, "observed", "hook_worker", correlation, elapsed)
            return {}
        if event in ("PostToolUse", "PostToolUseFailure"):
            outcome = message.get("outcome", "unknown")
            if outcome not in ("completed", "failed", "unknown"):
                raise ValueError("invalid_outcome")
            matched = (agent, correlation) in self.correlations
            self.telemetry.emit(
                agent, event, outcome, "matched" if matched else "unmatched", correlation
            )
            return {}
        if event == "PreInvocation":
            pending = self.pending.pop(namespace, None)
            if pending and now - pending[1] < 300:
                self.telemetry.emit(agent, "advisory_delivery", "advise", pending[0], emitted=True)
                return {"advisory": pending[0]}
            return {}
        if event != "PreToolUse":
            return {}
        start = time.monotonic()
        route = message.get("route")
        if not isinstance(route, Mapping) or len(json.dumps(route, default=json_value)) > 512:
            raise ValueError("invalid_route")
        result = self.decide(message, route, now)
        notice = d.digest([namespace, result.get("reason"), self.snapshot.get("content")])
        emitted = result["decision"] == "advise" and now - self.notices.get(notice, 0) >= 300
        if emitted:
            self.notices[notice] = now
            if agent == "antigravity":
                self.pending[namespace] = (result["reason"], now)
        result = freeze({**result, "emitted": emitted})
        if correlation:
            self.correlations[agent, correlation] = now
        self.telemetry.emit(
            agent,
            event,
            result["decision"],
            result["reason"],
            correlation,
            time.monotonic() - start,
            -1 if emitted and agent == "antigravity" else emitted,
        )
        return result

    @immutable_result
    def decide(self, message, route, now):
        def result(decision, reason, **extra):
            return {"decision": decision, "reason": reason, **extra}

        mode = message.get("mode", "guard")
        if mode not in ("guard", "advisory", "off"):
            return result("advise", "configuration_invalid")
        if mode == "off" or ("feeds" in self.config and not self.config["feeds"]):
            return result("allow", "disabled")
        if route.get("kind") in ("local", "diagnostic"):
            return result("allow", "protected_action")
        if message.get("generation") != self.generation or message.get("config_hash") != d.digest(
            self.config
        ):
            return result("advise", "configuration_changed")
        namespace = d.digest(
            [message["namespace"], self.generation, self.snapshot.get("fingerprint")]
        )
        action_key = message["action_key"]
        if self.state.consume_retry(namespace, action_key, now):
            return result("allow", "retry_consumed")
        snapshot = self.snapshot
        if not 0 <= now - snapshot.get("fetched_at", 0) < 300 or "AWS" in snapshot.get(
            "unavailable", []
        ):
            return result(
                "advise",
                "feed_decode_failed"
                if snapshot.get("failures", {}).get("AWS") == "feed_decode_failed"
                else "evidence_incomplete",
            )
        if route.get("kind") != "remote":
            return result("advise", "operation_unmapped")
        rule = snapshot.get("rules", {}).get(routes.key(route))
        if not rule:
            return result("advise", snapshot.get("failure") or "evidence_incomplete")
        if rule["decision"] == "pause":
            if not snapshot.get("qualified"):
                return result("advise", "model_unqualified")
            if mode != "guard":
                return result("advise", "affected_operation")
            expires = min(now + 300, snapshot["fetched_at"] + 300)
            identifier = self.state.save(
                namespace, action_key, snapshot["content"], rule, now, expires
            )
            return result(
                "pause",
                "affected_operation",
                decision_id=identifier,
                expires_at=expires,
                evidence_ids=rule["evidence_ids"],
            )
        self.state.save(
            namespace,
            action_key,
            snapshot["content"],
            rule,
            now,
            min(now + 300, snapshot["fetched_at"] + 300),
        )
        return result(
            rule["decision"],
            "no_affected_operation" if rule["decision"] == "allow" else "uncertain_dependency",
        )


class SocketOwner(socketserver.ThreadingTCPServer):
    daemon_threads = False
    block_on_close = True
    allow_reuse_address = False

    def __init__(self, runtime):
        self.runtime = runtime
        self.slots = threading.BoundedSemaphore(16)
        self.owner_lock = transport.lock_owner(runtime.root)
        try:
            super().__init__(("127.0.0.1", 0), Handler)
            self.endpoint = transport.publish_endpoint(runtime.root, self.server_address[1])
        except Exception:
            self.owner_lock.close()
            raise

    def server_close(self):
        super().server_close()
        self.owner_lock.close()

    def process_request(self, request, address):
        if not self.slots.acquire(blocking=False):
            request.close()
            return
        super().process_request(request, address)

    def process_request_thread(self, request, address):
        try:
            super().process_request_thread(request, address)
        finally:
            self.slots.release()


class Handler(socketserver.BaseRequestHandler):
    def handle(self):
        deadline = time.monotonic() + transport.DEADLINE
        try:
            message = transport.receive(self.request, deadline)
            if message.get("version") != transport.VERSION or not transport.authenticate(
                message, self.server.endpoint["secret"]
            ):
                return
            if message.get("event") in ("stats", "status"):
                deadline = time.monotonic() + transport.INSPECTION_DEADLINE
            response = self.server.runtime.dispatch(message)
            response = {"version": transport.VERSION, "nonce": message.get("nonce"), **response}
            transport.send(
                self.request,
                {
                    **response,
                    "signature": transport.signature(response, self.server.endpoint["secret"]),
                },
                deadline,
            )
        except (OSError, ValueError, KeyError, TypeError, sqlite3.Error):
            return


def serve(root, config, config_path=None):
    runtime = Runtime(root, config)
    stopped = threading.Event()

    def refresh():
        while not stopped.is_set():
            command = [sys.executable, "-m", "holdup", "collect", "--prepare-once"]
            if config_path:
                command += ["--config", config_path]
            child = subprocess.Popen(command, env={**os.environ, "HOLD_UP_STATE_DIR": str(root)})
            start = time.monotonic()
            while child.poll() is None and not stopped.wait(0.1):
                if time.monotonic() - start > 60:
                    child.kill()
                    break
            if child.poll() is None:
                child.kill()
            child.wait()
            runtime.reload()
            stopped.wait(max(0, 60 - (time.monotonic() - start)))

    worker = threading.Thread(target=refresh, daemon=True)
    try:
        with SocketOwner(runtime) as owner:
            worker.start()
            owner.serve_forever(poll_interval=0.1)
    finally:
        stopped.set()
        worker.join(timeout=2)
        runtime.close()
