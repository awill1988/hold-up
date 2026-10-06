"""Bounded local outcome storage; unavailable observations remain unknown."""

import json
import queue
import sqlite3
import threading
import time
from collections import Counter
from contextlib import contextmanager

AGENTS = ("claude", "codex", "antigravity", "unknown")


class Telemetry:
    def __init__(self, root):
        self.path = root / "telemetry.sqlite3"
        self.queue = queue.Queue(maxsize=1024)
        self.dropped = 0
        self.stopped = threading.Event()
        with self.connect() as db:
            db.execute("PRAGMA journal_mode=WAL")
            db.execute(
                "CREATE TABLE IF NOT EXISTS events (id INTEGER PRIMARY KEY, stamp REAL, agent TEXT, event TEXT, outcome TEXT, reason TEXT, correlation TEXT, seconds REAL, emitted INTEGER)"
            )
            db.execute("CREATE INDEX IF NOT EXISTS event_time ON events(stamp)")
            db.execute(
                "CREATE UNIQUE INDEX IF NOT EXISTS event_once ON events(agent,event,correlation) WHERE correlation != ''"
            )
        self.thread = threading.Thread(target=self.write_loop, daemon=True)
        self.thread.start()

    @contextmanager
    def connect(self):
        db = sqlite3.connect(self.path, timeout=0.005)
        try:
            with db:
                yield db
        finally:
            db.close()

    def emit(self, agent, event, outcome, reason, correlation="", seconds=0, emitted=False):
        try:
            self.queue.put_nowait(
                (time.time(), agent, event, outcome, reason, correlation, seconds, int(emitted))
            )
        except queue.Full:
            self.dropped += 1

    def write_loop(self):
        while not self.stopped.is_set() or not self.queue.empty():
            try:
                row = self.queue.get(timeout=0.1)
            except queue.Empty:
                continue
            rows = [row]
            while len(rows) < 128:
                try:
                    rows.append(self.queue.get_nowait())
                except queue.Empty:
                    break
            try:
                with self.connect() as db:
                    db.executemany(
                        "INSERT OR IGNORE INTO events(stamp,agent,event,outcome,reason,correlation,seconds,emitted) VALUES(?,?,?,?,?,?,?,?)",
                        rows,
                    )
                    db.execute(
                        "DELETE FROM events WHERE stamp < ? OR id <= COALESCE((SELECT id FROM events ORDER BY id DESC LIMIT 1 OFFSET 100000),0)",
                        (time.time() - 30 * 86400,),
                    )
            except sqlite3.Error:
                self.dropped += len(rows)

    def close(self):
        self.stopped.set()
        self.thread.join(timeout=2)

    def stats(self, since=86400, agent=None):
        result = []
        with self.connect() as db:
            for program in [agent] if agent else AGENTS:
                rows = db.execute(
                    "SELECT event,outcome,reason,seconds,emitted,stamp FROM events WHERE agent=? AND stamp>=?",
                    (program, time.time() - since),
                ).fetchall()
                checks = [r for r in rows if r[0] == "PreToolUse"]
                elapsed = sorted(r[3] for r in rows if r[0] == "hook_timing")
                result.append(
                    {
                        "agent": program,
                        "coverage": "observed" if rows else "not observed",
                        "checks": len(checks),
                        "decision_reasons": dict(Counter(r[2] for r in checks)),
                        "routing_follow_through": "not measured",
                        "advisories_emitted": sum(r[1] == "advise" and r[4] == 1 for r in rows),
                        "advisories_suppressed": sum(
                            r[1] == "advise" and r[4] == 0 for r in checks
                        ),
                        "advisories_queued": sum(r[1] == "advise" and r[4] == -1 for r in checks),
                        "denials_issued": sum(r[1] == "pause" for r in checks),
                        "retries": sum(r[2] == "retry_consumed" for r in checks),
                        "completions": sum(
                            r[0] in ("PostToolUse", "PostToolUseFailure") for r in rows
                        ),
                        "failures": sum(r[1] == "failed" for r in rows),
                        "outcome_unknown": sum(r[1] == "unknown" for r in rows),
                        "unmatched": sum(r[2] == "unmatched" for r in rows),
                        "p50_ms": elapsed[int((len(elapsed) - 1) * 0.50)] * 1000
                        if elapsed
                        else None,
                        "p95_ms": elapsed[int((len(elapsed) - 1) * 0.95)] * 1000
                        if elapsed
                        else None,
                        "last_activity": max((r[5] for r in rows), default=None),
                    }
                )
        return {
            "agents": result,
            "dropped_events_since_start": self.dropped,
            "best_effort": True,
            "latency_scope": "adapter_processing_excludes_process_startup",
        }


def render(report):
    print("agent         checks advice denied retry completed failed p95_ms coverage")
    for row in report["agents"]:
        latency = "unknown" if row["p95_ms"] is None else f"{row['p95_ms']:.2f}"
        print(
            f"{row['agent']:<13} {row['checks']:>6} {row['advisories_emitted']:>6} {row['denials_issued']:>6} {row['retries']:>5} {row['completions']:>9} {row['failures']:>6} {latency:>7} {row['coverage']}"
        )
    print(json.dumps({k: v for k, v in report.items() if k != "agents"}))
