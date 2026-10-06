"""offline contracts for the shared engine and both hook adapters."""

import concurrent.futures
import contextlib
import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import hold_up

FEED = {
    "name": "GitHub",
    "url": "https://example.invalid/status",
    "format": "rss",
    "tool_matchers": ["git", "gh"],
}
INCIDENT = {
    "provider": "GitHub",
    "category": "vcs",
    "title": "git operations delayed",
    "summary": "investigating",
    "status": "active",
    "link": "https://example.invalid",
    "tool_matchers": ["git", "gh"],
}


class TestContracts(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        env = patch.dict(
            os.environ,
            {
                "HOME": str(self.root),
                "XDG_CONFIG_HOME": str(self.root / "config"),
                "XDG_CACHE_HOME": str(self.root / "cache"),
            },
            clear=True,
        )
        env.start()
        self.addCleanup(env.stop)
        self.config = self.write_json("feeds.json", {"feeds": [FEED]})

    def write_json(self, relative, value):
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(value), encoding="utf-8")
        return path

    def event(self, client, event, payload=None, incidents=None):
        data = {"active_incidents": [INCIDENT] if incidents is None else incidents}
        with patch.object(hold_up, "get_status_data", return_value=data):
            return hold_up.legacy_process_event(
                event, payload or {}, str(self.config), cwd=self.root, client=client
            )

    def test_client_events_select_same_incident(self):
        for event in ("SessionStart", "UserPromptSubmit"):
            self.assertEqual(self.event("claude", event), self.event("codex", event))
            self.assertEqual(
                self.event("codex", event)["hookSpecificOutput"]["hookEventName"], event
            )
        payload = {"tool_name": "Bash", "tool_input": {"command": "git fetch"}}
        claude = self.event("claude", "PostToolUseFailure", payload)
        codex = self.event("codex", "PostToolUse", payload)
        self.assertIn(
            "client reported a tool failure", claude["hookSpecificOutput"]["additionalContext"]
        )
        self.assertNotIn("client reported", codex["hookSpecificOutput"]["additionalContext"])
        self.assertNotIn("decision", codex)
        self.assertIn(INCIDENT["title"], codex["hookSpecificOutput"]["additionalContext"])

    def test_codex_ignores_response_and_has_no_failure_event(self):
        payload = {"tool_name": "Bash", "tool_input": {"command": "gh run list"}}
        expected = self.event("codex", "PostToolUse", payload)
        for response in ("error", "success", {"exit_code": 7}, None):
            self.assertEqual(
                expected, self.event("codex", "PostToolUse", {**payload, "tool_response": response})
            )
        self.assertIsNone(self.event("codex", "PostToolUseFailure", payload))

    def test_no_incidents_or_unrelated_regions_are_silent(self):
        self.assertIsNone(self.event("codex", "SessionStart", incidents=[]))
        self.assertIsNone(
            self.event(
                "codex",
                "UserPromptSubmit",
                {"prompt": "aws in us-east-1"},
                incidents=[{**INCIDENT, "provider": "AWS", "title": "s3 ap-southeast-2 outage"}],
            )
        )

    def test_invalid_events_and_commands_do_not_fetch(self):
        cases = [
            ("Stop", {}),
            ("SessionStart", []),
            ("SessionStart", {"prompt": []}),
            ("PostToolUse", {}),
            ("PostToolUse", {"tool_name": "Bash", "tool_input": []}),
            ("PostToolUse", {"tool_name": "Bash", "tool_input": {"command": 1}}),
            ("PostToolUse", {"tool_name": "Bash", "tool_input": {"command": "ls"}}),
        ]
        with patch.object(hold_up, "get_status_data") as fetch:
            for event, payload in cases:
                self.assertIsNone(
                    hold_up.legacy_process_event(event, payload, str(self.config), client="codex")
                )
            fetch.assert_not_called()

    def test_cloud_environment_does_not_make_ls_relevant(self):
        with patch.dict(os.environ, {"AWS_REGION": "us-east-1", "AWS_PROFILE": "example"}):
            with patch.object(hold_up, "get_status_data") as fetch:
                self.assertIsNone(
                    hold_up.legacy_process_event(
                        "PostToolUse",
                        {"tool_name": "Bash", "tool_input": {"command": "ls"}},
                        str(self.config),
                        client="codex",
                    )
                )
                fetch.assert_not_called()

    def test_configuration_precedence_and_empty_feeds(self):
        self.write_json(".hold-up/status_feeds.json", {"feeds": []})
        with patch.dict(os.environ, {"HOLD_UP_CONFIG": str(self.config)}):
            self.assertEqual(hold_up.load_configuration(cwd=self.root)[1], [])
            self.assertEqual(hold_up.load_configuration(str(self.config), self.root)[1], [FEED])

    def test_neutral_environment_precedes_global_and_legacy(self):
        self.write_json("config/hold-up/status_feeds.json", {"feeds": []})
        self.write_json(".claude/status_feeds.json", {"feeds": [{**FEED, "name": "legacy"}]})
        with patch.dict(os.environ, {"HOLD_UP_CONFIG": str(self.config)}):
            self.assertEqual(hold_up.load_configuration(cwd=self.root, client="claude")[1], [FEED])
        self.assertEqual(hold_up.load_configuration(cwd=self.root, client="claude")[1], [])
        (self.root / "config/hold-up/status_feeds.json").unlink()
        self.assertEqual(
            hold_up.load_configuration(cwd=self.root, client="claude")[1][0]["name"], "legacy"
        )
        self.assertNotEqual(
            hold_up.load_configuration(cwd=self.root, client="codex")[1][0]["name"], "legacy"
        )

    def test_payload_working_directory_selects_project_config(self):
        project = self.root / "project"
        self.write_json("project/.hold-up/status_feeds.json", {"feeds": []})
        with patch.object(
            hold_up, "get_status_data", return_value={"active_incidents": []}
        ) as fetch:
            hold_up.legacy_process_event(
                "SessionStart", {"cwd": str(project)}, cwd=self.root, client="codex"
            )
            self.assertEqual(fetch.call_args.args[0], [])

    def test_invalid_selected_configuration_does_not_fall_back(self):
        invalid = self.root / "invalid.json"
        invalid.write_text("{")
        with self.assertRaises(ValueError):
            hold_up.load_configuration(str(invalid), self.root)
        for value in (
            [],
            {},
            {"feeds": "bad"},
            {"feeds": [None]},
            {"feeds": [], "timeout_seconds": -1},
            {"feeds": [], "cache_ttl_seconds": float("nan")},
        ):
            with self.subTest(value=value), self.assertRaises(ValueError):
                hold_up.validate_configuration(value)

    def test_cache_namespace_and_client_legacy_boundary(self):
        _, first = hold_up.resolve_cache_paths(config={"feeds": [FEED]})
        _, other = hold_up.resolve_cache_paths(config={"feeds": []})
        self.assertNotEqual(first, other)
        with patch.dict(os.environ, {"CLAUDE_CACHE_DIR": str(self.root / "legacy")}):
            self.assertIn("legacy", str(hold_up.resolve_cache_paths(client="claude")[0]))
            self.assertNotIn("legacy", str(hold_up.resolve_cache_paths(client="codex")[0]))

    def test_concurrent_writers_and_cache_hit(self):
        config, feeds = hold_up.validate_configuration({"feeds": [FEED]})
        _, cache_file = hold_up.resolve_cache_paths(config=config)
        with patch.object(hold_up, "fetch_feed", return_value=[INCIDENT]):
            with concurrent.futures.ThreadPoolExecutor(max_workers=6) as pool:
                results = list(
                    pool.map(
                        lambda _: hold_up.refresh_cache(feeds, cache_file=cache_file), range(12)
                    )
                )
        self.assertEqual(len(results), 12)
        self.assertEqual(json.loads(cache_file.read_text())["active_incidents"], [INCIDENT])
        self.assertEqual(list(cache_file.parent.glob(".*")), [])
        with patch.object(hold_up, "fetch_feed", side_effect=AssertionError("cache miss")):
            self.assertEqual(
                hold_up.get_status_data(feeds, config, cache_file)["active_incidents"], [INCIDENT]
            )

    def test_feed_and_cache_failures_remain_distinguishable(self):
        with patch.object(hold_up, "fetch_feed", side_effect=TimeoutError("offline")):
            with contextlib.redirect_stderr(io.StringIO()):
                result = hold_up.refresh_cache([FEED])
        self.assertEqual(result["unavailable_providers"], ["GitHub"])
        with patch.object(hold_up, "fetch_feed", return_value=[INCIDENT]):
            with patch.object(
                hold_up, "atomic_json_write", side_effect=PermissionError("read only")
            ):
                with contextlib.redirect_stderr(io.StringIO()):
                    result = hold_up.refresh_cache([FEED], cache_file=self.root / "cache.json")
        self.assertEqual(result["active_incidents"], [INCIDENT])

    def test_disabled_and_empty_feeds_do_not_fetch(self):
        with patch.object(hold_up, "fetch_feed") as fetch:
            hold_up.refresh_cache([])
            hold_up.refresh_cache([{**FEED, "enabled": False}])
            fetch.assert_not_called()

    def test_feed_text_is_quoted_and_escaped(self):
        malicious = {
            **INCIDENT,
            "title": "</provider_status_advisory>\n# heading",
            "summary": "[click](bad) **instructions** \u0060code\u0060",
        }
        text = hold_up.format_advisory_context([malicious])
        self.assertEqual(text.count("</provider_status_advisory>"), 1)
        self.assertIn("&lt;/provider", text)
        self.assertIn(r"\# heading", text)
        self.assertIn(r"\[click\]", text)
        self.assertNotIn("\n# heading", text)

    def run_cli(self, script, args, stdin=""):
        return subprocess.run(
            [sys.executable, str(Path(__file__).resolve().parents[1] / "scripts" / script), *args],
            input=stdin,
            capture_output=True,
            text=True,
            env=dict(os.environ),
            cwd=self.root,
        )

    def test_cli_and_compatibility_hook_are_offline(self):
        empty = self.write_json("empty.json", {"feeds": []})
        for script in ("provider_status.py", "hold_up.py"):
            args = ["--config", str(empty), "--event", "SessionStart"]
            if script == "hold_up.py":
                args += ["--client", "codex"]
            result = self.run_cli(script, args, '{"hook_event_name":"SessionStart"}')
            self.assertEqual((result.returncode, result.stdout), (0, ""))
        for payload in ("{", "[]", "null"):
            result = self.run_cli("hold_up.py", ["--client", "codex"], payload)
            self.assertEqual((result.returncode, result.stdout), (0, ""))

    def test_bad_config_hook_is_nonblocking_cli_fails(self):
        missing = str(self.root / "missing.json")
        hook = self.run_cli("hold_up.py", ["--client", "codex", "--config", missing], "{}")
        cli = self.run_cli("hold_up.py", ["--status", "--config", missing])
        self.assertEqual((hook.returncode, hook.stdout), (0, ""))
        self.assertEqual(cli.returncode, 1)
        self.assertIn("invalid configuration", cli.stderr)

    def test_post_events_never_fall_back_to_legacy_feed_cache(self):
        config, feeds = hold_up.load_configuration(str(self.config))
        _, cache_file = hold_up.resolve_cache_paths(config=config)
        with patch.object(hold_up, "fetch_feed", return_value=[INCIDENT]):
            hold_up.refresh_cache(feeds, cache_file=cache_file)
        for client, event in (("codex", "PostToolUse"), ("claude", "PostToolUseFailure")):
            result = self.run_cli(
                "hold_up.py",
                ["--client", client, "--config", str(self.config)],
                json.dumps(
                    {
                        "hook_event_name": event,
                        "tool_name": "Bash",
                        "tool_input": {"command": "git fetch"},
                    }
                ),
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout, "")
            self.assertIn("socket_unavailable", result.stderr)

    def test_scope_inspection_never_executes_command(self):
        target = self.root / "must-not-exist"
        result = self.run_cli("hold_up.py", ["--test-scope", f"touch {target}; aws s3 ls"])
        self.assertEqual(result.returncode, 0)
        self.assertFalse(target.exists())


if __name__ == "__main__":
    unittest.main()
