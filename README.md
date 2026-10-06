# hold-up!

Local outage advice and scoped action guards for **Codex and Claude Code**.

A shared Python engine reads public incident feeds for AWS, Google Cloud,
Microsoft Azure, GitHub, GitLab, and Bitbucket. Client adapters deliver relevant
reports as hook context. A scope match is evidence to investigate, not proof that
an incident caused a command failure.

Before a tool runs, a local NVIDIA model can classify its dependency on a reported
outage. A pause blocks that action, not the session. Blocking requires a passing
local evaluation; without it, the model can only advise. Provider reports cannot
reveal outages that providers have not reported.

## Behavior

- Python 3.10 or later; Poetry manages packaging and development dependencies. The Python runtime uses the standard library.
- RSS, Atom, and AWS JSON feeds, configured in [`src/holdup/data/status_feeds.json`](src/holdup/data/status_feeds.json).
- Provider and region inference from supported commands, prompts, flags, and environment variables.
- Region precedence: command flags, command-local environment, inherited environment, selected AWS profile.
- Unsupported shell constructs are not evaluated; command-based inference abstains.
- Configuration-keyed cache with a default 300-second TTL and 2.5-second network timeout.
- Hook workers have a 5-second execution deadline; feed responses are limited to 1 MiB.
- Unavailable feeds produce diagnostics, not a healthy-status assertion.
- No advisory output when there are no matching incidents. External report text is escaped and presented as data.

## Client adapters

Both adapters use the `holdup` package; the client name selects the event contract.
`scripts/hold_up.py` remains a checkout-compatible entry point.

| Trigger | Codex | Claude Code |
| --- | --- | --- |
| Session start | `SessionStart` | `SessionStart` |
| Prompt submission | `UserPromptSubmit` | `UserPromptSubmit` |
| Before any hook-visible tool | `PreToolUse`, matcher `.*` | `PreToolUse`, matcher `.*` |
| Shell tool event | `PostToolUse`, matcher `Bash` | `PostToolUseFailure`, matcher `Bash` |

Codex tool advisories describe command scope without asserting a failure.
Claude's failure event permits acknowledging the reported failure, but not
attributing its cause to an incident.

## Installation

Clone the implementation branch into a client-neutral directory:

```bash
git clone --branch feat/hold-up https://github.com/awill1988/hold-up.git ~/.local/share/hold-up
cd ~/.local/share/hold-up
poetry install
poetry run hold-up --list-feeds
```

The package uses the `poetry-core` build backend and a committed `poetry.lock`.
Run `poetry build` to produce a wheel and source distribution. No editable
checkout is required by the installed wheel. The compatibility hook scripts
below work from a checkout; installed integrations can invoke the absolute
virtual-environment path returned by `poetry env info --path`, followed by
`/bin/hold-up`, with the same arguments.

Use either direct hooks or the Claude plugin for a given Claude configuration,
not both. Preserve unrelated hooks when merging examples into existing files.
Replace `/absolute/path/to/hold-up` below with the checkout's absolute path.

### Codex hooks

Native hook discovery was verified with Codex `0.154.0`. In the active
`CODEX_HOME` directory (normally `~/.codex`), merge this setting into
`config.toml`:

```toml
[features]
hooks = true
```

Merge these entries into `hooks.json` in the same directory:

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": ".*",
        "hooks": [
          {
            "type": "command",
            "command": "python3 \"/absolute/path/to/hold-up/scripts/hold_up.py\" --client codex --event PreToolUse"
          }
        ]
      }
    ],
    "SessionStart": [
      {
        "matcher": "",
        "hooks": [
          {
            "type": "command",
            "command": "python3 \"/absolute/path/to/hold-up/scripts/hold_up.py\" --client codex --event SessionStart"
          }
        ]
      }
    ],
    "UserPromptSubmit": [
      {
        "matcher": "",
        "hooks": [
          {
            "type": "command",
            "command": "python3 \"/absolute/path/to/hold-up/scripts/hold_up.py\" --client codex --event UserPromptSubmit"
          }
        ]
      }
    ],
    "PostToolUse": [
      {
        "matcher": "Bash",
        "hooks": [
          {
            "type": "command",
            "command": "python3 \"/absolute/path/to/hold-up/scripts/hold_up.py\" --client codex --event PostToolUse"
          }
        ]
      }
    ]
  }
}
```

Open `/hooks` in Codex and review and trust the hook definitions. New or changed
definitions require review; installation alone does not grant trust.
See the [official hook documentation](https://learn.chatgpt.com/docs/hooks).

### Claude Code hooks

Use the same JSON structure in the active Claude `settings.json` (normally
`~/.claude/settings.json`), with these substitutions:

- Replace every `--client codex` with `--client claude`.
- Replace the `PostToolUse` event key and its `--event` argument with `PostToolUseFailure`.

`scripts/provider_status.py` remains a compatibility entry point for existing
Claude installations; new integrations should use `scripts/hold_up.py`.

### Claude Code plugin

The plugin is the Claude-specific adapter, not the identity of the shared engine.
Its existing installation identifier remains `provider-status@awill1988`.

The implementation branch can be loaded directly from the checkout:

```bash
claude --plugin-dir ~/.local/share/hold-up
```

The repository contains a [marketplace catalog](.claude-plugin/marketplace.json).
Its source URL follows the repository's default branch; ensure the intended
revision is published there before using marketplace installation.

### Nix and Home Manager

This repository is a non-flake source input. Select the implementation branch
and commit its resolved revision in the consuming flake lock:

```nix
inputs.hold-up = {
  url = "github:awill1988/hold-up/feat/hold-up";
  flake = false;
};
```

The Home Manager integration lives in the
[dotfiles module](https://github.com/awill1988/dotfiles/tree/master/modules/home/agents/orchestration/hold-up),
not in this repository. It exports `homeManagerModules.home-agent-hold-up`
and provides `programs.hold-up.enable`, `programs.hold-up.customFeeds`,
`programs.hold-up.mode`, and `programs.hold-up.manageRuntime`. Its application
derivation builds the Poetry package. Pin a published revision before deployment.

Managed runtime services use `launchd` on macOS and user `systemd` on Linux.
They run a loopback inference server and a provider evidence collector. Model
weights are provisioned explicitly, never downloaded by a hook or activation.
The Nix-selected mode overrides the JSON mode.

The module generates both client adapters using Nix-store paths and reconciles
only owned hook handlers. Per-profile client eligibility controls registration;
Codex disablement is inherited by child profiles. Activation rejects conflicting
destinations, malformed ownership manifests, and symlinked hook files.

Building does not activate the configuration or approve Codex hook trust.
The `home-agent-provider-status` export and
`programs.claude-provider-status` options remain compatibility aliases.

## Configuration

The first selected configuration is authoritative; feed arrays are not merged
across configuration files. An explicit empty `feeds` array disables fetching.

Selection order:

1. `--config /path/to/status_feeds.json`.
2. `.hold-up/status_feeds.json` in the hook's working directory.
3. `HOLD_UP_CONFIG`.
4. `$XDG_CONFIG_HOME/hold-up/status_feeds.json`, defaulting to `~/.config/hold-up/status_feeds.json`.
5. Claude-only legacy locations when `--client claude` is selected.
6. Bundled `holdup/data/status_feeds.json`, then embedded defaults if no file exists.

A malformed selected configuration fails rather than silently falling back.
Use the bundled registry as the starting point for additional feeds. Supported
formats are `rss`, `atom`, and `aws-json`; the response must match its declared
format.

Cache location precedence is `--cache-dir`, `HOLD_UP_CACHE_DIR`, Claude's
legacy `CLAUDE_CACHE_DIR/provider-status` when applicable, then
`$XDG_CACHE_HOME/hold-up` (default `~/.cache/hold-up`). Each configuration has
its own hashed subdirectory. The dotfiles module also separates profile caches.

## CLI

Run from the checkout:

```bash
poetry run hold-up --list-feeds
poetry run hold-up --test-scope 'aws --region us-west-2 s3 ls'
poetry run hold-up --test-feed "AWS"
poetry run hold-up --status
poetry run hold-up --refresh
```

Feed inspection, status, and refresh commands can access the network.
`--list-feeds` and `--test-scope` do not fetch feeds.
The 5-second supervisor applies to hook mode, not inspection commands.

### Local decision runtime

Provision the pinned NVIDIA Nemotron 3 Nano 4B GGUF checkpoint, then run the
inference server and collector in separate terminals, or use the managed Nix
services. `llama-server` must be available when not using Nix.

```bash
poetry run hold-up provision
poetry run hold-up serve --runner /absolute/path/to/llama-server
poetry run hold-up collect
```

Provisioning verifies the pinned SHA-256. The inference server listens only on
`127.0.0.1:18473`, with a local API key and prompt logging disabled. There is no
cloud inference fallback. It receives provider reports and sanitized action
metadata, not tool results, transcripts, or file contents. Sanitization removes
known secret forms; arbitrary positional arguments are not a guaranteed secret
boundary. Unknown tools and unsupported shell constructs cannot authorize a pause.

Use `HOLD_UP_STATE_DIR` to select the runtime state directory; otherwise it is
`$XDG_STATE_HOME/hold-up`, defaulting to `~/.local/state/hold-up`. The Nix wrapper
and services share `~/.local/state/hold-up`. Keep the collector configuration
consistent with the hook configuration; a mismatch produces an advisory.

```bash
poetry run hold-up-evaluate --qualification
poetry run hold-up status
poetry run hold-up retry DECISION_ID
poetry run hold-up wait DECISION_ID
```

Qualification runs the separately frozen 48-case `qualification-v1.json` corpus
three times. The exposed 120-case development corpus remains available through
`hold-up-evaluate` without `--qualification`; it cannot grant readiness.
Enforcement requires pause
precision of at least 95%, recall of at least 90%, no protected-local-action
pauses, no invalid outputs, and inference p95 below 5 seconds. The readiness
record is bound to the model checksum, runner binary and launch configuration,
inference settings, normalization and policy source digest, and qualification
corpus hash. Changes invalidate readiness and cached pauses. Evaluation records
the corpus hash before inference; tuning after qualification requires a new
qualification version. These synthetic cases do not establish production
reliability. The current model has not qualified for enforcement.

### AWS evidence contract

The collector and legacy advisories share snapshot contract version `2`. AWS
JSON is decoded from bytes, including BOM-marked UTF-16, with a 1 MiB response
limit. Both event arrays and `current_events` envelopes are supported. The event
ARN remains the incident identity; its canonical region is separate from the
provider's display name. Conflicting region fields leave scope uncertain.

Update logs are validated and sorted by numeric timestamp. Identical duplicates
collapse; conflicting same-time updates remain explicit evidence. Only the latest
update's full message, summary, and timestamp describe current impact. Top-level
text is used only when `event_log` is absent; malformed logs are unavailable
evidence. Raw status codes are preserved without numeric lifecycle mappings.

Acquisition time determines freshness, separately from publication time. An old
incident fetched successfully can remain ongoing. Decision evidence is complete,
subject to the total 16 KiB input budget; overflow produces advice. Display text
may be shortened. Legacy advisories do not keyword-filter AWS events or infer
recovery from historical occurrences of “resolved.” Earlier cache entries cannot
be reused under the versioned contract.

Unavailable decisions use fixed categories including `feed_decode_failed`,
`evidence_incomplete`, `evidence_context_overflow`, `model_output_invalid`, and
`model_unqualified`. Model-invented evidence or provider references are rejected.

`HOLD_UP_MODE` accepts `guard` (default), `advisory`, or `off`; JSON can set
`decision.mode` when the environment does not override it. Invalid or unavailable
model/feed evidence cannot create a new pause. A previously validated pause may
remain until its original lease expires, for at most 300 seconds. Missing
incidents are not treated as proof of recovery. Fresh model-classified recovery
on another pre-tool check replaces the pause.

`retry` grants one attempt for the exact original action, profile, workspace,
client, and session; it does not run the action. `wait` observes release, retry
approval, or lease expiry; it does not independently reclassify recovery.
The retry CLI is an operator control, not a security boundary against a process
running under the same operating-system account.

## Verification

Run the offline engine and adapter tests:

```bash
poetry check --lock --strict
poetry run python -m unittest discover -s tests -p "test_*.py" -v
poetry run ruff check src scripts tests
poetry run ruff format --check src scripts tests
poetry build
```

CI tests Python 3.10–3.13. Adversarial regressions cover scope false positives,
region precedence, malformed feeds and caches, response limits, and blocked
workers. Dotfiles additionally tests hook ownership, idempotency, interrupted
activation, destination conflicts, and profile eligibility through its Nix check.

`tests/native_clients.py` exercises real Codex `0.154.0` and Claude Code
`2.1.282` clients with temporary homes and an installed wheel. `--mode contract`
verifies denial, one-shot retry, renewed denial, and recovery with isolated
synthetic readiness. `--mode real --source live` fetches public AWS evidence and
uses the pinned local model and its actual readiness. `--source capture` replays
the immutable public response separately. Capture metadata records the source
URL, acquisition time, encoding, and checksum.

AWS execution is replaced with a sentinel that accepts only scripted arguments;
credentials and credential-provider environment variables are absent. The
harness checks hook output, execution counts, and the five-second hook deadline.
The affected-region operation is paired with another region, local inspection,
and AWS diagnostics. An unqualified model must permit execution with advice;
passing client mechanics does not qualify it for blocking. A feed without a
suitable scoped incident is unavailable for the live test, not a passing replay.

The [architecture decision](docs/adr/0001-local-outage-decisions.md) records the
evidence and enforcement boundaries.

## License

[MIT](LICENSE).
