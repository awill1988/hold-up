# Repository instructions

See [README.md](README.md) for setup and verification.

## Runtime and platform boundaries

- Use Python standard-library loopback TCP sockets for hook communication on
  Windows, macOS, and Linux. Do not introduce HTTP frameworks, containers,
  dashboards, or external telemetry infrastructure for this path.
- Keep network acquisition, model inference, binary hashing, and telemetry
  persistence outside synchronous hooks. Hooks must have bounded socket waits.
- Preserve native client permissions. An outage check never grants execution
  permission. Unknown scope and unqualified models cannot create a denial.
- Do not activate services, change persistent hook trust, or replace the pinned
  model as part of implementation or verification.

## XDG directories

- Honor `XDG_CONFIG_HOME`, `XDG_STATE_HOME`, `XDG_CACHE_HOME`, and
  `XDG_RUNTIME_DIR` when supplied as absolute paths on every platform.
- On Unix, default config/state/cache to `~/.config`, `~/.local/state`, and
  `~/.cache`. Use a private runtime directory when available; otherwise place
  endpoint discovery metadata in the private state directory.
- On Windows, use `%LOCALAPPDATA%/hold-up` with separate `config`, `state`,
  `cache`, and `runtime` subdirectories when XDG variables are absent.
- Keep runtime secrets and endpoint metadata private to the current OS user,
  including Windows ACLs. Never store them in the repository or logs.
- Keep `HOLD_UP_STATE_DIR` as the explicit isolation override for tests and
  existing deployments; isolate its runtime metadata inside that directory.
- Telemetry is local, bounded, and content-free. Never persist command arguments,
  prompts, transcripts, tool output, credentials, or resource identifiers.

## Python data contracts

- Use immutable standard-library data structures: `tuple`, `frozenset`, and
  detached, recursively frozen `types.MappingProxyType` mappings. Do not add
  third-party collection libraries or custom mutable record types.
- Configuration, normalized evidence, routes, model decisions, socket messages,
  and statistics must be immutable when crossing module or thread boundaries.
- Build replacements instead of editing shared records in place. Freeze owned
  copies so mutations to an input cannot change an already published snapshot.
- Confine mutable JSON objects to decoding, validation, and encoding boundaries.
  Local construction buffers, bounded queues, synchronized owner registries,
  diagnostic collectors, and transactional database state may mutate internally;
  they must not expose mutable records to consumers.

## Verification and publication

- Test Windows, macOS, and Linux socket behavior. Report native-client coverage
  separately from portable unit coverage and model qualification.
- Run Poetry lock checks, tests, Ruff, packaging, and isolated installation.
- Use the configured personal Git identity and conventional commit messages.
  Never include attribution footers.
- Verify `feat/hold-up` before plain `git push`. Stop on a refusal. Do not push
  `main`, `master`, or dotfiles changes without explicit authorization.
