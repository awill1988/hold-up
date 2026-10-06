# Immutable runtime verification

This record supersedes the earlier socket implementation's measurements without
removing its [historical results](../2026-10-05-sockets/README.md).

## Data contracts

Configuration, normalized AWS evidence, action scopes, decisions, socket
messages, and statistics use detached `MappingProxyType` mappings and tuples.
Sets use `frozenset`. The implementation uses only standard-library types.
JSON encoding is explicit; authentication no longer removes fields from a
received message. Runtime snapshots are replaced rather than edited in place.

104 unit tests pass, including nested mutation rejection, input-alias isolation,
JSON serialization, and non-mutating message authentication. Poetry lock checks,
Ruff, wheel/source builds, and isolated installation pass. Native contract tests
pass for Claude Code `2.1.282`, Codex `0.154.0`, and Antigravity CLI `1.2.2`.
Antigravity's separate neutral-permission test prevents execution as expected.

Windows CI exposed duplicate decision IDs when clock resolution produced the
same timestamp for concurrent decisions. IDs now use 128 bits of randomness.
A fixed-time regression verifies distinct persisted decisions, and concurrent
retry consumption again exercises actual sockets. A separate regression verifies
advisory output for an unavailable socket. Production deadlines were not relaxed.
Windows performance under load is not qualified by these correctness tests.

## Final qualification v7

The Windows decision-ID fix changes policy identity. Version 7 freezes the same
56-case corpus against policy
`693240f7a439e013942467cbeef125216860f4576971fc91fc97387acbf9bce3`.
It failed with 57 timeouts in 168 attempts, zero pause recall, zero protected
pauses, and 4.008-second attempt p95. Blocking remains disabled. The full report,
start record, runner metadata, and repeated native checks are under [`final/`](final/).

The source fix passes [all eight CI jobs](https://github.com/awill1988/hold-up/actions/runs/37411823733),
including Windows, macOS, and Linux socket/immutability/demo checks and Python
3.10–3.13 unit tests. Native agent programs were exercised on macOS only.

Final captured and live AWS tests each emitted one advisory and permitted four
sentinel operations per program. Contract tests again verified two denials, one
retry, recovery, and exactly two executions. Real-model blocking verification
remains unsuccessful.

## Historical qualification v6

The same 56-case corpus was frozen against the changed policy before three
repetitions. The run failed with 56 timeouts in 168 attempts, zero pause recall,
zero protected-action pauses, and 4.010-second attempt p95. The other 112 cases
returned accepted non-pausing decisions. Blocking remains disabled.

- Corpus: `768c97f1c3a4a025592ededdab7771c540333f58fd514eae59fa416fdc53fad4`.
- Policy: `21ab4e1236090257c929ce47ca909082c0e5bed256d7f01418b080aa7c9e0bb2`.
- Model and runner fingerprint remain unchanged from the prior run.

The full report and start record are retained. Captured and live AWS native
results remain separate; passing advisory behavior does not establish blocking
readiness. No synthetic readiness is written for real-model runs.

## Latency

The final policy's 600 complete hook-process samples are in `final/`. They use
prepared fixture decisions, with the temporary inference runner stopped:

| Program | Sequential p95 | Four-way p95 | Socket failures |
| --- | ---: | ---: | ---: |
| Claude Code | 56.09 ms | 72.22 ms | 0 |
| Codex | 56.90 ms | 68.14 ms | 0 |
| Antigravity CLI | 57.38 ms | 67.76 ms | 0 |

### Earlier measurements

`latency-mixed-load.json` preserves a run concurrent with native-client and
media verification: Claude p95 was 120.84 ms, Codex 69.44 ms, and Antigravity
68.97 ms, with no socket failures. This run missed the 100 ms target.
The four-way process benchmark in `latency-concurrent.json` measured p95 of
94.63 ms, 89.21 ms, and 86.67 ms respectively, with no socket failures.
The earlier native Codex cold-start outlier also remains documented. A universal
sub-100-ms claim is not supported.

After the other verification workloads and temporary inference runner stopped,
`latency-isolated.json` recorded another 100 complete processes per program:

| Program | Isolated p95 | Four-way p95 | Socket failures |
| --- | ---: | ---: | ---: |
| Claude Code | 79.23 ms | 94.63 ms | 0 |
| Codex | 81.75 ms | 89.21 ms | 0 |
| Antigravity CLI | 84.27 ms | 86.67 ms | 0 |

Individual isolated samples still reached 119–127 ms. The p95 target is a
measured distribution, not a per-invocation guarantee. Instrumented `stats`
latency excludes startup and must not be substituted for these process timings.

## Demonstrations

The [GIF/MP4 demos](../../docs/demos/README.md) execute real hooks and sockets
with fixture decisions and a local AWS sentinel. Both scenarios were exercised
for all three adapters. Cast playback timing is edited; it is not a benchmark.
The GIFs and H.264 MP4s were decoded and visually inspected. Each is below
50 KiB; MP4s use `yuv420p` and `faststart` for browser playback.
