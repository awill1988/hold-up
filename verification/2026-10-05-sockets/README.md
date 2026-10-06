# Socket runtime verification

Date: 2026-10-05. Host: macOS arm64. Package: installed Poetry wheel.

## Evidence and qualification

AWS ingestion regressions pass independently of model qualification. Public
AWS response captures include URL, encoding, acquisition time, and SHA-256.
Files labelled `capture` replay the immutable fixture; `live` files record a
separate network acquisition. AWS execution always uses a scripted sentinel.

The pinned NVIDIA checkpoint and llama.cpp runner are unchanged. Qualification
v3 failed with 52 timeouts in 156 attempts. Version 4 added dry-run, local
skeleton generation, custom endpoints, and `MULTIPLE_SERVICES` evidence cases;
it failed with 57 timeouts in 168 attempts and zero pause recall.

Version 5 freezes the same 56-case corpus against the final runtime policy,
including separate deadlines for hooks and explicit statistics inspection.
Its corpus SHA-256 is
`768c97f1c3a4a025592ededdab7771c540333f58fd514eae59fa416fdc53fad4`.
Start records precede evaluation. Reports retain expected decisions, failure
categories, available raw response traces, and individual elapsed times.
Timeouts have no received response to archive. No passing readiness was created
for real-model tests.

Version 5 failed with 56 timeouts in 168 attempts, zero pause recall, zero
protected-action pauses, and 4.010-second attempt p95. The 112 remaining cases
returned accepted non-pausing decisions; that does not compensate for failed
affected-operation decisions. Blocking remains disabled. Its policy digest is
`1345aadfe5c532880d8216755f6e8b5a60ab8ed5007016e25dca5c30c4d6dd89`.

`runner-props.json` records the applied template and runner configuration.
`runner-memory.txt` is a sampled resident-memory observation, not a peak:
3,334,496 KiB, approximately 3.18 GiB. The inference runner remains a background
dependency; socket hooks do not load its libraries or invoke inference.

## Native client mechanics

| Program | Version | Contract checks | Sentinel executions | Denials | Retries |
| --- | --- | ---: | ---: | ---: | ---: |
| Codex | `0.154.0` | 4 | 2 | 2 | 1 |
| Claude Code | `2.1.282` | 4 | 2 | 2 | 1 |
| Antigravity CLI | `1.2.2` | 4 | 2 | 2 | 1 |

Contract tests verify denial, exact-action retry, renewed denial, and recovery
using isolated in-memory fixture readiness. Antigravity additionally preserves
native permission denial with neutral hook output: one hook, zero executions.

Each real-model run pairs an affected-region EC2 operation with an unaffected
region, local inspection, and AWS diagnostics. Captured and live tests are
reported separately. An unqualified model must emit an advisory and permit
all four scripted operations. Real-model blocking verification is unsuccessful.

Per-program statistics accompany every native result. Codex completion payloads
in this fixture contain stdout without exit status, so outcomes are recorded as
unknown. Claude and Antigravity completion events are observed. Advisory counts
do not establish successful rerouting or saved time.

## Latency and boundaries

`latency-sequential.json` and `latency-concurrent.json` retain all 600 complete
hook-process samples, including Python startup. Each program has 100 sequential
and 100 four-way-concurrent samples. These benchmarks use prepared fixture
decisions and do not qualify the model. Native client results are separate;
a Codex cold hook took 419 ms, so a universal sub-100-ms native-client
claim is not supported.

| Program | Sequential p95 | Four-way p95 | Socket failures |
| --- | ---: | ---: | ---: |
| Claude Code | 70.56 ms | 82.57 ms | 0 |
| Codex | 69.74 ms | 82.81 ms | 0 |
| Antigravity CLI | 68.58 ms | 85.77 ms | 0 |

The 75 ms socket deadline applies to hook exchanges. Explicit `stats` and
`status` use a two-second inspection deadline; a populated 100,000-event
statistics request completed in 103 ms. Stalled stdin exercised the five-second
watchdog; complete process exit was observed at 5.061 seconds including startup.
The collector and its disposable preparation subprocess were also exercised
with an isolated empty feed configuration.

## Build and platform checks

Poetry lock validation, 99 unit tests, Ruff, wheel/source builds, and isolated
wheel installation pass locally. Nix flake checks and the Darwin build pass
with the local source override; remote-pin checks are repeated after publication.
CI exercises socket contracts on Windows, macOS, and Linux and the unit suite
on Python 3.10–3.13. Native-client execution was tested on macOS only; the current
native sentinel harness requires POSIX. No services were activated and no
persistent hook trust was changed.
