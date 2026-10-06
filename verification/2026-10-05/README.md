# AWS evidence and outage qualification

## Outcomes

| Boundary | Result |
| --- | --- |
| Ingestion | Shared normalization passes encoding, update ordering, conflict, scope, size, and preservation regressions. |
| Client contracts | Codex `0.154.0` and Claude Code `2.1.282` each deny, permit one retry, deny again, and permit recovery; two sentinel executions per client. |
| Model qualification | Failed. Enforcement remains disabled. |
| Real-model clients | Captured and independently fetched live evidence produce advisory behavior; four sentinel executions per run. Blocking verification is unsuccessful. |

## Qualification

The frozen [v2 corpus](../../src/holdup/data/qualification-v2.json) contains 48
AWS cases evaluated three times. It normalizes raw event logs, including older
updates, through the production parser. Acquisition time is assigned at each
inference; publication and update timestamps remain independent.

The [start record](evaluation-start.json) was written before inference. Its
corpus SHA-256 is
`178bc57dd7b6f165da3bc07125d790892777cabcf8070fad233835ab61191f00`.
The policy and corpus remained unchanged throughout evaluation.

| Gate | Required | Observed |
| --- | --- | --- |
| Repetitions | At least 3 | 3, totaling 144 attempts |
| Pause precision | At least 95% | No pause predictions; evaluator records 0 |
| Pause recall | At least 90% | 0% |
| Protected-action pauses | 0 | 0 |
| Invalid outputs | 0 | 119 inference timeouts |
| Inference p95 | Below 5 seconds | Attempt p95 4.012 seconds, including timeouts |

Timeouts are invalid outcomes, not successful inference measurements. Of 25
completed responses, one missed an expected pause; the other 24 were correct
non-pause classifications. [Raw outcomes](qualification-v2.json) retain expected
decisions, raw completed responses, finish reasons, validation categories, and
per-case latency. [Readiness](readiness.json) records `passed: false`.

## Diagnosis

- **Ingestion:** The public AWS response is BOM-marked UTF-16. The former UTF-8
  decode path failed, while the decision path omitted update logs and clipped
  narrative evidence. Both consumers now share the versioned normalizer.
- **Fixture labels:** The exposed AWS MCP upload cases lacked regions despite
  regional outage reports. Their expected pause labels were corrected. The
  [v1 diagnostic run](qualification-v1-invalid-fixture.json) used zero acquisition
  timestamps and is invalid as fresh-evidence qualification. V2 corrects that
  fixture defect without changing thresholds or inference settings. See the
  [label audit](fixture-label-audit.json).
- **Inference configuration:** The pinned NVIDIA checksum and local runner are
  retained. The [runtime manifest](runtime.json) and [runner properties](runner-props.json)
  record the executable, launch configuration, and embedded chat template.
  The [applied-template probe](template-diagnosis.json) ends in
  `<think></think>`, confirming disabled thinking. Requests use temperature `0`,
  structured JSON output, and a `512`-token limit. Non-`stop` finish reasons are
  rejected. Complete normalized evidence frequently exceeds the existing
  four-second request budget on this runner.
- **References and classification:** The [original baseline](baseline-evaluation.json)
  is preserved unchanged, including its generic `ValueError` records. It did
  not retain raw response text or detailed validation causes; these cannot be
  reconstructed exactly. The [development diagnostic](development-diagnosis.json)
  records classification errors independently of the qualification gate.
  Invented references remain invalid and are never repaired into valid decisions.

[RSS observations](runner-memory-samples.json) reached approximately `6.78 GiB`.
These are sampled resident-memory observations, not a measurement of lifetime
peak or total CPU/GPU allocation. The [pre-evaluation sample](runner-memory.txt)
is retained separately.

## Native clients

Both modes use temporary homes, the installed Poetry-built wheel, and the
existing loopback client backend. Only real-model mode calls the pinned outage
model. It copies actual runtime readiness and never manufactures a passing
record. Credential-provider environment is absent. AWS and local-inspection
sentinels accept only scripted arguments and never delegate to an installed AWS
CLI. Deterministic readiness remains confined to each contract-test directory.

| Client | Evidence | Sentinel executions | Complete-hook p95 | Blocking verified |
| --- | --- | --- | --- | --- |
| Codex | Captured public response | 4 | 4.557 s | No |
| Claude Code | Captured public response | 4 | 4.120 s | No |
| Codex | Separately fetched live response | 4 | 4.122 s | No |
| Claude Code | Separately fetched live response | 4 | 4.118 s | No |

Each run pairs an EC2 launch in the incident ARN's region with an operation in
an unreported region, local inspection, and EC2 diagnostics. The affected action
received `model_output_invalid` advice and executed its sentinel. The remaining
actions were permitted. All complete hook invocations stayed within five seconds.

Client records contain actual hook output and counts:
[Codex contract](codex-contract-capture.json),
[Claude contract](claude-contract-capture.json),
[Codex capture](codex-real-capture.json),
[Claude capture](claude-real-capture.json),
[Codex live](codex-real-live.json), and
[Claude live](claude-real-live.json).

The immutable [public fixture](../../tests/fixtures/aws-public-2026-10-05.bin)
has [capture metadata](../../tests/fixtures/aws-public-2026-10-05.metadata.json).
Live fetches have separate [Codex metadata](codex-live-acquisition.json) and
[Claude metadata](claude-live-acquisition.json), including URL, acquisition time,
encoding, and checksum. A matching checksum does not turn these independent
network acquisitions into replay tests.

## Build verification

Poetry lock validation, 83 unit tests, Ruff lint/format checks, wheel/source
builds, isolated wheel installation, native clients, current-platform Nix checks,
and the `macbook-personal` Darwin build passed against the local source. Final
delivery also verifies CI and repeats Nix/Darwin checks using the published
remote pin. Builds do not activate services or change persistent hook trust.
