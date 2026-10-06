# 0001. Separate local outage decisions from action execution

Date: 2026-10-05

## Status

Accepted. Model enforcement qualification is a separate evaluation gate and has
not passed; accepting this architecture does not enable blocking.

## Context

An outage advisory tells an operator about an incident. An action guard decides
whether that incident should prevent a particular pending operation. Provider
names alone do not establish that dependency: service, region, operation, and
recovery state matter. Providers may publish incomplete or delayed reports.

Static matching offers deterministic behavior but requires service-specific
policy maintenance. Remote inference offers broader models but depends on
external availability and transmits action context. Local inference retains
context on the machine but introduces memory costs and measurable classification
errors. A classifier must not acquire authority merely because it returns JSON.

## Decision

Package the shared Python engine as a Poetry project with a `src/holdup` layout.
Both client adapters call the same decision boundary. A background collector
acquires public provider reports; a pinned NVIDIA checkpoint served through
local `llama.cpp` classifies sanitized pending-action metadata. The adapter owns
native client denial; neither the model nor the operator controls execute tools.

Use `allow`, `advise`, and `pause` decisions. Validate output structure and
evidence references before accepting a result. Require a passing model/policy
evaluation before a pause can deny an operation. Persist bounded pause leases
and atomically consumed, action-bound retries in local SQLite state.

## Invariants & Abstention

- Provider reports are the only outage evidence. Tool results, transcripts, and
  repository contents are not evidence inputs. Unreported outages remain unknown.
- Unsupported or unknown action scope cannot authorize a pause. Local edits and
  recognized local inspection commands remain available.
- A new pause requires fresh evidence and a qualified model/policy. Missing,
  malformed, stale, oversized, or unavailable evidence yields advice instead.
- Existing qualified pauses may survive a refresh failure only until their
  original expiry; a failure cannot renew the lease.
- Incident disappearance does not prove recovery. Another pre-tool check can
  release a pause on fresh recovery evidence; passive `wait` does not classify it.
- Retry approval is scoped to profile, workspace, client, session, and exact
action arguments. Original arguments are hashed, not persisted.
- Provisioning is explicit and checksum-verified. Hooks never download weights,
  activate services, change hook trust, or fall back to cloud inference.

## Consequences

### Positive

Client-specific hook mechanics remain separate from shared policy. The package
has reproducible dependency resolution and an installable wheel. Failed model
qualification leaves useful advisory behavior without granting denial authority.

### Negative & Operational Costs

The runtime requires model storage, memory, collection, and explicit evaluation.
The synthetic regression suite is not a production accuracy guarantee. A single
collector snapshot currently requires a matching configuration; other project
configurations degrade until collected explicitly. Long feed histories can
exceed the bounded context budget and force abstention. Secret-pattern removal
does not prove arbitrary command arguments contain no sensitive data.

Controls and state files are not a hostile same-user security boundary. Runtime
activation, marketplace publication, source-pin updates, and client hook trust
remain separate deployment actions.
