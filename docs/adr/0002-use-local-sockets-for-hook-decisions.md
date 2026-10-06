# 0002. Use local sockets for hook decisions

## Status

Accepted. Supersedes the synchronous inference path in ADR 0001. Model
qualification remains a separate prerequisite for blocking.

## Context

A hook runs before a pending tool call. Its delay is paid by every affected
agent. The pinned local model failed qualification and repeatedly consumed its
inference timeout; moving inference transport into a library would leave that
computation on the critical path. Windows support also rules out relying on
Unix-domain sockets alone.

## Decision

The existing collector owns a lightweight loopback TCP socket and decision
state. A separate disposable process fetches evidence and prepares decisions
for a finite catalogue of AWS operations. Hooks normalize an action and match
the prepared decision through the socket. No HTTP service or external telemetry
collector is introduced. The existing local inference runner remains a separate
background dependency.

Requests and responses use bounded, versioned JSON frames authenticated with
HMAC and a response nonce. A per-start secret lives in a private XDG runtime
directory. Windows honors absolute XDG overrides and otherwise uses
`%LOCALAPPDATA%/hold-up`. User-only ACLs protect Windows state and runtime files.

Program-specific adapters preserve Claude, Codex, and Antigravity permission
semantics. Statistics distinguish issued hook decisions from observed execution;
neither an advisory nor a subsequent action proves that routing succeeded.

## Invariants and abstention

- A passing outage check never approves a native permission request.
- Hooks never fetch evidence, invoke a model, or start runtime processes.
- Unknown operations, ambiguous commands, stale evidence, mismatched generations,
  unavailable sockets, and unqualified interpretations cannot create denials.
- Only the background process mutates retry decisions. An override is consumed
  once for the exact action, program, workspace, and session namespace.
- Model changes and policy changes invalidate readiness. Tests cannot manufacture
  readiness for real-model verification.
- Telemetry cannot change a decision. Its bounded queue may drop events, which
  are reported as loss rather than inferred successful execution.
- Telemetry contains no raw commands, transcripts, tool responses, credentials,
  paths, or cloud resource identifiers.

## Consequences

Hooks can respond independently of inference latency. One standard-library
transport works on all three operating systems, with native permission adapters
at the boundary. The socket owner must be running for outage advice; failure
leaves normal client permission handling in place.

The finite operation catalogue intentionally abstains outside mapped operations.
Provider publication and polling delays limit freshness independently of hook
latency. Process startup contributes to complete hook latency; socket processing
statistics alone cannot demonstrate the end-to-end performance target.

## Sources

- [Claude Academy: hooks](https://academy.claude.com/courses/claude-code-in-action/hooks)
- [Claude native events](https://code.claude.com/docs/en/hooks)
- [Codex native events and coverage](https://learn.chatgpt.com/docs/hooks)
- [Antigravity native events](https://antigravity.google/docs/hooks)
- [MCP sampling](https://academy.claude.com/courses/model-context-protocol-advanced-topics/sampling)
  delegates inference through a client; it does not establish offline execution.

The public Academy lessons informed the design. The certification preparation
portal returned `403` and its restricted materials were not reviewed.
