# Security policy

Aperion Compass is a governance and audit tool, so it is held to a high
bar. This file covers three things: which releases get fixes, how to
report a vulnerability, and the threat model — including the trust
boundaries that come from Compass being deliberately offline.

---

## Supported versions

We fix security issues on the latest `compass-v*` release. During the
`0.x` series there is a single supported line (the newest minor).

| Version | Supported |
|---------|-----------|
| latest 0.x | ✅ |
| older 0.x | ❌ (upgrade) |

## Reporting a vulnerability

Please email **security@aperion.ai** with a description, affected
version, and reproduction steps. Do not open a public issue for an
unpatched vulnerability. We aim to acknowledge within 3 business days
and to ship a fix or mitigation for confirmed issues promptly.

## Threat model

**What Compass is.** A local, single-user command-line tool. It reads a
questionnaire answers file and evidence files you point it at
(exported logs, an audit chain, approval tickets, agent credentials, a
JWKS), computes a conformance score, and writes an HTML/Markdown/JSON
report. The `serve` subcommand renders that same report over
`127.0.0.1`.

**What Compass is not.** It is not a runtime enforcement layer, it does
not sit in your request path, and it makes **no network calls** — no
telemetry, no phone-home, no license check. Everything runs on your
machine against your files.

Trust boundaries and design choices that follow from that:

1. **Inputs are untrusted data, not code.** Every evidence file is
   parsed as JSON/YAML with `serde`; Compass never executes anything it
   reads. Field access is forgiving (unknown fields ignored), and a
   malformed file yields a check marked `not_run`, not a crash.
2. **Cryptographic verification is real, and offline.** Audit-chain
   integrity is checked with HMAC-SHA256 over canonical JSON plus
   `prev_hash` linkage; agent credentials are verified with Ed25519
   against a public key / JWKS you supply. Compass holds no secrets: it
   verifies signatures, it never issues them. A supplied HMAC key or
   JWKS is used only in-process and never persisted or transmitted.
3. **`serve` binds to localhost only.** It is a convenience viewer for a
   single user on one machine, not a multi-tenant server. It has no
   authentication because it is not intended to be exposed; do not bind
   it to a public interface or put it behind a reverse proxy. It serves
   only the dashboard and a read-only `/api/scorecard`.
4. **Reports may contain sensitive detail.** Evidence notes and check
   details you include can carry internal information. Generated
   reports are yours to store and share deliberately — treat
   `compass-report.*` like any other internal document.
5. **Lean dependency tree.** Compass avoids an async runtime, HTTP
   client, and database drivers on purpose to keep the audited surface
   small. `cargo audit` runs in CI.

## Scope note

A finding in how Compass *scores* a posture (e.g. a control mapped to
the wrong verdict) is a correctness bug — report it as a normal issue.
A finding that lets a crafted input execute code, exfiltrate data, or
cause Compass to make a network call is a security vulnerability —
report it privately per above.
