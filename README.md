# aperion-compass — local, offline AI governance self-assessment

[![License: Proprietary](https://img.shields.io/badge/License-Proprietary-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-1.75%2B-orange.svg)](https://www.rust-lang.org/)
[![Docker](https://img.shields.io/badge/docker-ghcr.io%2Faperionai%2Fcompass-2496ed.svg)](https://github.com/AperionAI/compass/pkgs/container/compass)
[![Security policy](https://img.shields.io/badge/security-SECURITY.md-red.svg)](SECURITY.md)

**Frameworks bundled:**
![EU AI Act](https://img.shields.io/badge/EU%20AI%20Act-supported-success)
![IMDA Agentic](https://img.shields.io/badge/IMDA%20Agentic%20AI-supported-success)

> ### ⭐ Star this repo if "we have AI governance" should mean more than a slide
>
> `aperion-compass` turns a governance framework into a **runnable check**: answer a guided questionnaire, point it at your exported logs, and get a scored conformance report — verifying your audit chain and agent credentials with real cryptography, not a checkbox. It runs entirely on your machine. No account, no telemetry, no upload.
>
> If "prove it, don't claim it" is how you think about compliance, a ⭐ is the fastest way to help other engineers in regulated shops find it → **[Star aperion-compass on GitHub](https://github.com/AperionAI/compass)**

![aperion-compass verifies an audit chain and scores a governance posture against the EU AI Act and IMDA agentic framework — local, offline, with a CI exit code](docs/img/compass-demo.gif)

`aperion-compass` is a single, offline Rust binary that runs a
governance **self-assessment** against the **EU AI Act** and Singapore's
**IMDA Model AI Governance Framework for Agentic AI**. You answer a
plain-language questionnaire (or hand-edit / commit an answers file),
and — this is the part that makes it more than a survey — you point it
at files you already have:

- **Audit-chain integrity** — verifies a tamper-evident HMAC-SHA256
  hash chain (`seq` / `prev_hash` / `entry_hmac`) with only the key.
- **Human oversight** — computes override rate, approval latency, and
  outlier reviewers from exported approval tickets (rubber-stamping and
  automation-bias signals).
- **Action-risk coverage** — deterministically tiers your tool calls
  T1/T2/T3 and reports how many irreversible actions had an approval.
- **Agent identity** — verifies Ed25519 agent credentials offline
  against a public key / JWKS (no shared secret, no running gateway).
- **Logging completeness** — field-presence stats over your request
  logs (identity, risk tier, decisions, perimeter).
- **Signed attestation** — seal the scored posture, evidence-check
  outcomes, and an anchor of the audit-chain tail into one Ed25519-signed
  bundle that an auditor or customer can verify **offline**, without
  trusting you or touching your gateway.

Objective evidence **overrides** a green self-attestation: claim an
Article 12 tamper-evident log, hand Compass a chain that fails
verification, and that control turns red — with a non-zero CI exit
code. Every gap carries remediation guidance (a generic pattern first;
Smartflow noted as one implementation).

It emits a self-contained **HTML dashboard** (opens from `file://`,
attach it to a board deck), plus **Markdown** and **JSON**. A `serve`
mode runs the same dashboard on `localhost` with a re-scan button.

---

## Quickstart

```bash
# 1. Answer the questionnaire (writes compass-assessment.yaml)
compass assess --framework eu-ai-act,imda

# 2. Attach evidence you already export (all optional)
compass ingest \
  --vas         logs.jsonl \
  --chain       audit-chain.jsonl --chain-hmac-key file:hmac.key \
  --approvals   approvals.jsonl \
  --credentials agents.jsonl --jwks issuer-jwks.json

# 3. Score it and render the report
compass report --out report.html --format html,md,json

# ...or explore live in the browser
compass serve --port 8787

# 4. Seal the result into a signed, offline-verifiable attestation
compass attest generate --out compass-attestation.json
compass attest verify   --bundle compass-attestation.json   # anyone, offline
```

No evidence files? A questionnaire-only run still produces a full
report — those controls are simply marked "self-attested".

### Signed attestation bundles

A report is something you produce; an **attestation** is something an
auditor or customer can *verify without trusting you*. `compass attest
generate` assembles the scored posture, every evidence-check outcome, and a
cryptographic anchor of your audit-chain tail into one JSON payload and
Ed25519-signs it. `compass attest verify` recomputes the canonical payload
and checks the signature **offline** against a published public key / JWKS —
so any tampering (a nudged score, a removed integrity failure, a swapped
framework) breaks verification with a non-zero exit code.

The signing key defaults to a stable per-user key at
`~/.aperion-compass/attest-ed25519.key` (created on first run), or pass your
own with `--signing-key file:…|base64:…|hex:…|env:…` — e.g. reuse the same
Ed25519 issuer key you already publish for AIDA agent credentials.
`generate` also writes the public key as `<out>.jwks.json` so a verifier
needs nothing but the bundle and that key. It reuses the exact Ed25519/JWKS
primitive Compass already uses to verify agent credentials.

### Don't have governance-grade logs? (most people don't)

That's the normal starting point, and it's the whole reason the tool
exists. Two ways to get real evidence:

```bash
# Convert something you already have (provider export → evidence)
compass ingest --from openai        --input openai-export.json
compass ingest --from azure-openai --input azure-export.json
compass ingest --from langsmith     --input langsmith-runs.jsonl
compass ingest --from anthropic     --input anthropic-messages.jsonl
compass ingest --from vertex        --input vertex-logs.jsonl
compass ingest --from bedrock        --input bedrock-invocations.jsonl
compass ingest --from csv-approvals --input approvals.csv   # Jira/ServiceNow export
compass ingest --doc risk-register.pdf --for art_9_risk_system,art_11_annex_iv
compass ingest --mcp-allowlist mcp-servers.json

# Or capture it from live traffic: run this in front of your model
# endpoint (http or https), point your SDK's base_url at it.
compass record --upstream https://api.openai.com --out compass-record.jsonl
# Optional: --redact bodies   --upstream-ca corp-root.pem

# Then see exactly what's still missing and how to fix each gap
compass doctor
```

Step-by-step guides for pulling logs from OpenAI, Azure OpenAI,
LiteLLM, Bedrock, and LangSmith — plus the minimal field spec if you
want to roll your own — live in [docs/evidence/](docs/evidence/).

### Try it on the bundled demo

```bash
cargo run --example gen_fixtures         # writes ./demo/*
compass report --assessment demo/compass-assessment.yaml --out report.html
compass verify --chain demo/chain.jsonl --chain-hmac-key file:demo/chain.key
```

## Install

```bash
# Homebrew (macOS / Linux)
brew install AperionAI/tap/aperion-compass

# GitHub release (any OS)
# https://github.com/AperionAI/compass/releases — unpack `compass` onto your PATH

# Docker
docker run --rm -v "$PWD:/work" -w /work \
  ghcr.io/aperionai/compass:latest report --out report.html

# From source
git clone https://github.com/AperionAI/compass && cd compass
cargo build --release      # ./target/release/compass
```

The crate is not published on crates.io. Build from this repo if you
want to compile it yourself.

## Commands

| Command | What it does |
|---|---|
| `compass assess` | Interactive questionnaire → `compass-assessment.yaml` (add `--defaults` to scaffold an editable file). |
| `compass ingest` | Register evidence files; `--from openai\|litellm\|bedrock\|azure-openai\|langsmith\|anthropic\|vertex\|csv\|csv-approvals`; `--doc <file> --for <control>`; `--mcp-allowlist`. |
| `compass doctor` | Show which automated checks have evidence and, for every gap, the exact step to close it. Flags stale files (default 90 days). `--json` for CI. |
| `compass record` | Localhost recording proxy (`http://` or `https://` upstreams; SSE pass-through). `--redact bodies`, `--upstream-ca <pem>`. |
| `compass report` | Score answers + evidence; write HTML / Markdown / JSON / JUnit / SARIF. `--baseline` is a ratchet (fail only on a drop). `--update-baseline` writes the file when the score improves. |
| `compass diff` | Compare two scored JSON reports (Markdown for a PR comment, or JSON). |
| `compass explain` | Why one control is the colour it is: question, verdict, applied checks, files, remediation. |
| `compass serve` | Live localhost dashboard with a re-scan button. |
| `compass verify` | Standalone tamper-evident audit-chain verification. |
| `compass attest` | `generate` a signed attestation bundle; `verify` one offline. |
| `compass frameworks` | List the bundled frameworks and control counts. |

## Assessment as code

`compass-assessment.yaml` is designed to be committed. It is editable,
diffable, and re-runnable, so a governance posture can be reviewed in a
pull request and enforced in CI:

```yaml
# .github/workflows/governance.yml
name: compass
on:
  pull_request:
  push:
    branches: [main]
permissions:
  contents: read
  pull-requests: write
  security-events: write
jobs:
  score:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: AperionAI/compass@compass-v0.6.0
        with:
          assessment: compass-assessment.yaml
          baseline: compass-baseline.json
```

Or call the binary yourself:

```yaml
- run: compass report --out report --format html,junit,sarif,json --baseline compass-baseline.json
  # with --baseline: exit 0 = hold/improve · 1 = dropped · 2 = evidence integrity failure
  # without --baseline: --threshold (default 70) is the gate
- run: compass diff compass-baseline.json report.json --format md
```

CI exit codes:

- **0** — score at or above `--threshold` (default 70), or — when
  `--baseline` is set — at or above the committed baseline.
- **1** — below threshold, or dropped below the baseline.
- **2** — an evidence-integrity check failed (tampered audit chain or an
  invalid agent credential). This takes precedence over the threshold
  and the baseline.

## Free tool vs. Smartflow

Compass is a **point-in-time** assessment from files. Smartflow is the
**continuous, runtime enforcement** the reports point toward. Same
concepts, same evidence formats — one measures, the other enforces.

| | **aperion-compass** (this) | **Smartflow** |
|---|---|---|
| Cost | Free to run | Commercial |
| Runs | Locally, offline, from files | In your request path (gateway) |
| Mode | Point-in-time snapshot | Continuous, live |
| Identity | Verifies exported credentials | Issues + validates on the hot path |
| Audit | Verifies an exported chain | Produces the tamper-evident chain |
| Oversight | Scores exported tickets | Runs the approval queue |
| Action risk | Tiers logged calls | Blocks/holds T3 actions before they run |
| Reports | HTML / MD / JSON / JUnit / SARIF | Live console + regulator API |
| Data | Never leaves your machine | On-prem / in your cluster |

Remediation text in reports links to the governance patterns at
[docs.aperion.ai](https://docs.aperion.ai).

## Honest limitations

- **It assesses; it does not enforce.** A passing Compass report says
  your *evidence and answers* look good at a point in time. It cannot
  stop a bad action — that is a runtime concern.
- **Verification is only as good as the export.** Compass verifies the
  files you give it. It cannot know your export is complete, that the
  HMAC key is the real one, or that a log wasn't filtered before export.
- **HMAC credentials aren't offline-verifiable.** Only Ed25519 (public
  key) credentials can be checked without a secret; HMAC ones are
  reported as "unverifiable", not "valid".
- **`compass record` talks to the upstream you name.** http and https both
  work. HTTPS uses rustls with Mozilla's webpki roots (corporate TLS
  intercept that isn't in that set will fail). Streaming responses are
  passed through as they arrive.
- **Not legal advice.** This is a preparation aid, not a conformity
  assessment, and not a substitute for a notified body, counsel, or
  your regulator. The control catalogs are our reading of the
  frameworks; verdicts are conservative but opinionated.
- **v1 scope.** EU AI Act + IMDA agentic today. NIST AI RMF is a
  later catalog. Documents attach by path + SHA-256; Compass does not
  parse PDFs. PDF export is print-to-PDF from the HTML.

## Development

```bash
cargo test                        # unit + integration tests
cargo run --example gen_fixtures  # regenerate ./demo/*
cargo clippy --all-targets
```

Layout: `catalogs/` (bundled framework YAML), `src/evidence/` (the
offline checks), `src/scoring.rs` (verdicts + rollups),
`src/report/` (renderers), `templates/dashboard.html` (the embedded
dashboard).

## License

Free to run. Source is inspectable in this repo. Compiled binaries and
images are under the Binary License Agreement — this is not an
open-source license. See [LICENSE](LICENSE).
