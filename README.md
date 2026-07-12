# aperion-compass — local, offline AI governance self-assessment

[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
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
```

No evidence files? A questionnaire-only run still produces a full
report — those controls are simply marked "self-attested".

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

# Cargo
cargo install aperion-compass

# Docker
docker run --rm -v "$PWD:/work" -w /work \
  ghcr.io/aperionai/compass:latest report --out report.html

# From source
git clone https://github.com/AperionAI/compass && cd compass
cargo build --release      # ./target/release/compass
```

## Commands

| Command | What it does |
|---|---|
| `compass assess` | Interactive questionnaire → `compass-assessment.yaml` (add `--defaults` to scaffold an editable file). |
| `compass ingest` | Register evidence files into the assessment for automated checks. |
| `compass report` | Score answers + evidence; write HTML / Markdown / JSON. |
| `compass serve` | Live localhost dashboard with a re-scan button. |
| `compass verify` | Standalone tamper-evident audit-chain verification. |
| `compass frameworks` | List the bundled frameworks and control counts. |

## Assessment as code

`compass-assessment.yaml` is designed to be committed. It is editable,
diffable, and re-runnable, so a governance posture can be reviewed in a
pull request and enforced in CI:

```yaml
# .github/workflows/governance.yml (excerpt)
- run: compass report --out report.html --threshold 80
  # exit 0 = at/above threshold · 1 = below · 2 = evidence integrity failure
```

CI exit codes:

- **0** — overall score at or above `--threshold` (default 70).
- **1** — below threshold.
- **2** — an evidence-integrity check failed (tampered audit chain or an
  invalid agent credential). This takes precedence over the threshold.

## Free tool vs. Smartflow

Compass is a **point-in-time** assessment from files. Smartflow is the
**continuous, runtime enforcement** the reports point toward. Same
concepts, same evidence formats — one measures, the other enforces.

| | **aperion-compass** (this) | **Smartflow** |
|---|---|---|
| Cost | Free, open source (Apache-2.0) | Commercial |
| Runs | Locally, offline, from files | In your request path (gateway) |
| Mode | Point-in-time snapshot | Continuous, live |
| Identity | Verifies exported credentials | Issues + validates on the hot path |
| Audit | Verifies an exported chain | Produces the tamper-evident chain |
| Oversight | Scores exported tickets | Runs the approval queue |
| Action risk | Tiers logged calls | Blocks/holds T3 actions before they run |
| Reports | HTML / MD / JSON | Live console + regulator API |
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
- **Not legal advice.** This is a preparation aid, not a conformity
  assessment, and not a substitute for a notified body, counsel, or
  your regulator. The control catalogs are our reading of the
  frameworks; verdicts are conservative but opinionated.
- **v1 scope.** EU AI Act + IMDA agentic today. NIST AI RMF and
  document/PDF ingestion are fast-follows; PDF export is print-to-PDF
  from the HTML.

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

Apache-2.0. See [LICENSE](LICENSE).
