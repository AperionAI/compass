# Roadmap

What's planned for the next two minor releases, and the regulatory
watch items that drive them. Dates and framework facts below were
validated against primary sources in July 2026.

## Where the frameworks stand (validated July 2026)

**EU AI Act — Regulation (EU) 2024/1689, as amended by the Digital
Omnibus on AI.** The Omnibus received final approval from the European
Parliament (16 June 2026) and the Council (29 June 2026); Official
Journal publication is expected in late July 2026, with entry into
force three days later. The load-bearing facts for assessments:

- **Annex III high-risk obligations deferred to 2 December 2027**
  (was 2 August 2026). Annex I (product-embedded) high-risk deferred
  to **2 August 2028**.
- **Article 50 transparency obligations were NOT deferred** — they
  apply from **2 August 2026** (AI interacting with people, synthetic
  content, emotion recognition, biometric categorisation). Art. 50(2)
  machine-readable marking: systems placed on the market before
  2 Aug 2026 get until 2 Dec 2026; new systems must comply immediately.
- **GPAI obligations (Arts. 51–55) are unaffected** and already apply
  (since August 2025).
- Prohibited practices (Art. 5) have applied since February 2025.

Implication: the controls most urgent for a user running Compass in
late 2026 are Art. 5, Art. 50, and GPAI. **v0.4 covers those**, and
marks Annex III high-risk articles (9–15, 17, 26, 72, 73) as
"prepare by 2 Dec 2027" instead of implying they are due today.

**IMDA MGF for Agentic AI.** Catalog seeded from **v1.5
(published 20 May 2026, updated 5 June 2026)** — confirmed still the
current edition. Identity, authorization, oversight effectiveness, MCP
whitelisting, sandboxed execution, tamper-evident logging, and change
management match. **v0.4 adds** systemic/multi-agent risk, memory
poisoning, and the platform-provider vs system-provider split. Still
open: threat-modelling depth beyond `multi_hop_taint`, and
agentic-commerce protocols (ACP, AP2).

**NIST.** AI RMF 1.0 is under revision; the Generative AI Profile
(NIST-AI-600-1) is current. The Cyber AI Profile (IR 8596) is in
preliminary draft. COSAiS SP 800-53 overlays (incl. single- and
multi-agent) are drafts, final no earlier than 2027. NIST's AI Agent
Standards Initiative (Feb 2026) targets an **AI Agent Interoperability
Profile in Q4 2026**. The RMF core (GOVERN / MAP / MEASURE / MANAGE)
is stable enough to catalog now; agent-specific NIST content should
wait for the Q4 2026 profile.

---

## v0.4 — shipped: current-obligation catalog + install funnel

Catalog (the content is the product):

- **[SHIPPED v0.4] EU Art. 50** — disclosure, synthetic-content marking,
  deepfake / emotion-recognition labelling. Binding from 2 Aug 2026.
- **[SHIPPED v0.4] GPAI Arts. 51–55** — provider scope, technical
  documentation, copyright policy, training-content summary, systemic-risk
  extras. Answer N/A if you are not a GPAI provider.
- **[SHIPPED v0.4] `effective_date` on every EU control** — reports badge
  "Binding now" vs "Prepare by 02 Dec 2027". Deferred controls stay in
  the score; the badge is the honesty layer.
- **[SHIPPED v0.4] Incident reporting retargeted to Art. 73.** Control
  id `art_79_incident_reporting` is unchanged so existing assessment files
  keep their answers. Art. 79 stays the related market-surveillance
  procedure in the guidance.
- **[SHIPPED v0.4] IMDA v1.5 delta** — `multi_agent_risk`,
  `memory_poisoning`, `value_chain_role`.

Install:

- Homebrew formula is rendered by `.github/workflows/release.yml` into
  `AperionAI/homebrew-tap` on each `compass-v*` tag (`brew install
  AperionAI/tap/aperion-compass`). The crate is **not** on crates.io;
  README no longer advertises `cargo install`.
- `compass attest` is in the commands table. GitHub about / README
  license one-liner: free to run, inspectable source, binary license.

## v0.5 — HTTPS record, CI output, crosswalk

Still from the earlier plan, next up:

- **`compass record` HTTPS + SSE** — today it forwards to http
  upstreams only. Direct-HTTPS and SSE pass-through so a hosted API
  can be recorded without a local LiteLLM in front.
- **CI-native output** — JUnit XML and SARIF so `compass report`
  annotates PRs; a reference GitHub Action.
- **Framework crosswalk** — map equivalent controls across EU / IMDA /
  NIST so one answered assessment scores against every catalog.
- **NIST AI RMF catalog** (GOVERN / MAP / MEASURE / MANAGE).
- **MCP trust-registry check** — ingest an exported server allowlist.
- **Emergency-stop evidence** — recognise kill-switch events in the chain.
- **Configurable thresholds** in the assessment file.
- **Non-interactive answers** — `compass assess --set control=yes`.
- IMDA leftovers: deeper threat-modelling / taint, agentic-commerce
  protocols (ACP, AP2).

## v0.2 / v0.3 — already shipped (evidence path)

Getting the evidence in the first place:

- **[SHIPPED v0.2] Evidence playbooks** — per-platform guides in
  `docs/evidence/` for exporting usable logs from the systems people
  actually run: OpenAI, Azure OpenAI (Log Analytics query included),
  AWS Bedrock (model-invocation logging → S3), LiteLLM, LangSmith,
  plus a "roll your own" minimal field spec. Copy-paste commands.
- **[SHIPPED v0.2] Named ingest adapters** — `compass ingest --from
  openai|litellm|bedrock|csv|csv-approvals --input <export>`
  normalises native formats into Compass JSONL. The csv-approvals
  adapter is the Jira/ServiceNow bridge: export a CSV and the
  human-oversight check lights up.
- **[SHIPPED v0.2] `compass doctor`** — evidence gap report: which
  checks have evidence, and for every gap the exact remediation step +
  playbook link. Gaps are findings, not failures.
- **[SHIPPED v0.2] `compass record`** — localhost OpenAI-compatible
  proxy. Point your SDK's `base_url` at it and every call is written as
  hash-chained JSONL.
- **[SHIPPED v0.3] Signed attestation** — `compass attest generate` /
  `verify`.

Later (unchanged):

- **Approval-system adapters** — deeper Jira and ServiceNow export
  converters building on the v0.2 CSV bridge.
- **Assessment diffing & trend** — `compass diff a.yaml b.yaml`.
- **Document evidence attachments** — hash + path recorded locally.
- **ISO/IEC 42001 catalog.**
- **Editable serve mode.**
- **NIST agent profile watch** — Q4 2026 profile; COSAiS overlays when
  final (2027).

## Out of scope (unchanged from v0.1)

Live connections to a running gateway, telemetry of any kind, PDF
*parsing* (attachments are referenced and hashed, not parsed), and
anything that would make Compass an enforcement layer — that is
[Smartflow](https://docs.aperion.ai).
