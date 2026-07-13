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
late 2026 are Art. 5, Art. 50, and GPAI — of which v0.1 covers only
Art. 5. The high-risk articles (9–15, 17, 26) remain correct and
useful as preparation for Dec 2027, but the catalog should say so.

**IMDA MGF for Agentic AI.** v0.1's catalog is seeded from **v1.5
(published 20 May 2026, updated 5 June 2026)** — confirmed still the
current edition. Spot-checked our control anchors against the v1.5
text: identity (unique/accounted/differentiated/catalogued),
authorization (scoped, least-privilege, bounded-by-human), oversight
effectiveness (override rate, response time, outlier reviewers), MCP
whitelisting + sandboxed code execution, tamper-evident logging, and
change management all match. v1.5 topics we don't yet cover: systemic
and multi-agent risks, memory poisoning, threat modelling / taint
tracing (per CSA's addendum), the platform-provider vs system-provider
value-chain split, and agentic-commerce protocols (ACP, AP2).

**NIST.** AI RMF 1.0 is under revision; the Generative AI Profile
(NIST-AI-600-1) is current. The Cyber AI Profile (IR 8596) is in
preliminary draft. COSAiS SP 800-53 overlays (incl. single- and
multi-agent) are drafts, final no earlier than 2027. NIST's AI Agent
Standards Initiative (Feb 2026) targets an **AI Agent Interoperability
Profile in Q4 2026**. The RMF core (GOVERN / MAP / MEASURE / MANAGE)
is stable enough to catalog now; agent-specific NIST content should
wait for the Q4 2026 profile.

---

## v0.2 — current-obligation coverage + CI depth

Catalog work (the content is the product):

- **EU: add an "Applies now" dimension** — Art. 50 transparency
  controls (disclosure, synthetic-content marking, deepfake labeling)
  and GPAI provider obligations (Arts. 51–55: technical documentation,
  copyright policy, training-content summary). These are the
  obligations binding in 2026 while high-risk is deferred.
- **EU: encode the Omnibus timeline** — per-control `effective_date`
  metadata so reports can say "binding now" vs "prepare by Dec 2027 /
  Aug 2028" instead of implying everything is due today.
- **EU: correct the incident-reporting reference** to Art. 73
  (serious-incident reporting), keeping Art. 79 as the related
  market-surveillance procedure. Control id stays stable so existing
  assessment files keep their answers.
- **IMDA: v1.5 delta controls** — systemic/multi-agent risk, memory
  poisoning, threat modelling & taint tracing, value-chain role
  clarity (platform vs system provider), agentic-commerce protocols.
- **NIST AI RMF catalog** (GOVERN / MAP / MEASURE / MANAGE) — the
  planned fast-follow from v0.1.

Getting the evidence in the first place (the biggest v0.1 gap —
most teams don't have governance-grade logs lying around, and
telling them "feed us JSONL" isn't a methodology):

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

Evidence + CI:

- **MCP trust-registry check** — ingest an exported server allowlist
  and report calls to unlisted servers (IMDA "whitelist trusted
  servers" gets objective evidence instead of self-attestation).
- **Emergency-stop evidence** — recognise kill-switch activation
  events in the chain and credit the interruption-authority controls.
- **Configurable thresholds** — per-check thresholds (override-rate
  floor, latency floor, sigma) in the assessment file instead of
  hard-coded defaults.
- **CI-native output** — JUnit XML and SARIF renderers so `compass
  report` results annotate PRs; a reference GitHub Action.
- **Non-interactive answers** — `compass assess --set control=yes`
  for scripted runs; `--only framework` and `--resume` for long
  questionnaires.

## v0.3 — crosswalks, trends, and richer evidence

- **[SHIPPED v0.2] `compass record`** — solves the cold-start problem
  for teams with no logs: a std-only localhost proxy speaking the
  OpenAI-compatible API. Point your SDK's `base_url` at it and every
  call is written as hash-chained, Compass-ready JSONL that doubles as
  the audit chain and the request log. Local only, nothing leaves the
  machine. (Follow-ups: direct-HTTPS upstreams and SSE streaming
  pass-through; today it forwards to http upstreams.)
- **Approval-system adapters** — deeper Jira and ServiceNow export
  converters building on the v0.2 CSV bridge.
- **Framework crosswalk** — map equivalent controls across EU / IMDA /
  NIST so one answered assessment scores against every catalog
  ("answer once, score everywhere"), with per-framework overrides.
- **Assessment diffing & trend** — `compass diff a.yaml b.yaml` and a
  score-over-time view in the dashboard; the quarterly-review story.
- **Signed reports** — optionally Ed25519-sign the scorecard JSON so a
  report is itself tamper-evident and a third party can verify who
  produced it (same primitive we already verify credentials with).
- **Document evidence attachments** — reference policy docs / PDFs per
  control (hash + path recorded in the assessment; content stays
  local), so the report carries an evidence inventory, not just notes.
- **ISO/IEC 42001 catalog** — the AI-management-system standard many
  buyers ask about alongside the EU AI Act; pairs with the crosswalk.
- **Editable serve mode** — change answers in the browser and save
  back to the assessment file (localhost only, same zero-server-trust
  posture).
- **NIST agent profile watch** — catalog the AI Agent Interoperability
  Profile when it lands (expected Q4 2026); COSAiS agent overlays when
  final (2027).

## Out of scope (unchanged from v0.1)

Live connections to a running gateway, telemetry of any kind, PDF
*parsing* (attachments are referenced and hashed, not parsed), and
anything that would make Compass an enforcement layer — that is
[Smartflow](https://docs.aperion.ai).
