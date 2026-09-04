//! Aperion Compass — a local, offline AI-governance self-assessment library.
//!
//! The crate is split so the CLI binary is a thin shell over testable pieces:
//!
//! - [`catalog`] — the control-catalog model + loader (bundled EU AI Act and
//!   IMDA agentic catalogs).
//! - [`questionnaire`] — the assessment file model and the interactive prompt
//!   loop.
//! - [`action_risk`] — vendored deterministic T1/T2/T3 tierer.
//! - [`evidence`] — offline checks over exported files (audit-chain integrity,
//!   human oversight, action-risk coverage, agent identity, logging
//!   completeness).
//! - [`crosswalk`] — equivalent controls across catalogs; unanswered items
//!   inherit a peer's answer so one assessment scores against every framework.
//! - [`scoring`] — combine answers + evidence into verdicts and a 0-100 score.
//! - [`report`] — JSON / Markdown / HTML / JUnit / SARIF renderers.
//! - [`diff`] — compare two scored JSON reports (PR comment / CI).
//! - [`explain`] — why one control is the colour it is.
//! - [`serve`] — a tiny std-only local dashboard server.
//! - [`adapters`] — native-export → canonical-JSONL converters (OpenAI,
//!   LiteLLM, Bedrock, Azure OpenAI, LangSmith, Anthropic, Vertex, CSV).
//! - [`doctor`] — the evidence gap report: what can't be proven yet, and how
//!   to gather it.
//! - [`record`] — a std-only OpenAI-compatible recording proxy (http or
//!   https upstreams, SSE pass-through) that captures tamper-evident evidence
//!   from live traffic.
//! - [`attest`] — assemble + Ed25519-sign an offline-verifiable attestation
//!   bundle (posture + evidence + audit-chain anchor), and verify one.

pub mod action_risk;
pub mod adapters;
pub mod attest;
pub mod catalog;
pub mod crosswalk;
pub mod diff;
pub mod doctor;
pub mod evidence;
pub mod explain;
pub mod questionnaire;
pub mod record;
pub mod report;
pub mod scoring;
pub mod serve;
