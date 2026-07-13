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
//! - [`scoring`] — combine answers + evidence into verdicts and a 0-100 score.
//! - [`report`] — JSON / Markdown / self-contained HTML renderers.
//! - [`serve`] — a tiny std-only local dashboard server.
//! - [`adapters`] — native-export → canonical-JSONL converters (OpenAI,
//!   LiteLLM, Bedrock, CSV) so existing logs become usable evidence.
//! - [`doctor`] — the evidence gap report: what can't be proven yet, and how
//!   to gather it.
//! - [`record`] — a std-only OpenAI-compatible recording proxy that captures
//!   tamper-evident evidence from live traffic.

pub mod action_risk;
pub mod adapters;
pub mod catalog;
pub mod doctor;
pub mod evidence;
pub mod questionnaire;
pub mod record;
pub mod report;
pub mod scoring;
pub mod serve;
