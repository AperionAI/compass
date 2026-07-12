//! Automated evidence checks over locally-exported files.
//!
//! Each check keys off one [`AutoCheck`] and runs entirely offline over files
//! the user registered with `ingest`. A check produces a [`CheckOutcome`] that
//! `scoring` uses to corroborate or adjust the self-attested verdict of every
//! control wired to that check. Checks are always optional -- a
//! questionnaire-only assessment simply has no outcomes, and those controls
//! stay "self-attested".

use crate::catalog::AutoCheck;
use crate::questionnaire::EvidencePaths;
use serde::Serialize;
use std::collections::BTreeMap;

pub mod aida;
pub mod approvals;
pub mod chain;
pub mod generic;
pub mod vas;

/// Result status of an automated check.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CheckStatus {
    /// Evidence corroborates the control.
    Pass,
    /// Evidence found but with concerns (partial coverage, anomalies).
    Warn,
    /// Evidence contradicts the control (e.g. tampering detected).
    Fail,
    /// Not run (no input file provided).
    NotRun,
}

impl CheckStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            CheckStatus::Pass => "pass",
            CheckStatus::Warn => "warn",
            CheckStatus::Fail => "fail",
            CheckStatus::NotRun => "not_run",
        }
    }
}

/// The outcome of one automated check.
#[derive(Debug, Clone, Serialize)]
pub struct CheckOutcome {
    pub check: String,
    pub status: CheckStatus,
    pub summary: String,
    /// Structured detail for the report (shape depends on the check).
    pub detail: serde_json::Value,
}

impl CheckOutcome {
    fn new(
        check: AutoCheck,
        status: CheckStatus,
        summary: impl Into<String>,
        detail: serde_json::Value,
    ) -> Self {
        CheckOutcome {
            check: check.as_str().to_string(),
            status,
            summary: summary.into(),
            detail,
        }
    }
}

/// All evidence-check outcomes for an assessment, keyed by check.
#[derive(Debug, Clone, Default, Serialize)]
pub struct EvidenceBundle {
    pub outcomes: BTreeMap<String, CheckOutcome>,
    /// Human-readable list of the evidence files that were read.
    pub sources: Vec<String>,
}

impl EvidenceBundle {
    pub fn outcome(&self, check: AutoCheck) -> Option<&CheckOutcome> {
        self.outcomes.get(check.as_str())
    }

    fn insert(&mut self, outcome: CheckOutcome) {
        self.outcomes.insert(outcome.check.clone(), outcome);
    }
}

/// Run every check for which the required input files are present.
///
/// `logs` (VAS or generic) feed action-risk coverage and logging completeness;
/// `chain` feeds audit-chain integrity; `approvals` feed human oversight;
/// `credentials`+`jwks` feed agent identity.
pub fn run_all(paths: &EvidencePaths) -> EvidenceBundle {
    let mut bundle = EvidenceBundle::default();

    // Load log records once (VAS + generic share the same LogRecord shape).
    let mut records: Vec<vas::LogRecord> = Vec::new();
    if let Some(p) = &paths.vas {
        match vas::load(p) {
            Ok(mut r) => {
                bundle
                    .sources
                    .push(format!("vas logs: {p} ({} records)", r.len()));
                records.append(&mut r);
            }
            Err(e) => bundle.sources.push(format!("vas logs: {p} (error: {e})")),
        }
    }
    if let Some(p) = &paths.generic {
        match generic::load(p) {
            Ok(mut r) => {
                bundle
                    .sources
                    .push(format!("generic logs: {p} ({} records)", r.len()));
                records.append(&mut r);
            }
            Err(e) => bundle
                .sources
                .push(format!("generic logs: {p} (error: {e})")),
        }
    }

    if !records.is_empty() {
        bundle.insert(vas::action_risk_coverage(&records));
        bundle.insert(vas::logging_completeness(&records));
    }

    if let Some(chain) = &paths.chain {
        bundle.sources.push(format!("audit chain: {chain}"));
        bundle.insert(chain::verify(chain, paths.chain_hmac_key.as_deref()));
    }

    if let Some(appr) = &paths.approvals {
        bundle.sources.push(format!("approval tickets: {appr}"));
        bundle.insert(approvals::human_oversight(appr));
    }

    if let Some(creds) = &paths.credentials {
        bundle.sources.push(format!("agent credentials: {creds}"));
        bundle.insert(aida::agent_identity(creds, paths.jwks.as_deref()));
    }

    bundle
}

pub(crate) fn make_outcome(
    check: AutoCheck,
    status: CheckStatus,
    summary: impl Into<String>,
    detail: serde_json::Value,
) -> CheckOutcome {
    CheckOutcome::new(check, status, summary, detail)
}
