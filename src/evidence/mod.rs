//! Automated evidence checks over locally-exported files.
//!
//! Each check keys off one [`AutoCheck`] and runs entirely offline over files
//! the user registered with `ingest`. A check produces a [`CheckOutcome`] that
//! `scoring` uses to corroborate or adjust the self-attested verdict of every
//! control wired to that check. Checks are always optional -- a
//! questionnaire-only assessment simply has no outcomes, and those controls
//! stay "self-attested".

use crate::catalog::AutoCheck;
use crate::questionnaire::{EvidencePaths, DEFAULT_FRESHNESS_DAYS};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

pub mod aida;
pub mod approvals;
pub mod chain;
pub mod documents;
pub mod generic;
pub mod mcp;
pub mod stop;
pub mod vas;

/// Result status of an automated check.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
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
#[derive(Debug, Clone, Serialize, Deserialize)]
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
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct EvidenceBundle {
    pub outcomes: BTreeMap<String, CheckOutcome>,
    /// Human-readable list of the evidence files that were read.
    pub sources: Vec<String>,
    /// Per-control document attachment results (`--doc --for <control>`).
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub documents: BTreeMap<String, CheckOutcome>,
    /// Evidence files older than the freshness window.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub stale: Vec<String>,
}

impl EvidenceBundle {
    pub fn outcome(&self, check: AutoCheck) -> Option<&CheckOutcome> {
        self.outcomes.get(check.as_str())
    }

    fn insert(&mut self, outcome: CheckOutcome) {
        self.outcomes.insert(outcome.check.clone(), outcome);
    }
}

/// SHA-256 hex of arbitrary bytes.
pub fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

/// RFC3339 timestamp from file mtime, if the OS reports one.
pub fn file_captured_at(path: &str) -> Option<String> {
    let meta = std::fs::metadata(path).ok()?;
    let modified = meta.modified().ok()?;
    let dt: DateTime<Utc> = modified.into();
    Some(dt.to_rfc3339())
}

/// Latest timestamp found in a JSONL / JSON-array file (`timestamp`,
/// `captured_at`, `created`, `start_time`), else file mtime.
pub fn evidence_captured_at(path: &str) -> Option<DateTime<Utc>> {
    if let Ok(raw) = std::fs::read_to_string(path) {
        let mut latest: Option<DateTime<Utc>> = None;
        let values = json_items(&raw);
        for v in values {
            let payload = v.get("payload").unwrap_or(&v);
            for key in [
                "timestamp",
                "captured_at",
                "created",
                "start_time",
                "startTime",
                "time",
            ] {
                if let Some(dt) = parse_ts(payload.get(key).or_else(|| v.get(key))) {
                    latest = Some(match latest {
                        Some(prev) if dt > prev => dt,
                        Some(prev) => prev,
                        None => dt,
                    });
                }
            }
        }
        if latest.is_some() {
            return latest;
        }
    }
    let meta = std::fs::metadata(path).ok()?;
    let modified = meta.modified().ok()?;
    Some(modified.into())
}

fn json_items(raw: &str) -> Vec<serde_json::Value> {
    let trimmed = raw.trim_start();
    if trimmed.starts_with('[') {
        return serde_json::from_str(raw).unwrap_or_default();
    }
    if trimmed.starts_with('{') {
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(raw) {
            if let Some(data) = v.get("data").and_then(|d| d.as_array()) {
                return data.clone();
            }
            return vec![v];
        }
    }
    let mut out = Vec::new();
    for line in raw.lines() {
        let s = line.trim();
        if s.is_empty() || s.starts_with('#') {
            continue;
        }
        if let Ok(v) = serde_json::from_str(s) {
            out.push(v);
        }
    }
    out
}

fn parse_ts(v: Option<&serde_json::Value>) -> Option<DateTime<Utc>> {
    let v = v?;
    match v {
        serde_json::Value::String(s) => DateTime::parse_from_rfc3339(s)
            .ok()
            .map(|d| d.with_timezone(&Utc))
            .or_else(|| {
                chrono::NaiveDateTime::parse_from_str(s, "%Y-%m-%d %H:%M:%S")
                    .ok()
                    .map(|n| n.and_utc())
            }),
        serde_json::Value::Number(n) => {
            let raw = n.as_i64()?;
            let secs = if raw > 1_000_000_000_000 {
                raw / 1000
            } else {
                raw
            };
            DateTime::from_timestamp(secs, 0)
        }
        _ => None,
    }
}

fn maybe_flag_stale(bundle: &mut EvidenceBundle, path: &str, freshness_days: u32, checks: &[&str]) {
    let Some(captured) = evidence_captured_at(path) else {
        return;
    };
    let age = (Utc::now() - captured).num_days();
    if age <= freshness_days as i64 {
        return;
    }
    let note = format!("{path} is {age} days old (freshness window {freshness_days}d)");
    if !bundle.stale.iter().any(|s| s == &note) {
        bundle.stale.push(note.clone());
    }
    for key in checks {
        if let Some(o) = bundle.outcomes.get_mut(*key) {
            if o.status == CheckStatus::Pass {
                o.status = CheckStatus::Warn;
                o.summary = format!("{} [stale: {note}]", o.summary);
            }
        }
    }
}

/// Run every check for which the required input files are present.
pub fn run_all(paths: &EvidencePaths) -> EvidenceBundle {
    run_all_with(paths, DEFAULT_FRESHNESS_DAYS)
}

/// Same as [`run_all`], with a freshness window in days (default 90).
pub fn run_all_with(paths: &EvidencePaths, freshness_days: u32) -> EvidenceBundle {
    let mut bundle = EvidenceBundle::default();
    let days = if freshness_days == 0 {
        DEFAULT_FRESHNESS_DAYS
    } else {
        freshness_days
    };

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
    for p in [&paths.vas, &paths.generic].into_iter().flatten() {
        maybe_flag_stale(
            &mut bundle,
            p,
            days,
            &[
                "action_risk_coverage",
                "logging_completeness",
                "mcp_allowlist",
            ],
        );
    }

    if let Some(chain) = &paths.chain {
        bundle.sources.push(format!("audit chain: {chain}"));
        bundle.insert(chain::verify(chain, paths.chain_hmac_key.as_deref()));
        bundle.insert(stop::check(chain));
        maybe_flag_stale(
            &mut bundle,
            chain,
            days,
            &["audit_chain_integrity", "emergency_stop"],
        );
    }

    if let Some(appr) = &paths.approvals {
        bundle.sources.push(format!("approval tickets: {appr}"));
        bundle.insert(approvals::human_oversight(appr));
        maybe_flag_stale(&mut bundle, appr, days, &["human_oversight"]);
    }

    if let Some(creds) = &paths.credentials {
        bundle.sources.push(format!("agent credentials: {creds}"));
        bundle.insert(aida::agent_identity(creds, paths.jwks.as_deref()));
        maybe_flag_stale(&mut bundle, creds, days, &["agent_identity"]);
    }

    if let Some(allow) = &paths.mcp_allowlist {
        bundle.sources.push(format!("mcp allowlist: {allow}"));
        bundle.insert(mcp::check(allow, &records));
        maybe_flag_stale(&mut bundle, allow, days, &["mcp_allowlist"]);
        for p in [&paths.vas, &paths.generic].into_iter().flatten() {
            maybe_flag_stale(&mut bundle, p, days, &["mcp_allowlist"]);
        }
    }

    if !paths.documents.is_empty() {
        bundle.documents = documents::verify_all(&paths.documents);
        let n = paths.documents.len();
        bundle.sources.push(format!("documents: {n} attached"));
        // A global document_attached outcome so doctor can see the check ran.
        let any_fail = bundle
            .documents
            .values()
            .any(|o| o.status == CheckStatus::Fail);
        let any_pass = bundle
            .documents
            .values()
            .any(|o| o.status == CheckStatus::Pass || o.status == CheckStatus::Warn);
        let status = if any_fail {
            CheckStatus::Fail
        } else if any_pass {
            CheckStatus::Pass
        } else {
            CheckStatus::NotRun
        };
        bundle.insert(make_outcome(
            AutoCheck::DocumentAttached,
            status,
            format!(
                "{} document(s) attached covering {} control(s).",
                n,
                bundle.documents.len()
            ),
            serde_json::json!({
                "controls": bundle.documents.keys().cloned().collect::<Vec<_>>(),
            }),
        ));
        for doc in &paths.documents {
            maybe_flag_stale(&mut bundle, &doc.path, days, &["document_attached"]);
            if evidence_captured_at(&doc.path)
                .map(|c| (Utc::now() - c).num_days() > days as i64)
                .unwrap_or(false)
            {
                for id in &doc.for_controls {
                    if let Some(o) = bundle.documents.get_mut(id) {
                        if o.status == CheckStatus::Pass {
                            o.status = CheckStatus::Warn;
                            o.summary = format!("{} [stale]", o.summary);
                        }
                    }
                }
            }
        }
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
