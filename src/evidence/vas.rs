//! VAS-log ingestion + the action-risk-coverage and logging-completeness
//! checks.
//!
//! Rather than vendor the ~83-field `VASLog` struct, Compass reads each line as
//! JSON and exposes a forgiving [`LogRecord`] accessor that understands both
//! Smartflow VAS exports and generic request logs (multiple key spellings).
//! This keeps ingestion robust to schema drift and to non-Smartflow users.

use super::{make_outcome, CheckOutcome, CheckStatus};
use crate::action_risk::{self, ActionContext, ActionRiskTier};
use crate::catalog::AutoCheck;
use anyhow::{Context, Result};
use serde_json::Value;
use std::collections::BTreeMap;

/// One log line, wrapped for forgiving field access across schema variants.
#[derive(Debug, Clone)]
pub struct LogRecord(pub Value);

impl LogRecord {
    /// First present string field among `keys` (searches top level and, for a
    /// couple of known nests, one level down).
    pub fn str_any(&self, keys: &[&str]) -> Option<String> {
        for k in keys {
            if let Some(s) = self.0.get(k).and_then(|v| v.as_str()) {
                if !s.is_empty() {
                    return Some(s.to_string());
                }
            }
        }
        None
    }

    pub fn bool_any(&self, keys: &[&str]) -> Option<bool> {
        for k in keys {
            if let Some(b) = self.0.get(k).and_then(|v| v.as_bool()) {
                return Some(b);
            }
        }
        None
    }

    fn has_nonempty(&self, keys: &[&str]) -> bool {
        keys.iter().any(|k| match self.0.get(k) {
            Some(Value::Null) | None => false,
            Some(Value::String(s)) => !s.is_empty(),
            Some(_) => true,
        })
    }

    /// The tool / method name if this record represents a tool or MCP call.
    pub fn tool_or_method(&self) -> Option<String> {
        self.str_any(&[
            "tool_name",
            "tool",
            "mcp_method",
            "method",
            "function",
            "name",
        ])
    }

    /// The semantic intent signature, if present.
    pub fn intent(&self) -> Option<String> {
        self.str_any(&[
            "intent",
            "task_class",
            "conversation_stage",
            "intent_signature",
        ])
    }

    /// The perimeter classification string, if present.
    pub fn perimeter_classification(&self) -> Option<String> {
        self.str_any(&["perimeter_classification", "classification"])
    }

    /// A pre-stamped action-risk tier, if the log already carries one.
    pub fn stamped_tier(&self) -> Option<String> {
        self.str_any(&["action_risk_tier", "risk_tier"])
    }

    /// Whether the record shows an accountable identity (human/agent binding).
    pub fn has_identity(&self) -> bool {
        self.has_nonempty(&[
            "user_id",
            "aida_principal_id",
            "aida_agent_id",
            "principal_id",
            "verified_identity",
            "user",
        ])
    }

    /// Whether the record shows a governance decision (shield/policy/etc.).
    pub fn has_decision(&self) -> bool {
        self.has_nonempty(&[
            "shield_decision",
            "shield_action",
            "policy_decision",
            "maestro_blocked",
            "decision",
            "blocked",
        ])
    }

    /// Whether this record shows an approval was involved.
    pub fn has_approval(&self) -> bool {
        self.has_nonempty(&[
            "shield_ticket_id",
            "approval_id",
            "approved_by",
            "approver_id",
        ])
    }

    /// Resolve the action-risk tier for this record deterministically.
    pub fn resolve_tier(&self) -> ActionRiskTier {
        // Prefer an already-stamped tier when present and parseable.
        if let Some(code) = self.stamped_tier() {
            match code.as_str() {
                "T1" => return ActionRiskTier::T1Reversible,
                "T2" => return ActionRiskTier::T2PartiallyReversible,
                "T3" => return ActionRiskTier::T3Irreversible,
                _ => {}
            }
        }
        let intent = self.intent();
        let tool = self.tool_or_method();
        let classification = self
            .perimeter_classification()
            .and_then(|s| action_risk::classification_from_str(&s));
        action_risk::resolve(&ActionContext {
            intent: intent.as_deref(),
            tool_or_method: tool.as_deref(),
            is_write: None,
            classification,
        })
    }
}

/// Load a JSONL (or JSON-array) file of log records.
pub fn load(path: &str) -> Result<Vec<LogRecord>> {
    let raw = std::fs::read_to_string(path).with_context(|| format!("reading log file {path}"))?;
    parse(&raw)
}

/// Parse JSONL (one object per line) or a JSON array into records. Blank lines
/// and `#` comments are skipped.
pub fn parse(raw: &str) -> Result<Vec<LogRecord>> {
    let trimmed = raw.trim_start();
    if trimmed.starts_with('[') {
        let arr: Vec<Value> = serde_json::from_str(raw).context("parsing JSON array of logs")?;
        return Ok(arr.into_iter().map(LogRecord).collect());
    }
    let mut out = Vec::new();
    for (i, line) in raw.lines().enumerate() {
        let s = line.trim();
        if s.is_empty() || s.starts_with('#') {
            continue;
        }
        let v: Value =
            serde_json::from_str(s).with_context(|| format!("parsing JSONL line {}", i + 1))?;
        out.push(LogRecord(v));
    }
    Ok(out)
}

/// Action-risk coverage: tier every tool-invoking record and report the
/// distribution, plus how many T3 (irreversible) actions carried an approval.
pub fn action_risk_coverage(records: &[LogRecord]) -> CheckOutcome {
    let mut t1 = 0u64;
    let mut t2 = 0u64;
    let mut t3 = 0u64;
    let mut t3_with_approval = 0u64;
    let mut actionable = 0u64; // records that look like an action (have a tool/method)

    for r in records {
        // Only tier records that represent an action (tool/method present) or
        // that already carry a stamped tier.
        if r.tool_or_method().is_none() && r.stamped_tier().is_none() {
            continue;
        }
        actionable += 1;
        match r.resolve_tier() {
            ActionRiskTier::T1Reversible => t1 += 1,
            ActionRiskTier::T2PartiallyReversible => t2 += 1,
            ActionRiskTier::T3Irreversible => {
                t3 += 1;
                if r.has_approval() {
                    t3_with_approval += 1;
                }
            }
        }
    }

    let detail = serde_json::json!({
        "actionable_records": actionable,
        "t1_reversible": t1,
        "t2_partially_reversible": t2,
        "t3_irreversible": t3,
        "t3_with_approval": t3_with_approval,
        "t3_without_approval": t3.saturating_sub(t3_with_approval),
    });

    if actionable == 0 {
        return make_outcome(
            AutoCheck::ActionRiskCoverage,
            CheckStatus::NotRun,
            "No tool/action records found to tier.",
            detail,
        );
    }

    let (status, summary) = if t3 == 0 {
        (
            CheckStatus::Pass,
            format!("Tiered {actionable} actions; no irreversible (T3) actions observed."),
        )
    } else if t3_with_approval == t3 {
        (
            CheckStatus::Pass,
            format!("All {t3} irreversible (T3) actions carried an approval."),
        )
    } else {
        (
            CheckStatus::Warn,
            format!(
                "{} of {t3} irreversible (T3) actions had no approval evidence.",
                t3 - t3_with_approval
            ),
        )
    };

    make_outcome(AutoCheck::ActionRiskCoverage, status, summary, detail)
}

/// Logging completeness: field-presence stats over the records for the
/// governance-relevant fields (identity, decision, risk tier, perimeter).
pub fn logging_completeness(records: &[LogRecord]) -> CheckOutcome {
    let n = records.len() as u64;
    if n == 0 {
        return make_outcome(
            AutoCheck::LoggingCompleteness,
            CheckStatus::NotRun,
            "No log records found.",
            serde_json::json!({}),
        );
    }

    let mut counts: BTreeMap<&str, u64> = BTreeMap::new();
    for r in records {
        if r.has_identity() {
            *counts.entry("identity").or_default() += 1;
        }
        if r.has_decision() {
            *counts.entry("decision").or_default() += 1;
        }
        if r.stamped_tier().is_some() {
            *counts.entry("risk_tier").or_default() += 1;
        }
        if r.perimeter_classification().is_some() {
            *counts.entry("perimeter").or_default() += 1;
        }
        if r.str_any(&["model", "provider"]).is_some() {
            *counts.entry("model_provider").or_default() += 1;
        }
        if r.str_any(&["request_id", "id"]).is_some() {
            *counts.entry("request_id").or_default() += 1;
        }
    }

    let pct = |k: &str| -> f64 {
        let c = counts.get(k).copied().unwrap_or(0);
        (c as f64 / n as f64) * 100.0
    };

    let coverage = serde_json::json!({
        "records": n,
        "request_id_pct": pct("request_id"),
        "model_provider_pct": pct("model_provider"),
        "identity_pct": pct("identity"),
        "decision_pct": pct("decision"),
        "risk_tier_pct": pct("risk_tier"),
        "perimeter_pct": pct("perimeter"),
    });

    // Core traceability fields: request id + model/provider + identity.
    let core = (pct("request_id") + pct("model_provider") + pct("identity")) / 3.0;
    let (status, summary) = if core >= 90.0 {
        (
            CheckStatus::Pass,
            format!("Core traceability fields present in {core:.0}% of {n} records."),
        )
    } else if core >= 50.0 {
        (
            CheckStatus::Warn,
            format!("Core traceability fields present in only {core:.0}% of {n} records."),
        )
    } else {
        (
            CheckStatus::Fail,
            format!("Core traceability fields present in just {core:.0}% of {n} records."),
        )
    };

    make_outcome(AutoCheck::LoggingCompleteness, status, summary, coverage)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_jsonl_and_array() {
        let jsonl = "{\"tool_name\":\"read_file\"}\n{\"tool_name\":\"delete_table\"}\n";
        let arr = r#"[{"tool_name":"read_file"},{"tool_name":"delete_table"}]"#;
        assert_eq!(parse(jsonl).unwrap().len(), 2);
        assert_eq!(parse(arr).unwrap().len(), 2);
    }

    #[test]
    fn tiers_actions_and_flags_missing_approval() {
        let recs = parse(
            "{\"tool_name\":\"read_file\"}\n\
             {\"tool_name\":\"delete_database\"}\n\
             {\"tool_name\":\"make_payment\",\"shield_ticket_id\":\"t-1\"}\n",
        )
        .unwrap();
        let o = action_risk_coverage(&recs);
        assert_eq!(o.status, CheckStatus::Warn); // one T3 (delete) w/o approval
        assert_eq!(o.detail["t3_irreversible"], 2);
        assert_eq!(o.detail["t3_with_approval"], 1);
    }

    #[test]
    fn logging_completeness_scores_coverage() {
        let recs = parse(
            "{\"request_id\":\"r1\",\"model\":\"gpt\",\"user_id\":\"u1\",\"action_risk_tier\":\"T1\"}\n\
             {\"request_id\":\"r2\",\"model\":\"gpt\",\"user_id\":\"u2\"}\n",
        )
        .unwrap();
        let o = logging_completeness(&recs);
        assert_eq!(o.status, CheckStatus::Pass);
        assert_eq!(o.detail["records"], 2);
    }

    #[test]
    fn stamped_tier_is_respected() {
        let r = LogRecord(serde_json::json!({"tool_name":"lookup","action_risk_tier":"T3"}));
        assert_eq!(r.resolve_tier(), ActionRiskTier::T3Irreversible);
    }
}
