//! Deterministic action-risk tiering (T1/T2/T3).
//!
//! Vendored, byte-for-byte-compatible copy of Smartflow's `src/action_risk.rs`
//! (Phase 0 of the Agentic Identity & Security Roadmap). The IMDA *Model AI
//! Governance Framework for Agentic AI* scores every agent action on severity,
//! reversibility, and feasibility of human oversight, and maps the result to a
//! tier that dictates how much autonomy the action is allowed.
//!
//! Compass uses this offline to tier the tool calls it finds in exported logs,
//! so an assessment reports the same tiers Smartflow would enforce at runtime.
//! The only change from the enterprise module is that the `Classification`
//! enum is inlined here (rather than imported from `crate::perimeter`) so the
//! tool has no dependency on the Smartflow crate.

use serde::{Deserialize, Serialize};

/// Where a destination sits relative to the trust fabric. Inlined copy of
/// `crate::perimeter::Classification` from Smartflow.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Classification {
    Internal,
    ExternalTrusted,
    ExternalPublic,
    Unknown,
}

impl Classification {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Internal => "internal",
            Self::ExternalTrusted => "external_trusted",
            Self::ExternalPublic => "external_public",
            Self::Unknown => "unknown",
        }
    }
}

/// Risk tier for a single agent action. Ordered `T1 < T2 < T3`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum ActionRiskTier {
    /// Low severity, fully reversible (reads, lists, searches).
    T1Reversible,
    /// Moderate severity, partially reversible (writes/edits, or data leaving
    /// the trust perimeter).
    T2PartiallyReversible,
    /// High severity, limited or no reversibility (deletes, payments,
    /// deployments, outbound communications, credential/permission changes).
    T3Irreversible,
}

impl ActionRiskTier {
    /// Short stable code stored in VAS / surfaced in headers.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::T1Reversible => "T1",
            Self::T2PartiallyReversible => "T2",
            Self::T3Irreversible => "T3",
        }
    }

    /// Human-readable label for dashboards.
    pub fn label(&self) -> &'static str {
        match self {
            Self::T1Reversible => "T1 — reversible",
            Self::T2PartiallyReversible => "T2 — partially reversible",
            Self::T3Irreversible => "T3 — irreversible",
        }
    }

    /// Whether a human approval checkpoint is recommended by default.
    pub fn requires_human_approval_default(&self) -> bool {
        matches!(self, Self::T3Irreversible)
    }

    /// Whether the control plane should fail **closed** for this tier when
    /// approval infrastructure is unavailable.
    pub fn fail_closed_default(&self) -> bool {
        matches!(self, Self::T2PartiallyReversible | Self::T3Irreversible)
    }
}

/// Inputs available for tier resolution. All optional so a caller can supply
/// only what it knows.
#[derive(Debug, Default, Clone)]
pub struct ActionContext<'a> {
    pub intent: Option<&'a str>,
    pub tool_or_method: Option<&'a str>,
    pub is_write: Option<bool>,
    pub classification: Option<Classification>,
}

const IRREVERSIBLE: &[&str] = &[
    "delete",
    "drop",
    "remove",
    "purge",
    "destroy",
    "truncate",
    "wipe",
    "erase",
    "payment",
    "pay",
    "transfer",
    "wire",
    "disburse",
    "refund",
    "charge",
    "invoice",
    "deploy",
    "release",
    "publish",
    "promote",
    "rollout",
    "send",
    "email",
    "sms",
    "notify",
    "post_message",
    "tweet",
    "terminate",
    "shutdown",
    "revoke",
    "deprovision",
    "provision",
    "grant",
    "merge",
    "force_push",
    "format",
    "execute",
    "exec",
    "run_command",
    "shell",
];

const WRITE: &[&str] = &[
    "write",
    "update",
    "modify",
    "edit",
    "create",
    "insert",
    "patch",
    "set",
    "put",
    "upsert",
    "rename",
    "move",
    "append",
    "add",
    "assign",
    "label",
    "schedule",
    "reschedule",
    "tag",
    "comment",
];

/// Resolve the action-risk tier from the signals a caller has.
pub fn resolve(ctx: &ActionContext<'_>) -> ActionRiskTier {
    let mut haystack = String::new();
    if let Some(i) = ctx.intent {
        haystack.push_str(&i.to_lowercase());
        haystack.push(' ');
    }
    if let Some(t) = ctx.tool_or_method {
        haystack.push_str(&t.to_lowercase());
    }

    if IRREVERSIBLE.iter().any(|k| haystack.contains(k)) {
        return ActionRiskTier::T3Irreversible;
    }

    let is_write_kw = WRITE.iter().any(|k| haystack.contains(k));
    let explicit_write = ctx.is_write == Some(true);
    let leaves_perimeter = matches!(
        ctx.classification,
        Some(Classification::ExternalPublic) | Some(Classification::Unknown)
    );

    if is_write_kw || explicit_write || leaves_perimeter {
        return ActionRiskTier::T2PartiallyReversible;
    }

    ActionRiskTier::T1Reversible
}

/// Convenience: resolve and return the stored string code in one call.
pub fn resolve_code(ctx: &ActionContext<'_>) -> String {
    resolve(ctx).as_str().to_string()
}

/// Map the perimeter classification *string* back to the enum.
pub fn classification_from_str(s: &str) -> Option<Classification> {
    match s {
        "internal" => Some(Classification::Internal),
        "external_trusted" => Some(Classification::ExternalTrusted),
        "external_public" => Some(Classification::ExternalPublic),
        "unknown" => Some(Classification::Unknown),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn t(tool: &str) -> ActionRiskTier {
        resolve(&ActionContext {
            tool_or_method: Some(tool),
            ..Default::default()
        })
    }

    #[test]
    fn ordering_is_t1_lt_t2_lt_t3() {
        assert!(ActionRiskTier::T1Reversible < ActionRiskTier::T2PartiallyReversible);
        assert!(ActionRiskTier::T2PartiallyReversible < ActionRiskTier::T3Irreversible);
    }

    #[test]
    fn reads_are_t1() {
        for tool in [
            "read_file",
            "list_dir",
            "search",
            "get_user",
            "fetch_docs",
            "describe_table",
        ] {
            assert_eq!(t(tool), ActionRiskTier::T1Reversible, "tool={tool}");
        }
    }

    #[test]
    fn writes_are_t2() {
        for tool in [
            "write_file",
            "update_record",
            "edit_doc",
            "create_ticket",
            "patch_config",
            "schedule_meeting",
        ] {
            assert_eq!(
                t(tool),
                ActionRiskTier::T2PartiallyReversible,
                "tool={tool}"
            );
        }
    }

    #[test]
    fn irreversible_are_t3() {
        for tool in [
            "delete_table",
            "make_payment",
            "deploy_service",
            "send_email",
            "drop_database",
            "revoke_access",
            "run_command",
        ] {
            assert_eq!(t(tool), ActionRiskTier::T3Irreversible, "tool={tool}");
        }
    }

    #[test]
    fn leaving_perimeter_bumps_read_to_t2() {
        let tier = resolve(&ActionContext {
            tool_or_method: Some("lookup"),
            classification: Some(Classification::ExternalPublic),
            ..Default::default()
        });
        assert_eq!(tier, ActionRiskTier::T2PartiallyReversible);
        let internal = resolve(&ActionContext {
            tool_or_method: Some("lookup"),
            classification: Some(Classification::Internal),
            ..Default::default()
        });
        assert_eq!(internal, ActionRiskTier::T1Reversible);
    }

    #[test]
    fn empty_context_defaults_t1() {
        assert_eq!(
            resolve(&ActionContext::default()),
            ActionRiskTier::T1Reversible
        );
    }

    #[test]
    fn classification_roundtrip() {
        for (s, c) in [
            ("internal", Classification::Internal),
            ("external_trusted", Classification::ExternalTrusted),
            ("external_public", Classification::ExternalPublic),
            ("unknown", Classification::Unknown),
        ] {
            assert_eq!(classification_from_str(s), Some(c));
            assert_eq!(c.as_str(), s);
        }
        assert_eq!(classification_from_str("bogus"), None);
    }
}
