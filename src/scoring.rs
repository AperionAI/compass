//! Scoring: combine self-attested answers with automated evidence checks into
//! per-control verdicts, roll those up per dimension and per framework, and
//! produce an overall 0-100 conformance score plus a CI exit code.
//!
//! ## How a verdict is decided
//!
//! 1. Start from the self-attested answer (`yes/partial/no/na → exists/partial/
//!    absent/not_applicable`).
//! 2. Apply the outcomes of every automated check wired to the control:
//!    - a **Fail** (e.g. tampering detected, invalid signature) forces the
//!      verdict to **Absent** and marks it *contradicted* — objective evidence
//!      overrides a green self-attestation;
//!    - a **Warn** caps an `Exists` claim down to `Partial`;
//!    - a **Pass** floors an `Absent`/unanswered control up to `Partial` and
//!      marks it *evidence-backed* (we don't auto-claim full `Exists` from a
//!      single check that covers only part of a control).
//! 3. `NotApplicable` is excluded from scoring entirely.
//!
//! Scores: Exists = 1.0, Partial = 0.5, Absent = 0.0, weighted by each
//! control's `weight`.

use crate::catalog::{Catalog, Verdict};
use crate::evidence::{CheckStatus, EvidenceBundle};
use crate::questionnaire::{Answer, Assessment};
use serde::Serialize;

pub const DEFAULT_PASS_THRESHOLD: f64 = 70.0;

/// Exit codes for CI.
pub const EXIT_PASS: i32 = 0;
pub const EXIT_BELOW_THRESHOLD: i32 = 1;
pub const EXIT_INTEGRITY_FAILURE: i32 = 2;

#[derive(Debug, Clone, Serialize)]
pub struct AppliedCheck {
    pub check: String,
    pub status: CheckStatus,
    pub summary: String,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct VerdictCounts {
    pub exists: u64,
    pub partial: u64,
    pub absent: u64,
    pub not_applicable: u64,
    pub unanswered: u64,
}

impl VerdictCounts {
    fn tally(&mut self, verdict: Verdict, answer: Answer) {
        match verdict {
            Verdict::Exists => self.exists += 1,
            Verdict::Partial => self.partial += 1,
            Verdict::Absent => self.absent += 1,
            Verdict::NotApplicable => self.not_applicable += 1,
        }
        if answer == Answer::Unanswered {
            self.unanswered += 1;
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct ControlScore {
    pub control_id: String,
    pub title: String,
    pub framework_ref: String,
    pub dimension: String,
    pub weight: u32,
    pub answer: Answer,
    pub verdict: Verdict,
    /// 1.0 / 0.5 / 0.0, or `None` when Not Applicable.
    pub score: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
    pub applied_checks: Vec<AppliedCheck>,
    pub evidence_backed: bool,
    pub contradicted: bool,
    /// Populated whenever the verdict is not `Exists` / `NotApplicable`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remediation: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct DimensionScore {
    pub id: String,
    pub title: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    pub score: f64,
    pub counts: VerdictCounts,
    pub controls: Vec<ControlScore>,
}

#[derive(Debug, Clone, Serialize)]
pub struct FrameworkScore {
    pub framework: String,
    pub name: String,
    pub version: String,
    pub source: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    pub score: f64,
    pub label: String,
    pub counts: VerdictCounts,
    pub dimensions: Vec<DimensionScore>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Scorecard {
    pub generated_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub organization: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub system_name: Option<String>,
    pub tool: String,
    pub tool_version: String,
    pub overall_score: f64,
    pub overall_label: String,
    pub counts: VerdictCounts,
    pub frameworks: Vec<FrameworkScore>,
    pub evidence: EvidenceBundle,
    pub pass_threshold: f64,
    pub passed: bool,
    pub integrity_failure: bool,
    pub recommended_exit_code: i32,
}

/// Weighted 0-100 score over a set of control scores (NA excluded).
fn weighted_score(controls: &[ControlScore]) -> f64 {
    let mut num = 0.0;
    let mut den = 0.0;
    for c in controls {
        if let Some(s) = c.score {
            num += s * c.weight as f64;
            den += c.weight as f64;
        }
    }
    if den == 0.0 {
        0.0
    } else {
        (num / den) * 100.0
    }
}

fn verdict_score(v: Verdict) -> Option<f64> {
    match v {
        Verdict::Exists => Some(1.0),
        Verdict::Partial => Some(0.5),
        Verdict::Absent => Some(0.0),
        Verdict::NotApplicable => None,
    }
}

/// Conformance label bands (calibrated to the Smartflow conformity console).
pub fn label_for(score: f64) -> &'static str {
    let s = score.round() as i64;
    match s {
        90..=100 => "regulator-ready",
        70..=89 => "audit-ready with gaps documented",
        50..=69 => "internal-ready, regulator-prep needed",
        25..=49 => "early — gap-closure roadmap required",
        _ => "not-ready",
    }
}

/// Score one control by combining its answer with the outcomes of its checks.
fn score_control(
    control: &crate::catalog::Control,
    answer: Answer,
    note: Option<String>,
    evidence: &EvidenceBundle,
) -> ControlScore {
    let base = answer.to_verdict();
    let mut verdict = base;
    let mut applied = Vec::new();
    let mut any_fail = false;
    let mut any_warn = false;
    let mut any_pass = false;

    for check in &control.auto_checks {
        if let Some(outcome) = evidence.outcome(*check) {
            applied.push(AppliedCheck {
                check: outcome.check.clone(),
                status: outcome.status,
                summary: outcome.summary.clone(),
            });
            match outcome.status {
                CheckStatus::Fail => any_fail = true,
                CheckStatus::Warn => any_warn = true,
                CheckStatus::Pass => any_pass = true,
                CheckStatus::NotRun => {}
            }
        }
    }

    let mut contradicted = false;
    let mut evidence_backed = false;

    // NotApplicable is never overridden by evidence.
    if verdict != Verdict::NotApplicable {
        if any_fail {
            verdict = Verdict::Absent;
            contradicted = true;
        } else {
            if any_warn && verdict == Verdict::Exists {
                verdict = Verdict::Partial;
            }
            if any_pass && verdict == Verdict::Absent {
                verdict = Verdict::Partial;
                evidence_backed = true;
            } else if any_pass {
                evidence_backed = true;
            }
        }
    }

    let remediation = match verdict {
        Verdict::Exists | Verdict::NotApplicable => None,
        _ => Some(control.remediation.trim().to_string()),
    };

    ControlScore {
        control_id: control.id.clone(),
        title: control.title.clone(),
        framework_ref: control.framework_ref.clone(),
        dimension: control.dimension.clone(),
        weight: control.weight,
        answer,
        verdict,
        score: verdict_score(verdict),
        note,
        applied_checks: applied,
        evidence_backed,
        contradicted,
        remediation,
    }
}

/// Build the full scorecard for the selected catalogs given an assessment and
/// evidence bundle.
pub fn score(
    catalogs: &[Catalog],
    assessment: &Assessment,
    evidence: &EvidenceBundle,
    pass_threshold: f64,
) -> Scorecard {
    let mut framework_scores = Vec::new();
    let mut overall_counts = VerdictCounts::default();
    let mut all_controls_for_overall: Vec<ControlScore> = Vec::new();

    for cat in catalogs {
        let fa = assessment.framework(&cat.framework);
        let mut dimensions = Vec::new();
        let mut fw_counts = VerdictCounts::default();
        let mut fw_controls: Vec<ControlScore> = Vec::new();

        for dim in &cat.dimensions {
            let mut dim_counts = VerdictCounts::default();
            let mut dim_controls = Vec::new();
            for control in cat.controls.iter().filter(|c| c.dimension == dim.id) {
                let (answer, note) = fa
                    .and_then(|f| f.answer_for(&control.id))
                    .map(|a| (a.answer, a.note.clone()))
                    .unwrap_or((Answer::Unanswered, None));
                let cs = score_control(control, answer, note, evidence);
                dim_counts.tally(cs.verdict, cs.answer);
                fw_counts.tally(cs.verdict, cs.answer);
                overall_counts.tally(cs.verdict, cs.answer);
                dim_controls.push(cs.clone());
                fw_controls.push(cs.clone());
                all_controls_for_overall.push(cs);
            }
            let dim_score = weighted_score(&dim_controls);
            dimensions.push(DimensionScore {
                id: dim.id.clone(),
                title: dim.title.clone(),
                description: dim.description.clone(),
                score: dim_score,
                counts: dim_counts,
                controls: dim_controls,
            });
        }

        let fw_score = weighted_score(&fw_controls);
        framework_scores.push(FrameworkScore {
            framework: cat.framework.clone(),
            name: cat.name.clone(),
            version: cat.version.clone(),
            source: cat.source.clone(),
            description: cat.description.clone(),
            score: fw_score,
            label: label_for(fw_score).to_string(),
            counts: fw_counts,
            dimensions,
        });
    }

    let overall_score = weighted_score(&all_controls_for_overall);

    // Integrity failure = any hard evidence contradiction (tampering / invalid
    // signature) on an audit-chain or agent-identity check.
    let integrity_failure = [
        crate::catalog::AutoCheck::AuditChainIntegrity,
        crate::catalog::AutoCheck::AgentIdentity,
    ]
    .iter()
    .any(|c| {
        evidence
            .outcome(*c)
            .map(|o| o.status == CheckStatus::Fail)
            .unwrap_or(false)
    });

    let passed = overall_score >= pass_threshold;
    let recommended_exit_code = if integrity_failure {
        EXIT_INTEGRITY_FAILURE
    } else if passed {
        EXIT_PASS
    } else {
        EXIT_BELOW_THRESHOLD
    };

    Scorecard {
        generated_at: crate::questionnaire::now_rfc3339(),
        organization: assessment.organization.clone(),
        system_name: assessment.system_name.clone(),
        tool: "Aperion Compass".to_string(),
        tool_version: env!("CARGO_PKG_VERSION").to_string(),
        overall_score,
        overall_label: label_for(overall_score).to_string(),
        counts: overall_counts,
        frameworks: framework_scores,
        evidence: evidence.clone(),
        pass_threshold,
        passed,
        integrity_failure,
        recommended_exit_code,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::catalog;
    use crate::evidence::CheckOutcome;
    use crate::questionnaire::Assessment;

    fn answer_all(assessment: &mut Assessment, framework: &str, ans: Answer) {
        if let Some(fa) = assessment.framework_mut(framework) {
            for a in fa.answers.iter_mut() {
                a.answer = ans;
            }
        }
    }

    #[test]
    fn all_yes_scores_100_before_evidence() {
        let cats = catalog::load_selection(&["imda".into()]).unwrap();
        let mut a = Assessment::scaffold(&cats);
        answer_all(&mut a, "imda", Answer::Yes);
        let sc = score(&cats, &a, &EvidenceBundle::default(), 70.0);
        assert!(
            (sc.overall_score - 100.0).abs() < 1e-6,
            "score={}",
            sc.overall_score
        );
        assert!(sc.passed);
        assert_eq!(sc.recommended_exit_code, EXIT_PASS);
    }

    #[test]
    fn all_no_scores_zero_and_fails() {
        let cats = catalog::load_selection(&["eu".into()]).unwrap();
        let mut a = Assessment::scaffold(&cats);
        answer_all(&mut a, "eu-ai-act", Answer::No);
        let sc = score(&cats, &a, &EvidenceBundle::default(), 70.0);
        assert!(sc.overall_score < 1.0);
        assert!(!sc.passed);
        assert_eq!(sc.recommended_exit_code, EXIT_BELOW_THRESHOLD);
    }

    #[test]
    fn failing_chain_check_forces_integrity_exit() {
        let cats = catalog::load_selection(&["eu".into()]).unwrap();
        let mut a = Assessment::scaffold(&cats);
        answer_all(&mut a, "eu-ai-act", Answer::Yes);
        let mut ev = EvidenceBundle::default();
        ev.outcomes.insert(
            "audit_chain_integrity".into(),
            CheckOutcome {
                check: "audit_chain_integrity".into(),
                status: CheckStatus::Fail,
                summary: "tampering".into(),
                detail: serde_json::json!({}),
            },
        );
        let sc = score(&cats, &a, &ev, 70.0);
        assert!(sc.integrity_failure);
        assert_eq!(sc.recommended_exit_code, EXIT_INTEGRITY_FAILURE);
        // The Art.12 traceability control (wired to the chain check) is now
        // contradicted despite the "yes" answer.
        let contradicted = sc
            .frameworks
            .iter()
            .flat_map(|f| f.dimensions.iter())
            .flat_map(|d| d.controls.iter())
            .any(|c| c.contradicted);
        assert!(contradicted);
    }

    #[test]
    fn pass_check_floors_absent_to_partial() {
        let cats = catalog::load_selection(&["imda".into()]).unwrap();
        let mut a = Assessment::scaffold(&cats);
        answer_all(&mut a, "imda", Answer::No);
        let mut ev = EvidenceBundle::default();
        ev.outcomes.insert(
            "audit_chain_integrity".into(),
            CheckOutcome {
                check: "audit_chain_integrity".into(),
                status: CheckStatus::Pass,
                summary: "clean".into(),
                detail: serde_json::json!({}),
            },
        );
        let sc = score(&cats, &a, &ev, 70.0);
        let tamper_control = sc
            .frameworks
            .iter()
            .flat_map(|f| f.dimensions.iter())
            .flat_map(|d| d.controls.iter())
            .find(|c| c.control_id == "tamper_proof_audit")
            .unwrap();
        assert_eq!(tamper_control.verdict, Verdict::Partial);
        assert!(tamper_control.evidence_backed);
    }
}
