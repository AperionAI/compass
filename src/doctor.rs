//! `compass doctor` — the evidence gap report.
//!
//! Diagnosis, not scoring. It looks at the automated checks the selected
//! catalogs rely on, sees which ones actually ran against the evidence you
//! provided, and for every gap prints the concrete next step: which file to
//! export, which `ingest --from` adapter converts it, and which playbook walks
//! you through pulling it from your platform. The whole point is to answer the
//! most common question from a first run — "I don't have these logs, now
//! what?" — inside the tool instead of in a wiki nobody reads.

use crate::catalog::{AutoCheck, Catalog};
use crate::evidence::{CheckStatus, EvidenceBundle};
use crate::questionnaire::EvidencePaths;

/// One check's diagnosis: did it run, and if not (or only partially), what to do.
#[derive(Debug, Clone)]
pub struct CheckDiag {
    pub check: &'static str,
    pub controls_backed: usize,
    pub status: CheckStatus,
    pub summary: String,
    /// Concrete remediation (empty when the check already passed).
    pub remediation: String,
    /// Relative path to the playbook that explains how to gather this evidence.
    pub playbook: &'static str,
}

/// The full gap report.
#[derive(Debug, Clone)]
pub struct Diagnosis {
    pub checks: Vec<CheckDiag>,
    pub ran: usize,
    pub total: usize,
}

impl Diagnosis {
    /// Fraction of auto-check-backed capability that has corroborating evidence.
    pub fn coverage_pct(&self) -> f64 {
        if self.total == 0 {
            return 100.0;
        }
        (self.ran as f64 / self.total as f64) * 100.0
    }
}

struct CheckMeta {
    playbook: &'static str,
    /// How to supply the missing evidence.
    remediation: &'static str,
}

fn meta_for(check: AutoCheck) -> CheckMeta {
    match check {
        AutoCheck::ActionRiskCoverage => CheckMeta {
            playbook: "docs/evidence/README.md",
            remediation: "Provide request/tool logs. Convert an existing export with \
                `compass ingest --from openai|litellm|bedrock|csv --input <export>` \
                (see the per-provider playbooks).",
        },
        AutoCheck::LoggingCompleteness => CheckMeta {
            playbook: "docs/evidence/README.md",
            remediation: "Provide request logs so field completeness can be measured. \
                Convert an export with `compass ingest --from <provider> --input <file>`.",
        },
        AutoCheck::AuditChainIntegrity => CheckMeta {
            playbook: "docs/evidence/audit-chain.md",
            remediation: "Export a tamper-evident audit chain and register it with \
                `--chain <file> --chain-hmac-key <spec>`. No chain yet? `compass record` \
                writes one from live traffic.",
        },
        AutoCheck::HumanOversight => CheckMeta {
            playbook: "docs/evidence/approvals-csv.md",
            remediation: "Export your approval/review decisions (a CSV from Jira or \
                ServiceNow works) and run \
                `compass ingest --from csv-approvals --input <file>`.",
        },
        AutoCheck::AgentIdentity => CheckMeta {
            playbook: "docs/evidence/agent-identity.md",
            remediation: "Export signed agent credentials plus the issuer public key / \
                JWKS and register them with `--credentials <file> --jwks <file>`.",
        },
    }
}

/// Build the diagnosis from the selected catalogs, the evidence paths on the
/// assessment, and the outcomes produced by running the checks.
pub fn diagnose(
    catalogs: &[Catalog],
    _evidence: &EvidencePaths,
    bundle: &EvidenceBundle,
) -> Diagnosis {
    // Count controls backing each check across all selected catalogs.
    let all = [
        AutoCheck::ActionRiskCoverage,
        AutoCheck::LoggingCompleteness,
        AutoCheck::AuditChainIntegrity,
        AutoCheck::HumanOversight,
        AutoCheck::AgentIdentity,
    ];

    let mut checks = Vec::new();
    let mut ran = 0usize;
    let mut total = 0usize;

    for check in all {
        let backed = catalogs
            .iter()
            .flat_map(|c| &c.controls)
            .filter(|ctl| ctl.auto_checks.contains(&check))
            .count();
        if backed == 0 {
            continue; // no control in the selected frameworks uses this check
        }
        total += 1;
        let meta = meta_for(check);

        let (status, summary, remediation) = match bundle.outcome(check) {
            Some(o) => {
                let ran_ok = matches!(
                    o.status,
                    CheckStatus::Pass | CheckStatus::Warn | CheckStatus::Fail
                );
                if matches!(o.status, CheckStatus::Pass) {
                    ran += 1;
                    (o.status, o.summary.clone(), String::new())
                } else if ran_ok {
                    // Warn/Fail: it ran, but flag what to tighten.
                    ran += 1;
                    let extra = if o.status == CheckStatus::Warn {
                        meta.remediation.to_string()
                    } else {
                        String::new()
                    };
                    (o.status, o.summary.clone(), extra)
                } else {
                    (
                        CheckStatus::NotRun,
                        o.summary.clone(),
                        meta.remediation.to_string(),
                    )
                }
            }
            None => (
                CheckStatus::NotRun,
                "No evidence provided for this check.".to_string(),
                meta.remediation.to_string(),
            ),
        };

        checks.push(CheckDiag {
            check: check.as_str(),
            controls_backed: backed,
            status,
            summary,
            remediation,
            playbook: meta.playbook,
        });
    }

    Diagnosis { checks, ran, total }
}

/// Render the diagnosis as a human-readable report.
pub fn render_text(d: &Diagnosis) -> String {
    let mut s = String::new();
    s.push_str("Aperion Compass — evidence check-up\n");
    s.push_str(&"=".repeat(48));
    s.push('\n');
    s.push_str(&format!(
        "{} of {} automated checks have evidence ({:.0}% of auto-verifiable capability).\n\n",
        d.ran,
        d.total,
        d.coverage_pct()
    ));

    for c in &d.checks {
        let mark = match c.status {
            CheckStatus::Pass => "PASS",
            CheckStatus::Warn => "WARN",
            CheckStatus::Fail => "FAIL",
            CheckStatus::NotRun => "GAP ",
        };
        s.push_str(&format!(
            "[{mark}] {}  ({} control{})\n",
            c.check,
            c.controls_backed,
            if c.controls_backed == 1 { "" } else { "s" }
        ));
        s.push_str(&format!("       {}\n", c.summary));
        if !c.remediation.is_empty() {
            s.push_str(&format!("       → {}\n", c.remediation));
            s.push_str(&format!("       playbook: {}\n", c.playbook));
        }
        s.push('\n');
    }

    if d.ran < d.total {
        s.push_str(
            "Gaps are findings, not failures: each one is a control you cannot yet prove.\n\
             Start with the playbook links above, or run `compass record` to capture\n\
             evidence from live traffic. Then re-run `compass report`.\n",
        );
    } else if d.total > 0 {
        s.push_str("All auto-verifiable checks have evidence. Run `compass report` to score.\n");
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::catalog;
    use crate::evidence::run_all;

    #[test]
    fn empty_evidence_reports_all_gaps() {
        let cats = catalog::load_selection(&["eu".into(), "imda".into()]).unwrap();
        let paths = EvidencePaths::default();
        let bundle = EvidenceBundle::default();
        let d = diagnose(&cats, &paths, &bundle);
        assert!(d.total > 0);
        assert_eq!(d.ran, 0);
        assert!(d.checks.iter().all(|c| c.status == CheckStatus::NotRun));
        assert!(d.checks.iter().all(|c| !c.remediation.is_empty()));
        let text = render_text(&d);
        assert!(text.contains("GAP"));
        assert!(text.contains("playbook:"));
    }

    #[test]
    fn provided_logs_close_the_logging_gap() {
        let cats = catalog::load_selection(&["imda".into()]).unwrap();
        // Write a tiny generic log file.
        let dir = tempfile::tempdir().unwrap();
        let log = dir.path().join("logs.jsonl");
        std::fs::write(
            &log,
            "{\"request_id\":\"r1\",\"model\":\"gpt\",\"provider\":\"openai\",\"user_id\":\"u1\",\"tool_name\":\"read_file\"}\n",
        )
        .unwrap();
        let paths = EvidencePaths {
            generic: Some(log.to_string_lossy().to_string()),
            ..Default::default()
        };
        let bundle = run_all(&paths);
        let d = diagnose(&cats, &paths, &bundle);
        let logging = d
            .checks
            .iter()
            .find(|c| c.check == "logging_completeness")
            .unwrap();
        assert_ne!(logging.status, CheckStatus::NotRun);
    }
}
