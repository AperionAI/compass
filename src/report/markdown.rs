//! Markdown report — diffable, PR-friendly, board-deck-pasteable.

use crate::catalog::Verdict;
use crate::scoring::{ControlScore, Scorecard};
use std::fmt::Write;

fn verdict_badge(v: Verdict) -> &'static str {
    match v {
        Verdict::Exists => "✅ Exists",
        Verdict::Partial => "🟡 Partial",
        Verdict::Absent => "❌ Absent",
        Verdict::NotApplicable => "⚪ N/A",
    }
}

pub fn render(card: &Scorecard) -> String {
    let mut s = String::new();

    writeln!(s, "# AI Governance Self-Assessment").ok();
    writeln!(s).ok();
    writeln!(
        s,
        "*Generated locally by {} v{} — no data leaves your machine.*",
        card.tool, card.tool_version
    )
    .ok();
    writeln!(s).ok();
    if let Some(org) = &card.organization {
        writeln!(s, "- **Organisation:** {org}").ok();
    }
    if let Some(sys) = &card.system_name {
        writeln!(s, "- **System:** {sys}").ok();
    }
    writeln!(s, "- **Generated:** {}", card.generated_at).ok();
    writeln!(s).ok();

    writeln!(
        s,
        "## Overall: {} / 100 — {}",
        card.overall_score.round() as i64,
        card.overall_label
    )
    .ok();
    writeln!(s).ok();
    let status = if card.passed {
        format!(
            "**PASS** (threshold {})",
            card.pass_threshold.round() as i64
        )
    } else {
        format!(
            "**BELOW THRESHOLD** ({})",
            card.pass_threshold.round() as i64
        )
    };
    writeln!(s, "{status}").ok();
    if card.integrity_failure {
        writeln!(s, "\n> ⚠ **Evidence integrity failure** — an audit-chain or agent-identity check failed. Treat results as compromised until resolved.").ok();
    }
    writeln!(s).ok();
    let c = &card.counts;
    writeln!(
        s,
        "| Exists | Partial | Absent | N/A | Unanswered |\n|---:|---:|---:|---:|---:|\n| {} | {} | {} | {} | {} |",
        c.exists, c.partial, c.absent, c.not_applicable, c.unanswered
    )
    .ok();
    writeln!(s).ok();

    // Evidence.
    writeln!(s, "## Evidence").ok();
    writeln!(s).ok();
    if card.evidence.outcomes.is_empty() {
        writeln!(
            s,
            "_No evidence files ingested — every control is self-attested._"
        )
        .ok();
    } else {
        writeln!(s, "| Check | Result | Summary |\n|---|---|---|").ok();
        for (k, o) in &card.evidence.outcomes {
            writeln!(
                s,
                "| {} | {} | {} |",
                k.replace('_', " "),
                o.status.as_str(),
                o.summary.replace('|', "\\|")
            )
            .ok();
        }
        if !card.evidence.sources.is_empty() {
            writeln!(s).ok();
            for src in &card.evidence.sources {
                writeln!(s, "- {src}").ok();
            }
        }
    }
    writeln!(s).ok();

    // Frameworks.
    for fw in &card.frameworks {
        writeln!(
            s,
            "## {} — {} / 100 ({})",
            fw.name,
            fw.score.round() as i64,
            fw.label
        )
        .ok();
        writeln!(s).ok();
        writeln!(s, "_{} — {}_", fw.version, fw.source).ok();
        writeln!(s).ok();
        for dim in &fw.dimensions {
            writeln!(s, "### {} — {} / 100", dim.title, dim.score.round() as i64).ok();
            writeln!(s).ok();
            writeln!(s, "| Ref | Control | Verdict | Notes |\n|---|---|---|---|").ok();
            for cs in &dim.controls {
                writeln!(
                    s,
                    "| {} | {} | {} | {} |",
                    cs.framework_ref,
                    cs.title.replace('|', "\\|"),
                    verdict_badge(cs.verdict),
                    control_notes(cs)
                )
                .ok();
            }
            writeln!(s).ok();
        }
    }

    // Remediation summary.
    let gaps: Vec<&ControlScore> = card
        .frameworks
        .iter()
        .flat_map(|f| f.dimensions.iter())
        .flat_map(|d| d.controls.iter())
        .filter(|c| c.remediation.is_some())
        .collect();
    if !gaps.is_empty() {
        writeln!(s, "## Remediation — {} open item(s)", gaps.len()).ok();
        writeln!(s).ok();
        for cs in gaps {
            writeln!(
                s,
                "- **[{}] {}** ({}) — {}",
                cs.framework_ref,
                cs.title,
                verdict_badge(cs.verdict),
                cs.remediation.as_deref().unwrap_or("")
            )
            .ok();
        }
        writeln!(s).ok();
    }

    writeln!(s, "---").ok();
    writeln!(
        s,
        "Remediation patterns and the continuous-enforcement upgrade: https://docs.aperion.ai"
    )
    .ok();

    s
}

fn control_notes(cs: &ControlScore) -> String {
    let mut parts = Vec::new();
    if cs.contradicted {
        parts.push("⚠ evidence contradicts self-attestation".to_string());
    } else if cs.evidence_backed {
        parts.push("evidence-backed".to_string());
    }
    for a in &cs.applied_checks {
        parts.push(format!(
            "{}={}",
            a.check.replace('_', " "),
            a.status.as_str()
        ));
    }
    if let Some(note) = &cs.note {
        parts.push(format!("“{}”", note.replace('|', "\\|")));
    }
    if parts.is_empty() {
        "—".to_string()
    } else {
        parts.join("; ")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{catalog, evidence::EvidenceBundle, questionnaire::Assessment, scoring};

    #[test]
    fn renders_markdown_with_headings() {
        let cats = catalog::load_selection(&["eu".into(), "imda".into()]).unwrap();
        let a = Assessment::scaffold(&cats);
        let card = scoring::score(&cats, &a, &EvidenceBundle::default(), 70.0);
        let md = render(&card);
        assert!(md.contains("# AI Governance Self-Assessment"));
        assert!(md.contains("## Overall:"));
        assert!(md.contains("EU AI Act"));
        assert!(md.contains("IMDA"));
    }
}
