//! `compass explain <control_id>` — why this control is the colour it is.

use crate::catalog::{Catalog, Control};
use crate::evidence::EvidenceBundle;
use crate::scoring::{ControlScore, Scorecard};

/// Render a human-readable explanation for one control.
pub fn render(
    control_id: &str,
    catalogs: &[Catalog],
    card: &Scorecard,
    evidence: &EvidenceBundle,
) -> anyhow::Result<String> {
    let (cat, control) = find_control(catalogs, control_id)?;
    let (_fw, scored) = card.control(control_id).ok_or_else(|| {
        anyhow::anyhow!(
            "control '{control_id}' is in the catalog but was not scored (check --framework)"
        )
    })?;

    let mut s = String::new();
    s.push_str(&format!("{} — {}\n", control.id, control.title));
    s.push_str(&format!(
        "{} · {} · {}\n\n",
        cat.name, control.framework_ref, scored.timeline_label
    ));
    s.push_str("Question\n");
    s.push_str(&format!("  {}\n\n", collapse(&control.question)));
    if let Some(g) = &control.guidance {
        s.push_str(&format!("Guidance\n  {}\n\n", collapse(g)));
    }

    s.push_str(&format!(
        "Verdict: {}  (self-attested: {})\n",
        scored.verdict.label(),
        scored.answer_label()
    ));
    if scored.contradicted {
        s.push_str("  contradicted by evidence (objective check overrode a green answer)\n");
    }
    if scored.evidence_backed {
        s.push_str("  evidence-backed\n");
    }
    if let Some(n) = &scored.note {
        s.push_str(&format!("  note: {n}\n"));
    }
    s.push('\n');

    if control.auto_checks.is_empty() && scored.applied_checks.is_empty() {
        s.push_str("Evidence\n  none wired — this control is self-attested unless you attach a document:\n");
        s.push_str(&format!(
            "  compass ingest --doc <file> --for {}\n\n",
            control.id
        ));
    } else {
        s.push_str("Evidence\n");
        if !control.auto_checks.is_empty() {
            s.push_str("  catalog checks: ");
            s.push_str(
                &control
                    .auto_checks
                    .iter()
                    .map(|c| c.as_str())
                    .collect::<Vec<_>>()
                    .join(", "),
            );
            s.push('\n');
        }
        if scored.applied_checks.is_empty() {
            s.push_str("  no check ran (no matching evidence file)\n");
        } else {
            for c in &scored.applied_checks {
                s.push_str(&format!(
                    "  [{}] {} — {}\n",
                    c.status.as_str(),
                    c.check,
                    c.summary
                ));
            }
        }
        if !evidence.sources.is_empty() {
            s.push_str("  files:\n");
            for src in &evidence.sources {
                s.push_str(&format!("    {src}\n"));
            }
        }
        s.push('\n');
    }

    if let Some(r) = &scored.remediation {
        s.push_str("Remediation\n");
        s.push_str(&format!("  {}\n", collapse(r)));
    }

    Ok(s)
}

fn find_control<'a>(
    catalogs: &'a [Catalog],
    control_id: &str,
) -> anyhow::Result<(&'a Catalog, &'a Control)> {
    let needle = control_id.trim();
    for cat in catalogs {
        if let Some(c) = cat.control(needle) {
            return Ok((cat, c));
        }
    }
    // Case-insensitive / substring hint.
    let lower = needle.to_ascii_lowercase();
    let mut hints: Vec<String> = catalogs
        .iter()
        .flat_map(|c| c.controls.iter())
        .filter(|c| {
            c.id.to_ascii_lowercase().contains(&lower)
                || c.title.to_ascii_lowercase().contains(&lower)
        })
        .map(|c| c.id.clone())
        .take(8)
        .collect();
    hints.sort();
    hints.dedup();
    if hints.is_empty() {
        anyhow::bail!("unknown control '{needle}'");
    }
    anyhow::bail!(
        "unknown control '{needle}'. Did you mean: {}?",
        hints.join(", ")
    )
}

fn collapse(s: &str) -> String {
    s.split_whitespace().collect::<Vec<_>>().join(" ")
}

trait AnswerLabel {
    fn answer_label(&self) -> &'static str;
}

impl AnswerLabel for ControlScore {
    fn answer_label(&self) -> &'static str {
        match self.answer {
            crate::questionnaire::Answer::Yes => "yes",
            crate::questionnaire::Answer::Partial => "partial",
            crate::questionnaire::Answer::No => "no",
            crate::questionnaire::Answer::Na => "n/a",
            crate::questionnaire::Answer::Unanswered => "unanswered",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::catalog;
    use crate::evidence::EvidenceBundle;
    use crate::questionnaire::Assessment;
    use crate::scoring;

    #[test]
    fn explains_a_bundled_control() {
        let cats = catalog::load_selection(&["eu".into()]).unwrap();
        let a = Assessment::scaffold(&cats);
        let bundle = EvidenceBundle::default();
        let card = scoring::score(&cats, &a, &bundle, 70.0);
        let text = render("art_12_traceability", &cats, &card, &bundle).unwrap();
        assert!(text.contains("art_12_traceability"));
        assert!(text.contains("Verdict:"));
        assert!(text.contains("audit_chain_integrity") || text.contains("Evidence"));
    }

    #[test]
    fn unknown_id_hints() {
        let cats = catalog::load_selection(&["eu".into()]).unwrap();
        let a = Assessment::scaffold(&cats);
        let bundle = EvidenceBundle::default();
        let card = scoring::score(&cats, &a, &bundle, 70.0);
        let err = render("traceability", &cats, &card, &bundle).unwrap_err();
        assert!(err.to_string().contains("Did you mean"));
    }
}
