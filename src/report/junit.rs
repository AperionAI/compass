//! JUnit XML so `compass report` can annotate a CI job.

use crate::catalog::Verdict;
use crate::scoring::{ControlScore, Scorecard};
use std::fmt::Write;

pub fn render(card: &Scorecard) -> String {
    let cases: Vec<&ControlScore> = card
        .frameworks
        .iter()
        .flat_map(|f| f.dimensions.iter())
        .flat_map(|d| d.controls.iter())
        .collect();

    let tests = cases.len();
    let failures = cases
        .iter()
        .filter(|c| matches!(c.verdict, Verdict::Absent | Verdict::Partial))
        .count();
    let skipped = cases
        .iter()
        .filter(|c| c.verdict == Verdict::NotApplicable)
        .count();

    let mut s = String::new();
    writeln!(s, r#"<?xml version="1.0" encoding="UTF-8"?>"#).ok();
    writeln!(
        s,
        r#"<testsuite name="aperion-compass" tests="{tests}" failures="{failures}" skipped="{skipped}" hostname="localhost">"#
    )
    .ok();
    writeln!(s, r#"  <properties>"#).ok();
    writeln!(
        s,
        r#"    <property name="overall_score" value="{}"/>"#,
        card.overall_score.round() as i64
    )
    .ok();
    writeln!(
        s,
        r#"    <property name="tool_version" value="{}"/>"#,
        xml(card.tool_version.as_str())
    )
    .ok();
    writeln!(s, r#"  </properties>"#).ok();

    for fw in &card.frameworks {
        for dim in &fw.dimensions {
            for cs in &dim.controls {
                let classname = format!("{}.{}", fw.framework, dim.id);
                write!(
                    s,
                    r#"  <testcase classname="{}" name="{}" time="0">"#,
                    xml(&classname),
                    xml(&cs.control_id)
                )
                .ok();
                match cs.verdict {
                    Verdict::Exists => {
                        writeln!(s, "</testcase>").ok();
                    }
                    Verdict::NotApplicable => {
                        writeln!(
                            s,
                            "\n    <skipped message=\"not applicable\"/>\n  </testcase>"
                        )
                        .ok();
                    }
                    Verdict::Partial | Verdict::Absent => {
                        let msg = format!("{} — {}", cs.verdict.as_str(), cs.title);
                        let body = cs.remediation.as_deref().unwrap_or(cs.title.as_str());
                        writeln!(
                            s,
                            "\n    <failure message=\"{}\">{}</failure>\n  </testcase>",
                            xml(&msg),
                            xml(body)
                        )
                        .ok();
                    }
                }
            }
        }
    }

    writeln!(s, "</testsuite>").ok();
    s
}

fn xml(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            _ => out.push(c),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{catalog, evidence::EvidenceBundle, questionnaire::Assessment, scoring};

    #[test]
    fn junit_has_testsuite_and_failures_for_unanswered() {
        let cats = catalog::load_selection(&["eu".into()]).unwrap();
        let a = Assessment::scaffold(&cats);
        let card = scoring::score(&cats, &a, &EvidenceBundle::default(), 70.0);
        let xml = render(&card);
        assert!(xml.contains("<testsuite"));
        assert!(xml.contains("art_50_disclosure"));
        assert!(xml.contains("<failure"));
    }
}
