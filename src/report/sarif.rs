//! SARIF 2.1.0 so GitHub code scanning (and other SARIF consumers) can
//! annotate a PR with Compass gaps.

use crate::catalog::Verdict;
use crate::scoring::Scorecard;
use anyhow::{Context, Result};
use serde_json::json;

pub fn render(card: &Scorecard) -> Result<String> {
    let mut rules = Vec::new();
    let mut results = Vec::new();

    for fw in &card.frameworks {
        for dim in &fw.dimensions {
            for cs in &dim.controls {
                let rule_id = format!("{}:{}", fw.framework, cs.control_id);
                rules.push(json!({
                    "id": rule_id,
                    "name": cs.control_id,
                    "shortDescription": { "text": cs.title },
                    "fullDescription": { "text": cs.framework_ref },
                    "helpUri": "https://docs.aperion.ai",
                    "properties": {
                        "framework": fw.framework,
                        "dimension": dim.id,
                        "timeline": cs.timeline_label,
                    }
                }));

                let level = match cs.verdict {
                    Verdict::Exists | Verdict::NotApplicable => continue,
                    Verdict::Partial => "warning",
                    Verdict::Absent => "error",
                };
                let text = match &cs.remediation {
                    Some(r) => format!("{}: {}", cs.title, r),
                    None => cs.title.clone(),
                };
                results.push(json!({
                    "ruleId": rule_id,
                    "level": level,
                    "message": { "text": text },
                    "locations": [{
                        "physicalLocation": {
                            "artifactLocation": { "uri": "compass-assessment.yaml" },
                            "region": { "startLine": 1 }
                        }
                    }]
                }));
            }
        }
    }

    // Dedup rules that got pushed for Exists too — we pushed a rule for every
    // control so the driver catalog is complete, then skipped Exists/NA in
    // results. That's intentional.
    let doc = json!({
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "Aperion Compass",
                    "version": card.tool_version,
                    "informationUri": "https://github.com/AperionAI/compass",
                    "rules": rules,
                }
            },
            "results": results,
            "properties": {
                "overallScore": card.overall_score.round() as i64,
                "passed": card.passed,
            }
        }]
    });

    serde_json::to_string_pretty(&doc).context("serialising SARIF")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{catalog, evidence::EvidenceBundle, questionnaire::Assessment, scoring};

    #[test]
    fn sarif_is_v2_and_reports_absent_as_error() {
        let cats = catalog::load_selection(&["eu".into()]).unwrap();
        let a = Assessment::scaffold(&cats);
        let card = scoring::score(&cats, &a, &EvidenceBundle::default(), 70.0);
        let s = render(&card).unwrap();
        let v: serde_json::Value = serde_json::from_str(&s).unwrap();
        assert_eq!(v["version"], "2.1.0");
        let results = v["runs"][0]["results"].as_array().unwrap();
        assert!(results.iter().any(|r| r["level"] == "error"));
        assert!(s.contains("art_50_disclosure"));
    }
}
