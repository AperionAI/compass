//! Diff two scored JSON reports.
//!
//! Input is the JSON `compass report --format json` already emits, so there
//! is no new schema. Output is Markdown (PR comment) or JSON.

use crate::catalog::Verdict;
use crate::evidence::CheckStatus;
use crate::scoring::Scorecard;
use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
pub struct FrameworkDelta {
    pub framework: String,
    pub old: f64,
    pub new: f64,
}

#[derive(Debug, Clone, Serialize)]
pub struct ControlFlip {
    pub framework: String,
    pub control_id: String,
    pub title: String,
    pub from: String,
    pub to: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct CheckFlip {
    pub check: String,
    pub from: String,
    pub to: String,
    pub summary: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct Diff {
    pub old_score: f64,
    pub new_score: f64,
    pub old_label: String,
    pub new_label: String,
    pub frameworks: Vec<FrameworkDelta>,
    pub flipped: Vec<ControlFlip>,
    pub checks_regressed: Vec<CheckFlip>,
    pub checks_improved: Vec<CheckFlip>,
}

impl Diff {
    pub fn score_dropped(&self) -> bool {
        (self.new_score.round() as i64) < self.old_score.round() as i64
    }
}

/// Compare two scorecards.
pub fn diff(old: &Scorecard, new: &Scorecard) -> Diff {
    let mut frameworks = Vec::new();
    for fw in &new.frameworks {
        let old_score = old
            .frameworks
            .iter()
            .find(|f| f.framework == fw.framework)
            .map(|f| f.score)
            .unwrap_or(0.0);
        frameworks.push(FrameworkDelta {
            framework: fw.framework.clone(),
            old: old_score,
            new: fw.score,
        });
    }

    let mut flipped = Vec::new();
    for (fw, ctrl) in new.iter_controls() {
        let old_v = old
            .control(&ctrl.control_id)
            .map(|(_, c)| c.verdict)
            .unwrap_or(Verdict::Absent);
        if old_v != ctrl.verdict {
            flipped.push(ControlFlip {
                framework: fw.to_string(),
                control_id: ctrl.control_id.clone(),
                title: ctrl.title.clone(),
                from: old_v.as_str().to_string(),
                to: ctrl.verdict.as_str().to_string(),
            });
        }
    }

    let mut checks_regressed = Vec::new();
    let mut checks_improved = Vec::new();
    for (key, new_o) in &new.evidence.outcomes {
        let old_status = old
            .evidence
            .outcomes
            .get(key)
            .map(|o| o.status)
            .unwrap_or(CheckStatus::NotRun);
        if old_status == new_o.status {
            continue;
        }
        let flip = CheckFlip {
            check: key.clone(),
            from: old_status.as_str().to_string(),
            to: new_o.status.as_str().to_string(),
            summary: new_o.summary.clone(),
        };
        if rank(new_o.status) < rank(old_status) {
            checks_regressed.push(flip);
        } else {
            checks_improved.push(flip);
        }
    }

    Diff {
        old_score: old.overall_score,
        new_score: new.overall_score,
        old_label: old.overall_label.clone(),
        new_label: new.overall_label.clone(),
        frameworks,
        flipped,
        checks_regressed,
        checks_improved,
    }
}

fn rank(s: CheckStatus) -> u8 {
    match s {
        CheckStatus::Pass => 3,
        CheckStatus::Warn => 2,
        CheckStatus::Fail => 1,
        CheckStatus::NotRun => 0,
    }
}

pub fn render_markdown(d: &Diff) -> String {
    let mut s = String::new();
    let old_i = d.old_score.round() as i64;
    let new_i = d.new_score.round() as i64;
    let arrow = if new_i > old_i {
        "↑"
    } else if new_i < old_i {
        "↓"
    } else {
        "→"
    };
    s.push_str("## Compass\n\n");
    s.push_str(&format!(
        "**Score {old_i} → {new_i}** {arrow}  \n{old} → {new}\n\n",
        old = d.old_label,
        new = d.new_label,
    ));

    if !d.frameworks.is_empty() {
        s.push_str("| Framework | Was | Now |\n|---|---:|---:|\n");
        for f in &d.frameworks {
            s.push_str(&format!(
                "| {} | {} | {} |\n",
                f.framework,
                f.old.round() as i64,
                f.new.round() as i64
            ));
        }
        s.push('\n');
    }

    let regressions: Vec<&ControlFlip> =
        d.flipped.iter().filter(|c| worse(&c.to, &c.from)).collect();
    let improvements: Vec<&ControlFlip> = d
        .flipped
        .iter()
        .filter(|c| !worse(&c.to, &c.from))
        .collect();

    if !regressions.is_empty() {
        s.push_str("### Regressed\n\n");
        for c in regressions {
            s.push_str(&format!(
                "- `{id}` {title}: {from} → {to}\n",
                id = c.control_id,
                title = c.title,
                from = c.from,
                to = c.to
            ));
        }
        s.push('\n');
    }
    if !improvements.is_empty() {
        s.push_str("### Improved\n\n");
        for c in improvements {
            s.push_str(&format!(
                "- `{id}` {title}: {from} → {to}\n",
                id = c.control_id,
                title = c.title,
                from = c.from,
                to = c.to
            ));
        }
        s.push('\n');
    }
    if !d.checks_regressed.is_empty() {
        s.push_str("### Evidence checks that got worse\n\n");
        for c in &d.checks_regressed {
            s.push_str(&format!(
                "- `{}`: {} → {} — {}\n",
                c.check, c.from, c.to, c.summary
            ));
        }
        s.push('\n');
    }
    if d.flipped.is_empty() && d.checks_regressed.is_empty() && d.checks_improved.is_empty() {
        s.push_str("_No control verdicts or evidence checks changed._\n");
    }
    s
}

fn worse(to: &str, from: &str) -> bool {
    rank_verdict(to) < rank_verdict(from)
}

fn rank_verdict(v: &str) -> u8 {
    match v {
        "exists" => 3,
        "partial" => 2,
        "absent" => 1,
        _ => 0,
    }
}

pub fn render_json(d: &Diff) -> anyhow::Result<String> {
    Ok(serde_json::to_string_pretty(d)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::catalog;
    use crate::evidence::EvidenceBundle;
    use crate::questionnaire::{Answer, Assessment};
    use crate::scoring;

    fn card_with(ans: Answer) -> Scorecard {
        let cats = catalog::load_selection(&["imda".into()]).unwrap();
        let mut a = Assessment::scaffold(&cats);
        if let Some(fa) = a.framework_mut("imda") {
            for c in fa.answers.iter_mut() {
                c.answer = ans;
            }
        }
        scoring::score(&cats, &a, &EvidenceBundle::default(), 70.0)
    }

    #[test]
    fn yes_to_no_shows_regression() {
        let old = card_with(Answer::Yes);
        let new = card_with(Answer::No);
        let d = diff(&old, &new);
        assert!(d.score_dropped());
        assert!(!d.flipped.is_empty());
        let md = render_markdown(&d);
        assert!(md.contains("Regressed"));
        assert!(md.contains("Score"));
    }
}
