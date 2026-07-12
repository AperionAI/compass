//! The assessment file model + the interactive questionnaire.
//!
//! An *assessment* (`compass-assessment.yaml`) is the re-runnable, editable,
//! diffable record of a self-assessment: organisation metadata, per-framework
//! answers, and the paths of any evidence files registered with `ingest`. It
//! is the "assessment as code" artifact -- commit it, diff it across quarters,
//! gate CI on it.
//!
//! The questionnaire loop reads plain stdin (no TTY dependency) so it works in
//! a bare terminal. All the file model + answer mapping is pure and unit
//! tested; only `run_interactive` touches stdio.

use crate::catalog::{Catalog, Verdict};
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::io::Write;

/// The current on-disk assessment schema version.
pub const ASSESSMENT_VERSION: u32 = 1;

/// Default assessment filename.
pub const DEFAULT_ASSESSMENT_PATH: &str = "compass-assessment.yaml";

/// A self-attested answer to one control question.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Answer {
    /// Fully in place → Exists.
    Yes,
    /// Partially in place → Partial.
    Partial,
    /// Not in place → Absent.
    No,
    /// Out of scope → NotApplicable (excluded from scoring).
    Na,
    /// Not yet answered → scored as Absent, but flagged as unanswered.
    Unanswered,
}

impl Answer {
    /// Map a self-attested answer to its base verdict (before auto-checks
    /// adjust it).
    pub fn to_verdict(self) -> Verdict {
        match self {
            Answer::Yes => Verdict::Exists,
            Answer::Partial => Verdict::Partial,
            Answer::No => Verdict::Absent,
            Answer::Na => Verdict::NotApplicable,
            Answer::Unanswered => Verdict::Absent,
        }
    }

    /// Parse one keystroke / word of user input. Returns `None` for "keep /
    /// skip" (leave the current answer untouched).
    pub fn parse_input(s: &str) -> Option<Answer> {
        match s.trim().to_ascii_lowercase().as_str() {
            "y" | "yes" => Some(Answer::Yes),
            "p" | "partial" => Some(Answer::Partial),
            "n" | "no" => Some(Answer::No),
            "a" | "na" | "n/a" => Some(Answer::Na),
            _ => None, // "", "s", "skip", anything else → keep current
        }
    }
}

/// One control's recorded answer plus an optional evidence note.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ControlAnswer {
    pub control_id: String,
    pub answer: Answer,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

/// All answers for one framework within an assessment.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FrameworkAssessment {
    pub framework: String,
    pub answers: Vec<ControlAnswer>,
}

impl FrameworkAssessment {
    pub fn answer_for(&self, control_id: &str) -> Option<&ControlAnswer> {
        self.answers.iter().find(|a| a.control_id == control_id)
    }

    fn upsert(&mut self, control_id: &str, answer: Answer, note: Option<String>) {
        if let Some(existing) = self.answers.iter_mut().find(|a| a.control_id == control_id) {
            existing.answer = answer;
            if note.is_some() {
                existing.note = note;
            }
        } else {
            self.answers.push(ControlAnswer {
                control_id: control_id.to_string(),
                answer,
                note,
            });
        }
    }
}

/// Paths to evidence files registered with `ingest`. Stored so `report` can
/// re-run the automated checks without re-specifying every path.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct EvidencePaths {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vas: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub chain: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub chain_hmac_key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approvals: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credentials: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jwks: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub generic: Option<String>,
}

impl EvidencePaths {
    pub fn is_empty(&self) -> bool {
        self.vas.is_none()
            && self.chain.is_none()
            && self.approvals.is_none()
            && self.credentials.is_none()
            && self.generic.is_none()
    }
}

/// The full assessment record persisted to `compass-assessment.yaml`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Assessment {
    pub version: u32,
    pub generated_at: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub organization: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub system_name: Option<String>,
    pub frameworks: Vec<FrameworkAssessment>,
    #[serde(default)]
    pub evidence: EvidencePaths,
}

impl Assessment {
    /// Build a fresh assessment scaffold from the selected catalogs with every
    /// control `Unanswered`.
    pub fn scaffold(catalogs: &[Catalog]) -> Assessment {
        let frameworks = catalogs
            .iter()
            .map(|cat| FrameworkAssessment {
                framework: cat.framework.clone(),
                answers: cat
                    .controls
                    .iter()
                    .map(|c| ControlAnswer {
                        control_id: c.id.clone(),
                        answer: Answer::Unanswered,
                        note: None,
                    })
                    .collect(),
            })
            .collect();
        Assessment {
            version: ASSESSMENT_VERSION,
            generated_at: now_rfc3339(),
            organization: None,
            system_name: None,
            frameworks,
            evidence: EvidencePaths::default(),
        }
    }

    pub fn from_yaml(yaml: &str) -> Result<Assessment> {
        serde_yaml::from_str(yaml).context("parsing assessment YAML")
    }

    pub fn from_path(path: &str) -> Result<Assessment> {
        let yaml = std::fs::read_to_string(path)
            .with_context(|| format!("reading assessment file {path}"))?;
        Assessment::from_yaml(&yaml)
    }

    pub fn to_yaml(&self) -> Result<String> {
        serde_yaml::to_string(self).context("serialising assessment")
    }

    pub fn save(&self, path: &str) -> Result<()> {
        std::fs::write(path, self.to_yaml()?)
            .with_context(|| format!("writing assessment file {path}"))
    }

    pub fn framework_mut(&mut self, framework: &str) -> Option<&mut FrameworkAssessment> {
        self.frameworks
            .iter_mut()
            .find(|f| f.framework == framework)
    }

    pub fn framework(&self, framework: &str) -> Option<&FrameworkAssessment> {
        self.frameworks.iter().find(|f| f.framework == framework)
    }

    /// Ensure the assessment contains a section for every selected catalog,
    /// adding any missing controls as `Unanswered` (so re-running `assess`
    /// after a catalog update surfaces the new questions).
    pub fn reconcile_with(&mut self, catalogs: &[Catalog]) {
        for cat in catalogs {
            if self.framework(&cat.framework).is_none() {
                self.frameworks.push(FrameworkAssessment {
                    framework: cat.framework.clone(),
                    answers: Vec::new(),
                });
            }
            let fa = self.framework_mut(&cat.framework).unwrap();
            for c in &cat.controls {
                if fa.answer_for(&c.id).is_none() {
                    fa.answers.push(ControlAnswer {
                        control_id: c.id.clone(),
                        answer: Answer::Unanswered,
                        note: None,
                    });
                }
            }
        }
    }
}

pub fn now_rfc3339() -> String {
    chrono::Utc::now().to_rfc3339()
}

// ── Interactive questionnaire (stdio) ───────────────────────────────────────

fn read_line() -> Result<String> {
    let mut buf = String::new();
    std::io::stdin()
        .read_line(&mut buf)
        .context("reading stdin")?;
    Ok(buf.trim_end_matches(['\n', '\r']).to_string())
}

fn prompt(msg: &str) -> Result<String> {
    print!("{msg}");
    std::io::stdout().flush().ok();
    read_line()
}

/// Run the interactive questionnaire over the selected catalogs, seeding from
/// (and updating) `assessment`. Controls already answered show their current
/// value and can be kept by pressing Enter.
pub fn run_interactive(catalogs: &[Catalog], assessment: &mut Assessment) -> Result<()> {
    assessment.reconcile_with(catalogs);

    println!("\nAperion Compass — governance self-assessment");
    println!("Answer each control: [y]es · [p]artial · [n]o · n[a] (not applicable) · Enter to keep/skip.");
    println!("After the answer you can type a short evidence note (or Enter to leave blank).\n");

    // Optional metadata (only ask if not already set).
    if assessment.organization.is_none() {
        let org = prompt("Organisation name (optional): ")?;
        if !org.is_empty() {
            assessment.organization = Some(org);
        }
    }
    if assessment.system_name.is_none() {
        let sys = prompt("AI system / product name (optional): ")?;
        if !sys.is_empty() {
            assessment.system_name = Some(sys);
        }
    }

    for cat in catalogs {
        println!("\n=== {} ({}) ===", cat.name, cat.version);
        let mut last_dim = String::new();
        // Clone the framework section out, mutate, then write back to avoid
        // holding a mutable borrow across the catalog iteration.
        for control in &cat.controls {
            if control.dimension != last_dim {
                if let Some(d) = cat.dimension(&control.dimension) {
                    println!("\n-- {} --", d.title);
                }
                last_dim = control.dimension.clone();
            }

            let current = assessment
                .framework(&cat.framework)
                .and_then(|f| f.answer_for(&control.id))
                .map(|a| a.answer)
                .unwrap_or(Answer::Unanswered);

            println!("\n[{}] {}", control.framework_ref, control.title);
            println!("  {}", control.question.trim());
            if let Some(g) = &control.guidance {
                println!("  ({})", g.trim());
            }
            let cur_label = match current {
                Answer::Unanswered => "unanswered".to_string(),
                other => format!("{:?}", other).to_lowercase(),
            };
            let ans_raw = prompt(&format!("  answer [current: {cur_label}] > "))?;

            let new_answer = Answer::parse_input(&ans_raw);
            if let Some(a) = new_answer {
                let note_raw = prompt("  evidence note (optional) > ")?;
                let note = if note_raw.is_empty() {
                    None
                } else {
                    Some(note_raw)
                };
                if let Some(fa) = assessment.framework_mut(&cat.framework) {
                    fa.upsert(&control.id, a, note);
                }
            }
            // else: keep current answer untouched.
        }
    }

    assessment.generated_at = now_rfc3339();
    println!("\nAssessment complete.");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::catalog;

    #[test]
    fn answer_verdict_mapping() {
        assert_eq!(Answer::Yes.to_verdict(), Verdict::Exists);
        assert_eq!(Answer::Partial.to_verdict(), Verdict::Partial);
        assert_eq!(Answer::No.to_verdict(), Verdict::Absent);
        assert_eq!(Answer::Na.to_verdict(), Verdict::NotApplicable);
        assert_eq!(Answer::Unanswered.to_verdict(), Verdict::Absent);
    }

    #[test]
    fn parse_input_variants() {
        assert_eq!(Answer::parse_input("y"), Some(Answer::Yes));
        assert_eq!(Answer::parse_input("YES"), Some(Answer::Yes));
        assert_eq!(Answer::parse_input("p"), Some(Answer::Partial));
        assert_eq!(Answer::parse_input("no"), Some(Answer::No));
        assert_eq!(Answer::parse_input("na"), Some(Answer::Na));
        assert_eq!(Answer::parse_input("n/a"), Some(Answer::Na));
        assert_eq!(Answer::parse_input(""), None);
        assert_eq!(Answer::parse_input("skip"), None);
    }

    #[test]
    fn scaffold_and_roundtrip() {
        let cats = catalog::load_selection(&["eu".into(), "imda".into()]).unwrap();
        let a = Assessment::scaffold(&cats);
        assert_eq!(a.frameworks.len(), 2);
        let yaml = a.to_yaml().unwrap();
        let back = Assessment::from_yaml(&yaml).unwrap();
        assert_eq!(back.frameworks.len(), 2);
        assert!(back
            .framework("eu-ai-act")
            .unwrap()
            .answers
            .iter()
            .all(|a| a.answer == Answer::Unanswered));
    }

    #[test]
    fn reconcile_adds_missing_controls() {
        let cats = catalog::load_selection(&["eu".into()]).unwrap();
        let mut a = Assessment {
            version: 1,
            generated_at: now_rfc3339(),
            organization: None,
            system_name: None,
            frameworks: vec![FrameworkAssessment {
                framework: "eu-ai-act".into(),
                answers: vec![], // empty — everything missing
            }],
            evidence: EvidencePaths::default(),
        };
        a.reconcile_with(&cats);
        let n = a.framework("eu-ai-act").unwrap().answers.len();
        assert_eq!(n, cats[0].controls.len());
    }
}
