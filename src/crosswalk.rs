//! Framework crosswalk — answer once, score everywhere.
//!
//! Bundled YAML groups equivalent control ids across catalogs. When a
//! control is `Unanswered`, scoring looks up any answered equivalent and
//! inherits that verdict, tagging the scorecard note so the report is honest.

use crate::questionnaire::{Answer, Assessment};
use anyhow::{Context, Result};
use serde::Deserialize;

const CROSSWALK_YAML: &str = include_str!("../catalogs/crosswalk.yaml");

#[derive(Debug, Deserialize)]
struct File {
    #[allow(dead_code)]
    version: u32,
    links: Vec<Link>,
}

#[derive(Debug, Deserialize)]
struct Link {
    reason: String,
    ids: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct Crosswalk {
    groups: Vec<(String, Vec<String>)>,
}

impl Crosswalk {
    pub fn bundled() -> Result<Crosswalk> {
        let f: File = serde_yaml::from_str(CROSSWALK_YAML).context("parsing crosswalk YAML")?;
        Ok(Crosswalk {
            groups: f.links.into_iter().map(|l| (l.reason, l.ids)).collect(),
        })
    }

    /// If `control_id` is unanswered, return `(answer, source_id)` from the
    /// first answered equivalent in the same group.
    pub fn inherit(&self, control_id: &str, assessment: &Assessment) -> Option<(Answer, String)> {
        let group = self
            .groups
            .iter()
            .find(|(_, ids)| ids.iter().any(|i| i == control_id))?;
        for other in &group.1 {
            if other == control_id {
                continue;
            }
            for fa in &assessment.frameworks {
                if let Some(a) = fa.answer_for(other) {
                    if a.answer != Answer::Unanswered {
                        return Some((a.answer, other.clone()));
                    }
                }
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::catalog;
    use crate::questionnaire::Assessment;

    #[test]
    fn bundled_crosswalk_parses_and_maps_logging() {
        let w = Crosswalk::bundled().unwrap();
        let cats = catalog::load_selection(&["eu".into(), "imda".into()]).unwrap();
        let mut a = Assessment::scaffold(&cats);
        if let Some(fa) = a.framework_mut("eu-ai-act") {
            if let Some(ans) = fa
                .answers
                .iter_mut()
                .find(|x| x.control_id == "art_12_logging")
            {
                ans.answer = Answer::Yes;
            }
        }
        let (ans, src) = w
            .inherit("log_all_interactions", &a)
            .expect("logging should inherit");
        assert_eq!(ans, Answer::Yes);
        assert_eq!(src, "art_12_logging");
    }

    #[test]
    fn native_unanswered_with_no_peer_is_none() {
        let w = Crosswalk::bundled().unwrap();
        let cats = catalog::load_selection(&["imda".into()]).unwrap();
        let a = Assessment::scaffold(&cats);
        assert!(w.inherit("log_all_interactions", &a).is_none());
    }
}
