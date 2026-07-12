//! Control-catalog model + loader.
//!
//! A *catalog* is one governance framework expressed as a list of *controls*,
//! each grouped under a *dimension*. Every control carries a plain-language
//! `question` (for the self-assessment), an optional set of `auto_checks` that
//! run over ingested evidence files, a `weight` for scoring, and a
//! `remediation` note shown whenever the control is not fully met.
//!
//! Verdicts use one unified four-value vocabulary across every framework:
//! **exists / partial / absent / not_applicable** (mirroring the IMDA mapping;
//! the EU Conformity Console's present/partial/not_implemented map onto the
//! first three). Catalogs are YAML and are bundled into the binary at compile
//! time, so `compass` works with zero external files. Users can still point at
//! their own catalog file to extend or override.

use anyhow::{anyhow, Context, Result};
use serde::{Deserialize, Serialize};

/// Unified conformance verdict for a control (and rolled up per dimension /
/// framework). Ordered worst-to-best for `min` style aggregation is *not*
/// implied; treat this as a label and score it via `scoring`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Verdict {
    /// Control is met / enforced.
    Exists,
    /// Present but incomplete — self-attested only, partial coverage, or a
    /// known gap.
    Partial,
    /// Not implemented.
    Absent,
    /// Out of scope for this deployment (excluded from scoring).
    NotApplicable,
}

impl Verdict {
    pub fn as_str(&self) -> &'static str {
        match self {
            Verdict::Exists => "exists",
            Verdict::Partial => "partial",
            Verdict::Absent => "absent",
            Verdict::NotApplicable => "not_applicable",
        }
    }

    pub fn label(&self) -> &'static str {
        match self {
            Verdict::Exists => "Exists",
            Verdict::Partial => "Partial",
            Verdict::Absent => "Absent",
            Verdict::NotApplicable => "N/A",
        }
    }
}

/// Automated evidence check a control can be wired to. Executed by the
/// `evidence` module over the files a user ingests; each produces a
/// [`crate::evidence::CheckOutcome`] that can confirm or adjust the
/// self-attested verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AutoCheck {
    /// Verify the tamper-evident hash chain over an exported audit log.
    AuditChainIntegrity,
    /// Compute human-oversight effectiveness (override rate, latency,
    /// outliers) over exported approval tickets.
    HumanOversight,
    /// Tier sampled tool calls T1/T2/T3 and report high-risk coverage.
    ActionRiskCoverage,
    /// Verify Ed25519 agent credentials offline against a JWKS / public key.
    AgentIdentity,
    /// Field-presence stats over exported request logs (identity, risk tier,
    /// compliance fields present or missing).
    LoggingCompleteness,
}

impl AutoCheck {
    pub fn as_str(&self) -> &'static str {
        match self {
            AutoCheck::AuditChainIntegrity => "audit_chain_integrity",
            AutoCheck::HumanOversight => "human_oversight",
            AutoCheck::ActionRiskCoverage => "action_risk_coverage",
            AutoCheck::AgentIdentity => "agent_identity",
            AutoCheck::LoggingCompleteness => "logging_completeness",
        }
    }
}

/// A grouping of controls within a framework (the framework's "dimensions",
/// "themes", or "articles blocks").
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Dimension {
    pub id: String,
    pub title: String,
    #[serde(default)]
    pub description: Option<String>,
}

fn default_weight() -> u32 {
    1
}

/// A single auditable control / requirement.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Control {
    /// Stable id, unique within the catalog (e.g. `art_12`, `imda_1_identity`).
    pub id: String,
    /// Dimension id this control rolls up under.
    pub dimension: String,
    /// Human-facing reference into the source framework (article / page).
    pub framework_ref: String,
    /// Short control title.
    pub title: String,
    /// Plain-language self-assessment question.
    pub question: String,
    /// Optional extra guidance shown alongside the question.
    #[serde(default)]
    pub guidance: Option<String>,
    /// Relative weight in scoring (default 1). Higher = more load-bearing.
    #[serde(default = "default_weight")]
    pub weight: u32,
    /// Automated checks that corroborate or adjust the answer.
    #[serde(default)]
    pub auto_checks: Vec<AutoCheck>,
    /// What to do when this control is not fully met.
    pub remediation: String,
}

/// One framework's full control catalog.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Catalog {
    /// Stable framework id used on the CLI (e.g. `eu-ai-act`, `imda`).
    pub framework: String,
    /// Display name.
    pub name: String,
    /// Framework version / edition.
    pub version: String,
    /// Citation for the source document.
    pub source: String,
    #[serde(default)]
    pub description: Option<String>,
    pub dimensions: Vec<Dimension>,
    pub controls: Vec<Control>,
}

impl Catalog {
    /// Parse a catalog from a YAML string, validating structural invariants.
    pub fn from_yaml(yaml: &str) -> Result<Catalog> {
        let cat: Catalog = serde_yaml::from_str(yaml).context("parsing catalog YAML")?;
        cat.validate()?;
        Ok(cat)
    }

    /// Load a catalog from a YAML file on disk.
    pub fn from_path(path: &str) -> Result<Catalog> {
        let yaml = std::fs::read_to_string(path)
            .with_context(|| format!("reading catalog file {path}"))?;
        Catalog::from_yaml(&yaml)
    }

    fn validate(&self) -> Result<()> {
        if self.controls.is_empty() {
            return Err(anyhow!("catalog '{}' has no controls", self.framework));
        }
        // Every control must reference a declared dimension, and ids unique.
        let mut seen = std::collections::HashSet::new();
        for c in &self.controls {
            if !seen.insert(&c.id) {
                return Err(anyhow!(
                    "catalog '{}' has duplicate control id '{}'",
                    self.framework,
                    c.id
                ));
            }
            if !self.dimensions.iter().any(|d| d.id == c.dimension) {
                return Err(anyhow!(
                    "control '{}' references unknown dimension '{}'",
                    c.id,
                    c.dimension
                ));
            }
        }
        Ok(())
    }

    /// Look up a control by id.
    pub fn control(&self, id: &str) -> Option<&Control> {
        self.controls.iter().find(|c| c.id == id)
    }

    /// Look up a dimension by id.
    pub fn dimension(&self, id: &str) -> Option<&Dimension> {
        self.dimensions.iter().find(|d| d.id == id)
    }
}

// ── Bundled catalogs ────────────────────────────────────────────────────────

const EU_AI_ACT_YAML: &str = include_str!("../catalogs/eu-ai-act.yaml");
const IMDA_AGENTIC_YAML: &str = include_str!("../catalogs/imda-agentic.yaml");

/// Every framework id that ships in the binary, with its CLI aliases.
pub const BUNDLED_FRAMEWORKS: &[(&str, &[&str])] = &[
    ("eu-ai-act", &["eu", "euaiact", "eu_ai_act"]),
    ("imda", &["imda-agentic", "imda_agentic", "sg"]),
];

/// Resolve a user-supplied framework token (id or alias) to its canonical id.
pub fn resolve_framework_id(token: &str) -> Option<&'static str> {
    let t = token.trim().to_ascii_lowercase();
    for (canon, aliases) in BUNDLED_FRAMEWORKS {
        if *canon == t || aliases.iter().any(|a| *a == t) {
            return Some(canon);
        }
    }
    None
}

/// Load a single bundled catalog by canonical id.
pub fn bundled(framework_id: &str) -> Result<Catalog> {
    let yaml = match framework_id {
        "eu-ai-act" => EU_AI_ACT_YAML,
        "imda" => IMDA_AGENTIC_YAML,
        other => return Err(anyhow!("no bundled catalog for framework '{other}'")),
    };
    Catalog::from_yaml(yaml)
}

/// Resolve and load a set of catalogs from CLI tokens (ids/aliases), or the
/// path to a user catalog file. Deduplicates while preserving order.
pub fn load_selection(tokens: &[String]) -> Result<Vec<Catalog>> {
    let mut out: Vec<Catalog> = Vec::new();
    for token in tokens {
        // Allow a path to a custom catalog file.
        if token.ends_with(".yaml") || token.ends_with(".yml") {
            let cat = Catalog::from_path(token)?;
            if !out.iter().any(|c| c.framework == cat.framework) {
                out.push(cat);
            }
            continue;
        }
        let id = resolve_framework_id(token).ok_or_else(|| {
            anyhow!(
                "unknown framework '{token}'. Available: {}",
                BUNDLED_FRAMEWORKS
                    .iter()
                    .map(|(c, _)| *c)
                    .collect::<Vec<_>>()
                    .join(", ")
            )
        })?;
        if out.iter().any(|c| c.framework == id) {
            continue;
        }
        out.push(bundled(id)?);
    }
    if out.is_empty() {
        return Err(anyhow!("no frameworks selected"));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bundled_catalogs_parse_and_validate() {
        let eu = bundled("eu-ai-act").expect("eu catalog parses");
        assert_eq!(eu.framework, "eu-ai-act");
        assert!(eu.controls.len() >= 10, "eu should have >=10 controls");

        let imda = bundled("imda").expect("imda catalog parses");
        assert_eq!(imda.framework, "imda");
        assert!(imda.controls.len() >= 10, "imda should have >=10 controls");
    }

    #[test]
    fn framework_aliases_resolve() {
        assert_eq!(resolve_framework_id("eu"), Some("eu-ai-act"));
        assert_eq!(resolve_framework_id("EU_AI_ACT"), Some("eu-ai-act"));
        assert_eq!(resolve_framework_id("imda-agentic"), Some("imda"));
        assert_eq!(resolve_framework_id("nope"), None);
    }

    #[test]
    fn selection_dedupes() {
        let sel = load_selection(&["eu".into(), "eu-ai-act".into(), "imda".into()]).unwrap();
        assert_eq!(sel.len(), 2);
    }

    #[test]
    fn rejects_unknown_dimension() {
        let yaml = r#"
framework: x
name: X
version: "1"
source: test
dimensions:
  - id: d1
    title: One
controls:
  - id: c1
    dimension: dNOPE
    framework_ref: "p.1"
    title: Bad
    question: "?"
    remediation: fix
"#;
        assert!(Catalog::from_yaml(yaml).is_err());
    }
}
