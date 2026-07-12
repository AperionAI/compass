//! `compass` — the Aperion Compass CLI.
//!
//! Subcommands:
//!   assess   interactive questionnaire → compass-assessment.yaml
//!   ingest   register evidence files (logs, chain, approvals, credentials)
//!   report   score + render HTML/Markdown/JSON; CI exit codes
//!   serve    live local dashboard
//!   verify   standalone audit-chain verification
//!
//! Everything runs offline. No telemetry, no network.

use anyhow::{anyhow, Context, Result};
use aperion_compass::catalog::{self, BUNDLED_FRAMEWORKS};
use aperion_compass::evidence::{self, CheckStatus, EvidenceBundle};
use aperion_compass::questionnaire::{self, Assessment, EvidencePaths, DEFAULT_ASSESSMENT_PATH};
use aperion_compass::report::{self, Format};
use aperion_compass::scoring::{self, Scorecard, DEFAULT_PASS_THRESHOLD};
use clap::{Args, Parser, Subcommand};

#[derive(Debug, Parser)]
#[command(
    name = "compass",
    version,
    about = "Aperion Compass — local, offline AI governance self-assessment (EU AI Act & IMDA agentic).",
    long_about = None
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Run the interactive questionnaire and write the assessment file.
    Assess(AssessArgs),
    /// Register evidence files into an assessment for automated checks.
    Ingest(IngestArgs),
    /// Score the assessment and render a report (HTML / Markdown / JSON).
    Report(ReportArgs),
    /// Serve a live local dashboard that re-scans on demand.
    Serve(ServeArgs),
    /// Independently verify a tamper-evident audit-chain export.
    Verify(VerifyArgs),
    /// List the governance frameworks bundled into this binary.
    Frameworks,
}

/// Evidence-file flags, shared by `ingest` and `report`.
#[derive(Debug, Default, Args)]
struct EvidenceArgs {
    /// Smartflow VAS log export (JSONL or JSON array).
    #[arg(long)]
    vas: Option<String>,
    /// Tamper-evident audit-chain export (JSONL or JSON array).
    #[arg(long)]
    chain: Option<String>,
    /// HMAC key for the chain: file:<path> | base64:<v> | hex:<v> | env:<NAME>.
    #[arg(long)]
    chain_hmac_key: Option<String>,
    /// Approval-ticket export (JSONL or JSON array).
    #[arg(long)]
    approvals: Option<String>,
    /// Agent-credential export (JSONL or JSON array).
    #[arg(long)]
    credentials: Option<String>,
    /// Issuer public key / JWKS file for Ed25519 credential verification.
    #[arg(long)]
    jwks: Option<String>,
    /// Generic (non-Smartflow) request-log export (JSONL or JSON array).
    #[arg(long)]
    generic: Option<String>,
}

impl EvidenceArgs {
    /// Merge any set flags over an existing EvidencePaths (CLI wins).
    fn merge_into(&self, base: &mut EvidencePaths) {
        if self.vas.is_some() {
            base.vas = self.vas.clone();
        }
        if self.chain.is_some() {
            base.chain = self.chain.clone();
        }
        if self.chain_hmac_key.is_some() {
            base.chain_hmac_key = self.chain_hmac_key.clone();
        }
        if self.approvals.is_some() {
            base.approvals = self.approvals.clone();
        }
        if self.credentials.is_some() {
            base.credentials = self.credentials.clone();
        }
        if self.jwks.is_some() {
            base.jwks = self.jwks.clone();
        }
        if self.generic.is_some() {
            base.generic = self.generic.clone();
        }
    }
}

#[derive(Debug, Args)]
struct AssessArgs {
    /// Frameworks to assess (comma-separated ids/aliases or a catalog path).
    #[arg(long, default_value = "eu-ai-act,imda")]
    framework: String,
    /// Assessment file to create or update.
    #[arg(long, default_value = DEFAULT_ASSESSMENT_PATH)]
    assessment: String,
    /// Skip prompting; just scaffold/reconcile the file with unanswered
    /// controls (useful for seeding an assessment to edit by hand / in CI).
    #[arg(long)]
    defaults: bool,
}

#[derive(Debug, Args)]
struct IngestArgs {
    /// Assessment file to update.
    #[arg(long, default_value = DEFAULT_ASSESSMENT_PATH)]
    assessment: String,
    /// If the assessment file does not exist, scaffold it for these frameworks.
    #[arg(long)]
    framework: Option<String>,
    #[command(flatten)]
    evidence: EvidenceArgs,
}

#[derive(Debug, Args)]
struct ReportArgs {
    /// Assessment file to score.
    #[arg(long, default_value = DEFAULT_ASSESSMENT_PATH)]
    assessment: String,
    /// Override the frameworks to score (defaults to those in the assessment).
    #[arg(long)]
    framework: Option<String>,
    /// Output path (base name; per-format extensions are appended when
    /// multiple formats are requested).
    #[arg(long, default_value = "compass-report.html")]
    out: String,
    /// Comma-separated formats: html, md, json.
    #[arg(long, default_value = "html")]
    format: String,
    /// Pass threshold (0-100) for the CI exit code.
    #[arg(long, default_value_t = DEFAULT_PASS_THRESHOLD)]
    threshold: f64,
    /// Do not set a non-zero process exit code on a below-threshold / integrity
    /// result (always exit 0).
    #[arg(long)]
    no_exit_code: bool,
    #[command(flatten)]
    evidence: EvidenceArgs,
}

#[derive(Debug, Args)]
struct ServeArgs {
    /// Assessment file to score.
    #[arg(long, default_value = DEFAULT_ASSESSMENT_PATH)]
    assessment: String,
    /// Override the frameworks to score.
    #[arg(long)]
    framework: Option<String>,
    /// Port to bind on localhost.
    #[arg(long, default_value_t = 8787)]
    port: u16,
    /// Pass threshold (0-100).
    #[arg(long, default_value_t = DEFAULT_PASS_THRESHOLD)]
    threshold: f64,
    #[command(flatten)]
    evidence: EvidenceArgs,
}

#[derive(Debug, Args)]
struct VerifyArgs {
    /// Audit-chain export (JSONL or JSON array).
    #[arg(long)]
    chain: String,
    /// HMAC key: file:<path> | base64:<v> | hex:<v> | env:<NAME>.
    #[arg(long)]
    chain_hmac_key: Option<String>,
}

fn main() {
    let cli = Cli::parse();
    let code = match run(cli) {
        Ok(code) => code,
        Err(e) => {
            eprintln!("error: {e:#}");
            2
        }
    };
    std::process::exit(code);
}

fn run(cli: Cli) -> Result<i32> {
    match cli.command {
        Command::Assess(a) => cmd_assess(a),
        Command::Ingest(a) => cmd_ingest(a),
        Command::Report(a) => cmd_report(a),
        Command::Serve(a) => cmd_serve(a),
        Command::Verify(a) => cmd_verify(a),
        Command::Frameworks => {
            println!("Bundled frameworks:");
            for (id, aliases) in BUNDLED_FRAMEWORKS {
                let cat = catalog::bundled(id)?;
                println!(
                    "  {id:<12} {} — {} controls (aliases: {})",
                    cat.name,
                    cat.controls.len(),
                    aliases.join(", ")
                );
            }
            Ok(0)
        }
    }
}

fn parse_framework_tokens(s: &str) -> Vec<String> {
    s.split(',')
        .map(|t| t.trim().to_string())
        .filter(|t| !t.is_empty())
        .collect()
}

fn cmd_assess(a: AssessArgs) -> Result<i32> {
    let tokens = parse_framework_tokens(&a.framework);
    let catalogs = catalog::load_selection(&tokens)?;

    let mut assessment = if std::path::Path::new(&a.assessment).exists() {
        Assessment::from_path(&a.assessment)?
    } else {
        Assessment::scaffold(&catalogs)
    };
    assessment.reconcile_with(&catalogs);

    if a.defaults {
        assessment.save(&a.assessment)?;
        println!(
            "Scaffolded assessment (all controls unanswered) → {}",
            a.assessment
        );
        println!("Edit it by hand or re-run `compass assess` without --defaults to answer interactively.");
        return Ok(0);
    }

    questionnaire::run_interactive(&catalogs, &mut assessment)?;
    assessment.save(&a.assessment)?;
    println!("Saved assessment → {}", a.assessment);
    println!("Next: `compass ingest` to attach evidence, then `compass report`.");
    Ok(0)
}

fn cmd_ingest(a: IngestArgs) -> Result<i32> {
    let mut assessment = if std::path::Path::new(&a.assessment).exists() {
        Assessment::from_path(&a.assessment)?
    } else {
        let tokens = a
            .framework
            .as_deref()
            .map(parse_framework_tokens)
            .ok_or_else(|| {
                anyhow!(
                    "assessment file {} not found; pass --framework to scaffold one, or run `compass assess` first",
                    a.assessment
                )
            })?;
        let catalogs = catalog::load_selection(&tokens)?;
        Assessment::scaffold(&catalogs)
    };

    a.evidence.merge_into(&mut assessment.evidence);
    assessment.save(&a.assessment)?;

    if assessment.evidence.is_empty() {
        println!("No evidence flags supplied — nothing registered.");
    } else {
        println!("Registered evidence into {} :", a.assessment);
        let e = &assessment.evidence;
        for (label, val) in [
            ("vas", &e.vas),
            ("chain", &e.chain),
            ("approvals", &e.approvals),
            ("credentials", &e.credentials),
            ("jwks", &e.jwks),
            ("generic", &e.generic),
        ] {
            if let Some(v) = val {
                println!("  {label:<12} {v}");
            }
        }
        println!("Run `compass report` to score with these checks.");
    }
    Ok(0)
}

/// Resolve the catalogs to score: an explicit `--framework`, else the
/// frameworks recorded in the assessment.
fn catalogs_for(
    assessment: &Assessment,
    framework: &Option<String>,
) -> Result<Vec<catalog::Catalog>> {
    let tokens = match framework {
        Some(s) => parse_framework_tokens(s),
        None => assessment
            .frameworks
            .iter()
            .map(|f| f.framework.clone())
            .collect(),
    };
    if tokens.is_empty() {
        return Err(anyhow!("no frameworks to score; the assessment is empty"));
    }
    catalog::load_selection(&tokens)
}

fn build_scorecard(
    assessment: &Assessment,
    framework: &Option<String>,
    evidence_override: &EvidenceArgs,
    threshold: f64,
) -> Result<(Vec<catalog::Catalog>, Scorecard)> {
    let catalogs = catalogs_for(assessment, framework)?;
    let mut paths = assessment.evidence.clone();
    evidence_override.merge_into(&mut paths);
    let bundle: EvidenceBundle = if paths.is_empty() {
        EvidenceBundle::default()
    } else {
        evidence::run_all(&paths)
    };
    let card = scoring::score(&catalogs, assessment, &bundle, threshold.clamp(0.0, 100.0));
    Ok((catalogs, card))
}

fn cmd_report(a: ReportArgs) -> Result<i32> {
    let assessment = Assessment::from_path(&a.assessment).with_context(|| {
        format!(
            "load assessment (run `compass assess` first?) {}",
            a.assessment
        )
    })?;

    let (_cats, card) = build_scorecard(&assessment, &a.framework, &a.evidence, a.threshold)?;

    let formats: Vec<Format> = a
        .format
        .split(',')
        .map(|f| f.trim())
        .filter(|f| !f.is_empty())
        .map(|f| {
            Format::parse(f).ok_or_else(|| anyhow!("unknown format '{f}' (use html, md, json)"))
        })
        .collect::<Result<_>>()?;
    if formats.is_empty() {
        return Err(anyhow!("no output format selected"));
    }

    // Derive per-format output paths.
    let multi = formats.len() > 1;
    let base = strip_known_ext(&a.out);
    for fmt in &formats {
        let path = if multi {
            format!("{base}.{}", fmt.ext())
        } else {
            // Honour the user's exact --out for a single format.
            a.out.clone()
        };
        let rendered = report::render(&card, *fmt)?;
        std::fs::write(&path, rendered).with_context(|| format!("writing {path}"))?;
        println!("Wrote {} report → {path}", fmt.ext());
    }

    print_summary(&card);

    if a.no_exit_code {
        Ok(0)
    } else {
        Ok(card.recommended_exit_code)
    }
}

fn strip_known_ext(out: &str) -> String {
    for ext in [".html", ".md", ".json"] {
        if let Some(stripped) = out.strip_suffix(ext) {
            return stripped.to_string();
        }
    }
    out.to_string()
}

fn print_summary(card: &Scorecard) {
    println!();
    println!(
        "Overall: {} / 100 — {}",
        card.overall_score.round() as i64,
        card.overall_label
    );
    let c = &card.counts;
    println!(
        "  exists={} partial={} absent={} n/a={} unanswered={}",
        c.exists, c.partial, c.absent, c.not_applicable, c.unanswered
    );
    for fw in &card.frameworks {
        println!(
            "  {:<24} {} / 100 ({})",
            fw.name,
            fw.score.round() as i64,
            fw.label
        );
    }
    if card.integrity_failure {
        println!("  ⚠ EVIDENCE INTEGRITY FAILURE — an audit-chain/identity check failed.");
    }
    println!(
        "  {} (threshold {})",
        if card.passed {
            "PASS"
        } else {
            "BELOW THRESHOLD"
        },
        card.pass_threshold.round() as i64
    );
}

fn cmd_serve(a: ServeArgs) -> Result<i32> {
    // Validate up front that the assessment loads.
    let _ = Assessment::from_path(&a.assessment)
        .with_context(|| format!("load assessment {}", a.assessment))?;

    let assessment_path = a.assessment.clone();
    let framework = a.framework.clone();
    let evidence_override = a.evidence;
    let threshold = a.threshold;

    // Recompute reloads the assessment + re-runs evidence on every request so
    // the dashboard reflects edits to files without a restart.
    let recompute = move || -> Result<Scorecard> {
        let assessment = Assessment::from_path(&assessment_path)?;
        let (_cats, card) =
            build_scorecard(&assessment, &framework, &evidence_override, threshold)?;
        Ok(card)
    };

    aperion_compass::serve::run(a.port, recompute)?;
    Ok(0)
}

fn cmd_verify(a: VerifyArgs) -> Result<i32> {
    let outcome = evidence::chain::verify(&a.chain, a.chain_hmac_key.as_deref());
    println!("{}", outcome.summary);
    println!("{}", serde_json::to_string_pretty(&outcome.detail)?);
    Ok(match outcome.status {
        CheckStatus::Pass | CheckStatus::Warn => 0,
        CheckStatus::Fail => 1,
        CheckStatus::NotRun => 2,
    })
}
