//! End-to-end integration tests over the committed `demo/` fixtures.
//!
//! These exercise the full pipeline (assess → ingest → report) via both the
//! library API and the `compass` binary, and lock in the CI exit-code
//! contract: 0 pass, 1 below threshold, 2 evidence-integrity failure.

use aperion_compass::{catalog, evidence, questionnaire::Assessment, scoring};
use std::io::Write;
use std::process::Command;

const BIN: &str = env!("CARGO_BIN_EXE_compass");
const DEMO_ASSESSMENT: &str = "demo/compass-assessment.yaml";

fn demo_scorecard() -> scoring::Scorecard {
    let assessment = Assessment::from_path(DEMO_ASSESSMENT)
        .expect("demo assessment (run `cargo run --example gen_fixtures`)");
    let tokens: Vec<String> = assessment
        .frameworks
        .iter()
        .map(|f| f.framework.clone())
        .collect();
    let cats = catalog::load_selection(&tokens).unwrap();
    let bundle = evidence::run_all(&assessment.evidence);
    scoring::score(&cats, &assessment, &bundle, scoring::DEFAULT_PASS_THRESHOLD)
}

#[test]
fn demo_fixtures_score_clean_and_pass() {
    let card = demo_scorecard();
    assert!(
        !card.integrity_failure,
        "demo fixtures should verify cleanly"
    );
    // Every automated check should have run over the demo evidence.
    for key in [
        "audit_chain_integrity",
        "human_oversight",
        "action_risk_coverage",
        "agent_identity",
        "logging_completeness",
    ] {
        assert!(
            card.evidence.outcomes.contains_key(key),
            "missing check {key}"
        );
    }
    // The clean signed chain + valid Ed25519 creds must not fail.
    assert_eq!(
        card.evidence.outcomes["audit_chain_integrity"].status,
        evidence::CheckStatus::Pass
    );
    assert_eq!(
        card.evidence.outcomes["agent_identity"].status,
        evidence::CheckStatus::Pass
    );
    assert!(card.overall_score >= 60.0, "score={}", card.overall_score);
    assert_eq!(card.recommended_exit_code, scoring::EXIT_PASS);
}

#[test]
fn binary_report_writes_all_formats_and_exits_pass() {
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("report");
    let status = Command::new(BIN)
        .args([
            "report",
            "--assessment",
            DEMO_ASSESSMENT,
            "--out",
            out.to_str().unwrap(),
            "--format",
            "html,md,json",
        ])
        .status()
        .unwrap();
    assert_eq!(status.code(), Some(scoring::EXIT_PASS));
    assert!(dir.path().join("report.html").exists());
    assert!(dir.path().join("report.md").exists());
    assert!(dir.path().join("report.json").exists());
}

#[test]
fn binary_report_below_threshold_exits_1() {
    let status = Command::new(BIN)
        .args([
            "report",
            "--assessment",
            DEMO_ASSESSMENT,
            "--out",
            &tmp_out(),
            "--format",
            "json",
            "--threshold",
            "99",
        ])
        .status()
        .unwrap();
    assert_eq!(status.code(), Some(scoring::EXIT_BELOW_THRESHOLD));
}

#[test]
fn binary_report_tampered_chain_exits_2() {
    let dir = tempfile::tempdir().unwrap();
    let tampered = dir.path().join("chain.jsonl");
    let good = std::fs::read_to_string("demo/chain.jsonl").unwrap();
    // Corrupt the payload of the first entry without touching entry_hmac.
    let corrupted = good.replacen("\"T1\"", "\"T3\"", 1);
    assert_ne!(good, corrupted, "tamper should change the file");
    std::fs::write(&tampered, corrupted).unwrap();

    let status = Command::new(BIN)
        .args([
            "report",
            "--assessment",
            DEMO_ASSESSMENT,
            "--out",
            &tmp_out(),
            "--format",
            "json",
            "--chain",
            tampered.to_str().unwrap(),
            "--chain-hmac-key",
            "file:demo/chain.key",
        ])
        .status()
        .unwrap();
    assert_eq!(status.code(), Some(scoring::EXIT_INTEGRITY_FAILURE));
}

#[test]
fn binary_verify_good_is_0_tampered_is_1() {
    let good = Command::new(BIN)
        .args([
            "verify",
            "--chain",
            "demo/chain.jsonl",
            "--chain-hmac-key",
            "file:demo/chain.key",
        ])
        .status()
        .unwrap();
    assert_eq!(good.code(), Some(0));

    let dir = tempfile::tempdir().unwrap();
    let tampered = dir.path().join("chain.jsonl");
    let corrupted = std::fs::read_to_string("demo/chain.jsonl")
        .unwrap()
        .replacen("\"T1\"", "\"T3\"", 1);
    std::fs::write(&tampered, corrupted).unwrap();
    let bad = Command::new(BIN)
        .args([
            "verify",
            "--chain",
            tampered.to_str().unwrap(),
            "--chain-hmac-key",
            "file:demo/chain.key",
        ])
        .status()
        .unwrap();
    assert_eq!(bad.code(), Some(1));
}

#[test]
fn assess_defaults_then_report_roundtrips() {
    let dir = tempfile::tempdir().unwrap();
    let assessment = dir.path().join("a.yaml");

    let seed = Command::new(BIN)
        .args([
            "assess",
            "--framework",
            "imda",
            "--assessment",
            assessment.to_str().unwrap(),
            "--defaults",
        ])
        .status()
        .unwrap();
    assert!(seed.success());
    assert!(assessment.exists());

    // All-unanswered scaffold → below threshold, but a valid report.
    let out = dir.path().join("r");
    let status = Command::new(BIN)
        .args([
            "report",
            "--assessment",
            assessment.to_str().unwrap(),
            "--out",
            out.to_str().unwrap(),
            "--format",
            "md",
        ])
        .status()
        .unwrap();
    assert_eq!(status.code(), Some(scoring::EXIT_BELOW_THRESHOLD));
    assert!(dir.path().join("r").exists() || dir.path().join("r.md").exists());
}

fn tmp_out() -> String {
    let mut f = tempfile::NamedTempFile::new().unwrap();
    // Ensure a .json suffix so single-format honours the path as-is.
    writeln!(f, "{{}}").ok();
    let p = f.path().with_extension("json");
    p.to_str().unwrap().to_string()
}
