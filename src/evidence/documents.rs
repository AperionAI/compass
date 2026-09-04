//! Document attachments: path + SHA-256, no parsing.
//!
//! Annex IV and QMS evidence is paper. Compass records that a file was
//! attached to a control and still hashes to what was ingested. An auditor
//! can re-hash the same file; Compass never opens PDFs.

use super::{make_outcome, sha256_hex, CheckOutcome, CheckStatus};
use crate::catalog::AutoCheck;
use crate::questionnaire::EvidenceDocument;
use std::collections::BTreeMap;

/// Verify one attached document against the bytes currently on disk.
pub fn verify_one(doc: &EvidenceDocument) -> CheckOutcome {
    let bytes = match std::fs::read(&doc.path) {
        Ok(b) => b,
        Err(e) => {
            return make_outcome(
                AutoCheck::DocumentAttached,
                CheckStatus::Fail,
                format!("Could not read {}: {e}", doc.path),
                serde_json::json!({
                    "path": doc.path,
                    "expected_sha256": doc.sha256,
                }),
            );
        }
    };
    let got = sha256_hex(&bytes);
    if got.eq_ignore_ascii_case(&doc.sha256) {
        make_outcome(
            AutoCheck::DocumentAttached,
            CheckStatus::Pass,
            format!("Document attached, hash verified ({} bytes).", bytes.len()),
            serde_json::json!({
                "path": doc.path,
                "sha256": doc.sha256,
                "captured_at": doc.captured_at,
                "bytes": bytes.len(),
            }),
        )
    } else {
        make_outcome(
            AutoCheck::DocumentAttached,
            CheckStatus::Fail,
            format!(
                "Hash mismatch for {}: expected {}, got {got}",
                doc.path, doc.sha256
            ),
            serde_json::json!({
                "path": doc.path,
                "expected_sha256": doc.sha256,
                "actual_sha256": got,
            }),
        )
    }
}

/// Map each targeted control id → its document check outcome.
/// If several documents target the same control, Fail wins, then Warn, else Pass.
pub fn verify_all(docs: &[EvidenceDocument]) -> BTreeMap<String, CheckOutcome> {
    let mut by_control: BTreeMap<String, CheckOutcome> = BTreeMap::new();
    for doc in docs {
        let outcome = verify_one(doc);
        for id in &doc.for_controls {
            match by_control.get(id) {
                None => {
                    by_control.insert(id.clone(), outcome.clone());
                }
                Some(existing) if worse(outcome.status, existing.status) => {
                    by_control.insert(id.clone(), outcome.clone());
                }
                _ => {}
            }
        }
    }
    by_control
}

fn worse(a: CheckStatus, b: CheckStatus) -> bool {
    rank(a) > rank(b)
}

fn rank(s: CheckStatus) -> u8 {
    match s {
        CheckStatus::Fail => 3,
        CheckStatus::Warn => 2,
        CheckStatus::Pass => 1,
        CheckStatus::NotRun => 0,
    }
}

/// Hash a file and return (sha256 hex, captured_at RFC3339 from mtime).
pub fn hash_file(path: &str) -> anyhow::Result<(String, String)> {
    let bytes = std::fs::read(path)?;
    let sha = sha256_hex(&bytes);
    let captured = super::file_captured_at(path).unwrap_or_else(crate::questionnaire::now_rfc3339);
    Ok((sha, captured))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn matching_hash_passes() {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        f.write_all(b"annex-iv-body").unwrap();
        f.flush().unwrap();
        let path = f.path().to_str().unwrap().to_string();
        let (sha, captured) = hash_file(&path).unwrap();
        let doc = EvidenceDocument {
            path: path.clone(),
            sha256: sha,
            captured_at: captured,
            for_controls: vec!["art_11_annex_iv".into()],
        };
        let map = verify_all(&[doc]);
        assert_eq!(map["art_11_annex_iv"].status, CheckStatus::Pass);
    }

    #[test]
    fn mutated_file_fails() {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        f.write_all(b"original").unwrap();
        f.flush().unwrap();
        let path = f.path().to_str().unwrap().to_string();
        let doc = EvidenceDocument {
            path: path.clone(),
            sha256: "deadbeef".into(),
            captured_at: "2026-01-01T00:00:00Z".into(),
            for_controls: vec!["art_17_qms".into()],
        };
        let o = verify_one(&doc);
        assert_eq!(o.status, CheckStatus::Fail);
        assert!(o.summary.contains("Hash mismatch"));
    }
}
