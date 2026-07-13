//! Tamper-evident audit-chain verification.
//!
//! Forked from Smartflow's open-source `audit-verifier` (and byte-compatible
//! with `crate::audit_chain`): strip `entry_hmac`, recursively sort object
//! keys, `serde_json::to_string`, HMAC-SHA256 with the key, compare; and each
//! entry's `prev_hash` must equal the previous entry's `entry_hmac`
//! (`genesis` for seq 1, `unsigned:<seq>` when no key is used).
//!
//! Exposed as the `audit_chain_integrity` check: Pass on a clean signed chain,
//! Fail on any tampering, Warn when only linkage (no HMAC key) could be checked.

use super::{make_outcome, CheckOutcome, CheckStatus};
use crate::catalog::AutoCheck;
use base64::Engine;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::collections::BTreeMap;

type HmacSha256 = Hmac<Sha256>;

/// Verify a chain export at `path`, optionally with an HMAC key spec
/// (`file:` | `base64:` | `hex:` | `env:` | bare value).
pub fn verify(path: &str, hmac_key: Option<&str>) -> CheckOutcome {
    let raw = match std::fs::read_to_string(path) {
        Ok(r) => r,
        Err(e) => {
            return make_outcome(
                AutoCheck::AuditChainIntegrity,
                CheckStatus::NotRun,
                format!("Could not read chain file {path}: {e}"),
                serde_json::json!({}),
            )
        }
    };
    let entries = match parse_entries(&raw) {
        Ok(e) if !e.is_empty() => e,
        Ok(_) => {
            return make_outcome(
                AutoCheck::AuditChainIntegrity,
                CheckStatus::NotRun,
                "Chain file contained no entries.",
                serde_json::json!({}),
            )
        }
        Err(e) => {
            return make_outcome(
                AutoCheck::AuditChainIntegrity,
                CheckStatus::NotRun,
                format!("Could not parse chain: {e}"),
                serde_json::json!({}),
            )
        }
    };

    let key = hmac_key.and_then(load_key_spec);

    let mut by_seq: BTreeMap<u64, serde_json::Value> = BTreeMap::new();
    let mut duplicates = Vec::new();
    let mut missing_seq = 0u64;
    for e in &entries {
        match e.get("seq").and_then(|v| v.as_u64()) {
            Some(seq) => {
                if by_seq.insert(seq, e.clone()).is_some() {
                    duplicates.push(seq);
                }
            }
            None => missing_seq += 1,
        }
    }

    let from = *by_seq.keys().next().unwrap();
    let to = *by_seq.keys().next_back().unwrap();

    let mut hmac_mismatches: Vec<u64> = Vec::new();
    let mut prev_breaks: Vec<u64> = Vec::new();
    let mut missing: Vec<u64> = Vec::new();
    let mut unsigned = 0u64;
    let mut checked = 0u64;

    let mut expected_prev: Option<String> = if from == 1 {
        Some("genesis".to_string())
    } else {
        None // partial range; accept whatever seq `from` declares
    };

    for seq in from..=to {
        let entry = match by_seq.get(&seq) {
            Some(e) => e,
            None => {
                missing.push(seq);
                expected_prev = None;
                continue;
            }
        };
        checked += 1;

        if let Some(exp) = &expected_prev {
            match entry.get("prev_hash").and_then(|v| v.as_str()) {
                Some(actual) if actual == exp => {}
                _ => prev_breaks.push(seq),
            }
        }

        let stored = entry.get("entry_hmac").and_then(|v| v.as_str());
        match (&key, stored) {
            (Some(k), Some(s)) => {
                let canonical = canonical_for_hmac(entry);
                if hmac_hex(k, &canonical) != s {
                    hmac_mismatches.push(seq);
                }
            }
            _ => unsigned += 1,
        }

        expected_prev = Some(
            stored
                .map(|s| s.to_string())
                .unwrap_or_else(|| format!("unsigned:{seq}")),
        );
    }

    let tampered = !missing.is_empty()
        || !hmac_mismatches.is_empty()
        || !prev_breaks.is_empty()
        || !duplicates.is_empty()
        || missing_seq > 0;

    let detail = serde_json::json!({
        "from_seq": from,
        "to_seq": to,
        "entries_checked": checked,
        "unsigned_entries": unsigned,
        "signed": key.is_some(),
        "missing": trunc(&missing),
        "duplicates": trunc(&duplicates),
        "hmac_mismatches": trunc(&hmac_mismatches),
        "prev_hash_breaks": trunc(&prev_breaks),
        "entries_without_seq": missing_seq,
    });

    if tampered {
        return make_outcome(
            AutoCheck::AuditChainIntegrity,
            CheckStatus::Fail,
            format!(
                "Tampering detected: {} hmac mismatch(es), {} link break(s), {} missing, {} duplicate(s).",
                hmac_mismatches.len(),
                prev_breaks.len(),
                missing.len(),
                duplicates.len()
            ),
            detail,
        );
    }

    if key.is_none() {
        return make_outcome(
            AutoCheck::AuditChainIntegrity,
            CheckStatus::Warn,
            format!(
                "Linkage verified across seq {from}..{to} ({checked} entries), but no HMAC key supplied — signatures unverified. Pass --chain-hmac-key to fully verify."
            ),
            detail,
        );
    }

    make_outcome(
        AutoCheck::AuditChainIntegrity,
        CheckStatus::Pass,
        format!("Chain integrity verified: {checked} entries, signatures + linkage intact (seq {from}..{to})."),
        detail,
    )
}

fn trunc(v: &[u64]) -> Vec<u64> {
    v.iter().take(20).copied().collect()
}

fn parse_entries(raw: &str) -> anyhow::Result<Vec<serde_json::Value>> {
    let trimmed = raw.trim_start();
    if trimmed.starts_with('[') {
        return Ok(serde_json::from_str(raw)?);
    }
    let mut out = Vec::new();
    for line in raw.lines() {
        let s = line.trim();
        if s.is_empty() || s.starts_with('#') {
            continue;
        }
        out.push(serde_json::from_str(s)?);
    }
    Ok(out)
}

/// Canonicalise an entry for HMAC: drop `entry_hmac`, recursively sort object
/// keys, serialise compactly. Shared with the recorder so written chains are
/// byte-compatible with what this verifier expects.
pub(crate) fn canonical_for_hmac(entry: &serde_json::Value) -> String {
    let mut v = entry.clone();
    if let Some(obj) = v.as_object_mut() {
        obj.remove("entry_hmac");
    }
    serde_json::to_string(&sort_value(&v)).unwrap_or_default()
}

fn sort_value(v: &serde_json::Value) -> serde_json::Value {
    match v {
        serde_json::Value::Object(m) => {
            let bt: BTreeMap<String, serde_json::Value> = m
                .iter()
                .map(|(k, val)| (k.clone(), sort_value(val)))
                .collect();
            serde_json::Value::Object(bt.into_iter().collect())
        }
        serde_json::Value::Array(a) => serde_json::Value::Array(a.iter().map(sort_value).collect()),
        _ => v.clone(),
    }
}

pub(crate) fn hmac_hex(key: &[u8], msg: &str) -> String {
    let mut mac = HmacSha256::new_from_slice(key).expect("hmac accepts any key length");
    mac.update(msg.as_bytes());
    hex::encode(mac.finalize().into_bytes())
}

pub(crate) fn load_key_spec(spec: &str) -> Option<Vec<u8>> {
    if let Some(rest) = spec.strip_prefix("file:") {
        let bytes = std::fs::read(rest).ok()?;
        // If file contents look like text, try loose decode; else raw bytes.
        if let Ok(s) = std::str::from_utf8(&bytes) {
            let s = s.trim();
            if !s.is_empty() && s.chars().all(|c| c.is_ascii() && !c.is_control()) {
                return Some(decode_loose(s));
            }
        }
        Some(bytes)
    } else if let Some(rest) = spec.strip_prefix("base64:") {
        base64::engine::general_purpose::STANDARD
            .decode(rest.trim())
            .ok()
    } else if let Some(rest) = spec.strip_prefix("hex:") {
        hex::decode(rest.trim()).ok()
    } else if let Some(rest) = spec.strip_prefix("env:") {
        std::env::var(rest).ok().map(|v| decode_loose(&v))
    } else {
        Some(decode_loose(spec))
    }
}

fn decode_loose(v: &str) -> Vec<u8> {
    if let Ok(b) = base64::engine::general_purpose::STANDARD.decode(v.as_bytes()) {
        if b.len() >= 16 {
            return b;
        }
    }
    if let Ok(b) = hex::decode(v) {
        if b.len() >= 16 {
            return b;
        }
    }
    v.as_bytes().to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn signed_entry(
        seq: u64,
        prev: &str,
        key: &[u8],
        extra: serde_json::Value,
    ) -> serde_json::Value {
        let mut e = serde_json::json!({"seq": seq, "prev_hash": prev, "payload": extra});
        let mac = hmac_hex(key, &canonical_for_hmac(&e));
        e.as_object_mut()
            .unwrap()
            .insert("entry_hmac".into(), serde_json::json!(mac));
        e
    }

    fn write_tmp(lines: &[serde_json::Value]) -> tempfile::NamedTempFile {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        for l in lines {
            writeln!(f, "{}", serde_json::to_string(l).unwrap()).unwrap();
        }
        f
    }

    #[test]
    fn clean_signed_chain_passes() {
        let key = b"compass-test-key-32-bytes-long!!";
        let e1 = signed_entry(1, "genesis", key, serde_json::json!({"a": 1}));
        let p1 = e1["entry_hmac"].as_str().unwrap().to_string();
        let e2 = signed_entry(2, &p1, key, serde_json::json!({"b": 2}));
        let f = write_tmp(&[e1, e2]);
        let spec = format!(
            "base64:{}",
            base64::engine::general_purpose::STANDARD.encode(key)
        );
        let o = verify(f.path().to_str().unwrap(), Some(&spec));
        assert_eq!(o.status, CheckStatus::Pass, "summary={}", o.summary);
    }

    #[test]
    fn mutation_is_detected() {
        let key = b"compass-test-key-32-bytes-long!!";
        let mut e1 = signed_entry(1, "genesis", key, serde_json::json!({"a": 1}));
        e1.as_object_mut()
            .unwrap()
            .insert("payload".into(), serde_json::json!({"a": 999}));
        let f = write_tmp(&[e1]);
        let spec = format!(
            "base64:{}",
            base64::engine::general_purpose::STANDARD.encode(key)
        );
        let o = verify(f.path().to_str().unwrap(), Some(&spec));
        assert_eq!(o.status, CheckStatus::Fail);
    }

    #[test]
    fn no_key_is_warn() {
        let key = b"compass-test-key-32-bytes-long!!";
        let e1 = signed_entry(1, "genesis", key, serde_json::json!({}));
        let f = write_tmp(&[e1]);
        let o = verify(f.path().to_str().unwrap(), None);
        assert_eq!(o.status, CheckStatus::Warn);
    }
}
