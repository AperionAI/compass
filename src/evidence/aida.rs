//! Offline agent-identity verification (AIDA Ed25519 credentials).
//!
//! Reproduces the canonical payload and verification from Smartflow's
//! `src/aida/crypto.rs` so a partner or auditor can verify exported agent
//! credentials with only the issuer's **public** key (a JWKS or raw base64
//! key) — no shared secret, no running gateway.
//!
//! The `agent_identity` check reports, per credential: signature validity
//! (Ed25519), expiry, and revocation. HMAC credentials cannot be verified
//! offline (they need the server secret) and are reported as unverifiable.

use super::{make_outcome, CheckOutcome, CheckStatus};
use crate::catalog::AutoCheck;
use base64::Engine;
use chrono::Utc;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::Serialize;
use serde_json::Value;

/// Rebuild the canonical byte payload the Ed25519 signature covers. Mirrors
/// `crate::aida::crypto::canonical_payload` exactly.
pub fn canonical_payload(
    cred_id: &str,
    agent_id: &str,
    principal_id: &str,
    issued_ts: i64,
    expires_ts: i64,
    scopes_csv: &str,
    max_transaction_usd: Option<f64>,
) -> Vec<u8> {
    let max_txn = match max_transaction_usd {
        Some(v) => format!("{:.4}", v),
        None => "none".to_string(),
    };
    format!(
        "aida-cred-v1\n{cred_id}\n{agent_id}\n{principal_id}\n{issued_ts}\n{expires_ts}\n{scopes_csv}\n{max_txn}"
    )
    .into_bytes()
}

/// Convert a scope JSON value to its `Display` string (matching `AgentScope`).
fn scope_to_str(v: &Value) -> Option<String> {
    match v {
        Value::String(s) => Some(s.clone()),
        Value::Object(o) => o
            .get("custom")
            .and_then(|c| c.as_str())
            .map(|c| format!("custom:{c}")),
        _ => None,
    }
}

fn scopes_csv(cred: &Value) -> String {
    cred.get("authorized_scopes")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(scope_to_str)
                .collect::<Vec<_>>()
                .join(",")
        })
        .unwrap_or_default()
}

fn rfc3339_to_ts(cred: &Value, key: &str) -> Option<i64> {
    cred.get(key)
        .and_then(|v| v.as_str())
        .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
        .map(|dt| dt.timestamp())
}

/// Load a verifying key from a JWKS file (RFC 8037 OKP/Ed25519 `x` field) or a
/// raw base64 32-byte public-key file.
fn load_verifying_key(path: &str) -> Option<VerifyingKey> {
    let raw = std::fs::read_to_string(path).ok()?;
    // Try JWKS first.
    if let Ok(v) = serde_json::from_str::<Value>(&raw) {
        if let Some(x) = v
            .get("keys")
            .and_then(|k| k.as_array())
            .and_then(|arr| arr.first())
            .and_then(|k| k.get("x"))
            .and_then(|x| x.as_str())
            .or_else(|| v.get("x").and_then(|x| x.as_str()))
        {
            if let Some(vk) = key_from_b64url(x).or_else(|| key_from_b64std(x)) {
                return Some(vk);
            }
        }
    }
    // Fall back to a bare base64 key file.
    let trimmed = raw.trim();
    key_from_b64std(trimmed).or_else(|| key_from_b64url(trimmed))
}

fn key_from_b64url(s: &str) -> Option<VerifyingKey> {
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(s.trim())
        .ok()?;
    key_from_bytes(&bytes)
}

fn key_from_b64std(s: &str) -> Option<VerifyingKey> {
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(s.trim())
        .ok()?;
    key_from_bytes(&bytes)
}

fn key_from_bytes(bytes: &[u8]) -> Option<VerifyingKey> {
    if bytes.len() != 32 {
        return None;
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(bytes);
    VerifyingKey::from_bytes(&arr).ok()
}

fn verify_sig(vk: &VerifyingKey, payload: &[u8], sig_b64: &str) -> bool {
    let bytes = match base64::engine::general_purpose::STANDARD.decode(sig_b64.trim()) {
        Ok(b) if b.len() == 64 => b,
        _ => return false,
    };
    let mut arr = [0u8; 64];
    arr.copy_from_slice(&bytes);
    vk.verify(payload, &Signature::from_bytes(&arr)).is_ok()
}

#[derive(Debug, Clone, Serialize)]
struct CredResult {
    cred_id: String,
    agent_id: String,
    principal_id: String,
    alg: String,
    signature_valid: Option<bool>,
    expired: bool,
    revoked: bool,
    note: String,
}

/// The `agent_identity` check over an exported credentials file, verified
/// against an optional JWKS / public-key file.
pub fn agent_identity(creds_path: &str, key_path: Option<&str>) -> CheckOutcome {
    let raw = match std::fs::read_to_string(creds_path) {
        Ok(r) => r,
        Err(e) => {
            return make_outcome(
                AutoCheck::AgentIdentity,
                CheckStatus::NotRun,
                format!("Could not read credentials file {creds_path}: {e}"),
                serde_json::json!({}),
            )
        }
    };
    let creds = match parse_creds(&raw) {
        Ok(c) if !c.is_empty() => c,
        _ => {
            return make_outcome(
                AutoCheck::AgentIdentity,
                CheckStatus::NotRun,
                "No credentials found to verify.",
                serde_json::json!({}),
            )
        }
    };

    let vk = key_path.and_then(load_verifying_key);
    let now = Utc::now().timestamp();

    let mut results = Vec::new();
    let mut ed_valid = 0u64;
    let mut ed_invalid = 0u64;
    let mut unverifiable = 0u64;
    let mut expired_ct = 0u64;
    let mut revoked_ct = 0u64;

    for c in &creds {
        let cred_id = c
            .get("cred_id")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let agent_id = c
            .get("agent_id")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let principal_id = c
            .get("principal_id")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let alg = c
            .get("alg")
            .and_then(|v| v.as_str())
            .unwrap_or("hmac-sha256")
            .to_string();
        let revoked = c.get("revoked").and_then(|v| v.as_bool()).unwrap_or(false);
        let expires_ts = rfc3339_to_ts(c, "expires_at");
        let expired = expires_ts.map(|e| e < now).unwrap_or(false);
        if expired {
            expired_ct += 1;
        }
        if revoked {
            revoked_ct += 1;
        }

        let (signature_valid, note) = if alg == "ed25519" {
            let sig = c.get("signature_b64").and_then(|v| v.as_str());
            match (&vk, sig) {
                (Some(vk), Some(sig)) => {
                    let issued = rfc3339_to_ts(c, "issued_at").unwrap_or(0);
                    let expires = expires_ts.unwrap_or(0);
                    let max_txn = c.get("max_transaction_usd").and_then(|v| v.as_f64());
                    let payload = canonical_payload(
                        &cred_id,
                        &agent_id,
                        &principal_id,
                        issued,
                        expires,
                        &scopes_csv(c),
                        max_txn,
                    );
                    let ok = verify_sig(vk, &payload, sig);
                    if ok {
                        ed_valid += 1;
                    } else {
                        ed_invalid += 1;
                    }
                    (
                        Some(ok),
                        if ok {
                            "Ed25519 signature valid".into()
                        } else {
                            "Ed25519 signature INVALID".into()
                        },
                    )
                }
                (None, _) => {
                    unverifiable += 1;
                    (
                        None,
                        "Ed25519 credential, but no public key/JWKS supplied to verify".into(),
                    )
                }
                (_, None) => {
                    ed_invalid += 1;
                    (
                        Some(false),
                        "Ed25519 credential missing signature_b64".into(),
                    )
                }
            }
        } else {
            unverifiable += 1;
            (
                None,
                format!("{alg} credential — not offline-verifiable (needs issuer secret)"),
            )
        };

        results.push(CredResult {
            cred_id,
            agent_id,
            principal_id,
            alg,
            signature_valid,
            expired,
            revoked,
            note,
        });
    }

    let detail = serde_json::json!({
        "credentials": creds.len(),
        "ed25519_valid": ed_valid,
        "ed25519_invalid": ed_invalid,
        "unverifiable": unverifiable,
        "expired": expired_ct,
        "revoked": revoked_ct,
        "results": results,
    });

    let (status, summary) = if ed_invalid > 0 {
        (
            CheckStatus::Fail,
            format!("{ed_invalid} credential(s) failed Ed25519 verification."),
        )
    } else if ed_valid > 0 {
        (
            CheckStatus::Pass,
            format!(
                "{ed_valid} credential(s) verified with the published Ed25519 key ({unverifiable} not offline-verifiable)."
            ),
        )
    } else if vk.is_none()
        && creds
            .iter()
            .any(|c| c.get("alg").and_then(|v| v.as_str()) == Some("ed25519"))
    {
        (
            CheckStatus::Warn,
            "Ed25519 credentials present but no public key/JWKS supplied — pass --jwks to verify."
                .to_string(),
        )
    } else {
        (
            CheckStatus::Warn,
            format!(
                "{} credential(s) present but none are offline-verifiable (HMAC credentials need the issuer secret).",
                creds.len()
            ),
        )
    };

    make_outcome(AutoCheck::AgentIdentity, status, summary, detail)
}

fn parse_creds(raw: &str) -> anyhow::Result<Vec<Value>> {
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

#[cfg(test)]
mod tests {
    use super::*;
    use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
    use ed25519_dalek::{Signer, SigningKey};
    use std::io::Write;

    fn tmp(content: &str) -> tempfile::NamedTempFile {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        write!(f, "{content}").unwrap();
        f
    }

    #[test]
    fn verifies_valid_ed25519_credential() {
        let sk = SigningKey::from_bytes(&[7u8; 32]);
        let vk = sk.verifying_key();
        let jwks = serde_json::json!({
            "keys": [{"kty":"OKP","crv":"Ed25519","x": URL_SAFE_NO_PAD.encode(vk.to_bytes())}]
        });
        let jwks_f = tmp(&jwks.to_string());

        let issued = 1_000i64;
        let expires = 9_999_999_999i64; // far future
        let payload = canonical_payload(
            "aida-1",
            "agent-1",
            "prin-1",
            issued,
            expires,
            "read_only",
            None,
        );
        let sig = STANDARD.encode(sk.sign(&payload).to_bytes());

        let cred = serde_json::json!({
            "cred_id": "aida-1", "agent_id": "agent-1", "principal_id": "prin-1",
            "authorized_scopes": ["read_only"],
            "issued_at": chrono::DateTime::from_timestamp(issued, 0).unwrap().to_rfc3339(),
            "expires_at": chrono::DateTime::from_timestamp(expires, 0).unwrap().to_rfc3339(),
            "alg": "ed25519", "signature_b64": sig, "revoked": false
        });
        let cred_f = tmp(&cred.to_string());

        let o = agent_identity(
            cred_f.path().to_str().unwrap(),
            Some(jwks_f.path().to_str().unwrap()),
        );
        assert_eq!(o.status, CheckStatus::Pass, "summary={}", o.summary);
        assert_eq!(o.detail["ed25519_valid"], 1);
    }

    #[test]
    fn detects_tampered_credential() {
        let sk = SigningKey::from_bytes(&[9u8; 32]);
        let vk = sk.verifying_key();
        let jwks = serde_json::json!({"keys":[{"x": URL_SAFE_NO_PAD.encode(vk.to_bytes())}]});
        let jwks_f = tmp(&jwks.to_string());

        let payload = canonical_payload(
            "aida-2",
            "agent-2",
            "prin-2",
            1000,
            9_999_999_999,
            "read_only",
            None,
        );
        let sig = STANDARD.encode(sk.sign(&payload).to_bytes());
        // Tamper: change agent_id after signing.
        let cred = serde_json::json!({
            "cred_id": "aida-2", "agent_id": "agent-EVIL", "principal_id": "prin-2",
            "authorized_scopes": ["read_only"],
            "issued_at": chrono::DateTime::from_timestamp(1000, 0).unwrap().to_rfc3339(),
            "expires_at": chrono::DateTime::from_timestamp(9_999_999_999, 0).unwrap().to_rfc3339(),
            "alg": "ed25519", "signature_b64": sig
        });
        let cred_f = tmp(&cred.to_string());
        let o = agent_identity(
            cred_f.path().to_str().unwrap(),
            Some(jwks_f.path().to_str().unwrap()),
        );
        assert_eq!(o.status, CheckStatus::Fail);
    }

    #[test]
    fn hmac_credential_is_unverifiable_warn() {
        let cred = serde_json::json!({
            "cred_id": "aida-3", "agent_id": "a", "principal_id": "p",
            "authorized_scopes": [], "alg": "hmac-sha256",
            "issued_at": "2026-01-01T00:00:00Z", "expires_at": "2030-01-01T00:00:00Z"
        });
        let cred_f = tmp(&cred.to_string());
        let o = agent_identity(cred_f.path().to_str().unwrap(), None);
        assert_eq!(o.status, CheckStatus::Warn);
    }
}
