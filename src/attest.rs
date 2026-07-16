//! Signed attestation bundles (v0.3).
//!
//! `compass attest generate` packages the scored governance posture, the
//! evidence-check outcomes, and a cryptographic anchor of the audit-chain
//! tail into a single JSON payload and signs it with an Ed25519 key.
//! `compass attest verify` re-checks the signature and payload integrity
//! **offline** against a published public key / JWKS — no Compass internals,
//! no running gateway, no network.
//!
//! This is the "prove it, don't claim it" artifact: a tamper-evident,
//! offline-verifiable snapshot an auditor or customer can validate without
//! trusting the party that produced it. It reuses the exact Ed25519 / JWKS
//! primitive Compass already uses to verify AIDA agent credentials.
//!
//! ## Envelope
//!
//! ```json
//! {
//!   "payload":       { ...canonical attestation object... },
//!   "alg":           "EdDSA",
//!   "keyid":         "<hex>",
//!   "signature_b64": "<base64 64-byte Ed25519 signature over canonical payload>"
//! }
//! ```
//!
//! The signature is computed over the RFC-8785-style canonical form of the
//! payload (recursively key-sorted, compact). Verification recomputes that
//! canonical form from the received payload, so any mutation — a flipped
//! score, a removed integrity failure, a swapped framework — breaks it.

use anyhow::{anyhow, Context, Result};
use base64::Engine as _;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::scoring::Scorecard;

/// Attestation payload schema version.
pub const ATTESTATION_VERSION: u32 = 1;

/// Result of verifying a signed attestation bundle.
#[derive(Debug, Clone)]
pub struct VerifyReport {
    pub valid: bool,
    pub keyid: Option<String>,
    pub attestation_version: Option<u64>,
    pub tool_version: Option<String>,
    pub generated_at: Option<String>,
    pub overall_score: Option<f64>,
    pub overall_label: Option<String>,
    pub integrity_failure: Option<bool>,
    pub summary: String,
}

/// Assemble and sign an attestation bundle for a scored `card`.
///
/// Returns `(envelope, keyid, jwks)` where `envelope` is the signed bundle
/// to write, `keyid` identifies the signing key, and `jwks` is the public
/// key in JWKS form for verifiers.
pub fn generate(
    card: &Scorecard,
    chain_path: Option<&str>,
    signing_key_spec: Option<&str>,
) -> Result<(Value, String, Value)> {
    let signing_key = load_signing_key(signing_key_spec)?;
    let vk = signing_key.verifying_key();
    let keyid = keyid_for(&vk);

    let payload = build_payload(card, chain_path);
    let canonical = canonical_json(&payload);
    let sig: Signature = signing_key.sign(&canonical);
    let signature_b64 = base64::engine::general_purpose::STANDARD.encode(sig.to_bytes());

    let envelope = json!({
        "payload": payload,
        "alg": "EdDSA",
        "keyid": keyid,
        "signature_b64": signature_b64,
    });
    let jwks = jwks_for(&vk, &keyid);
    Ok((envelope, keyid, jwks))
}

/// Verify a signed attestation `bundle` against the public key at `jwks_path`.
pub fn verify(bundle: &Value, jwks_path: &str) -> Result<VerifyReport> {
    let payload = bundle
        .get("payload")
        .ok_or_else(|| anyhow!("bundle is missing `payload`"))?;
    let signature_b64 = bundle
        .get("signature_b64")
        .and_then(|s| s.as_str())
        .ok_or_else(|| anyhow!("bundle is missing `signature_b64`"))?;
    let keyid = bundle
        .get("keyid")
        .and_then(|s| s.as_str())
        .map(|s| s.to_string());

    let vk = load_verifying_key(jwks_path)
        .ok_or_else(|| anyhow!("could not load an Ed25519 public key from {jwks_path}"))?;

    let canonical = canonical_json(payload);
    let valid = verify_sig(&vk, &canonical, signature_b64);

    // Optional keyid cross-check: warn (not fail) if the bundle names a
    // different key than the one we verified against.
    let expected_keyid = keyid_for(&vk);
    let keyid_note = match &keyid {
        Some(k) if *k != expected_keyid => {
            format!(" (note: bundle keyid {k} != provided key {expected_keyid})")
        }
        _ => String::new(),
    };

    let overall_score = payload.get("overall_score").and_then(|v| v.as_f64());
    let overall_label = payload
        .get("overall_label")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());
    let integrity_failure = payload.get("integrity_failure").and_then(|v| v.as_bool());

    let summary = if valid {
        format!(
            "attestation signature VALID{keyid_note} — score {}, integrity_failure={}",
            overall_score.map(|s| s.round() as i64).unwrap_or(-1),
            integrity_failure.unwrap_or(false)
        )
    } else {
        format!("attestation signature INVALID{keyid_note} — payload tampered or wrong key")
    };

    Ok(VerifyReport {
        valid,
        keyid,
        attestation_version: payload.get("attestation_version").and_then(|v| v.as_u64()),
        tool_version: payload
            .get("tool_version")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string()),
        generated_at: payload
            .get("generated_at")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string()),
        overall_score,
        overall_label,
        integrity_failure,
        summary,
    })
}

/// Default per-user signing-key path: `~/.aperion-compass/attest-ed25519.key`.
pub fn default_key_path() -> Option<std::path::PathBuf> {
    std::env::var_os("HOME").map(|home| {
        std::path::Path::new(&home)
            .join(".aperion-compass")
            .join("attest-ed25519.key")
    })
}

// ── Payload assembly ───────────────────────────────────────────────────

fn build_payload(card: &Scorecard, chain_path: Option<&str>) -> Value {
    let frameworks: Vec<Value> = card
        .frameworks
        .iter()
        .map(|f| {
            json!({
                "framework": f.framework,
                "name": f.name,
                "version": f.version,
                "score": f.score,
                "label": f.label,
            })
        })
        .collect();

    json!({
        "attestation_version": ATTESTATION_VERSION,
        "generated_at": chrono::Utc::now().to_rfc3339(),
        "tool": card.tool,
        "tool_version": card.tool_version,
        "organization": card.organization,
        "system_name": card.system_name,
        "overall_score": card.overall_score,
        "overall_label": card.overall_label,
        "pass_threshold": card.pass_threshold,
        "passed": card.passed,
        "integrity_failure": card.integrity_failure,
        "frameworks": frameworks,
        "chain_anchor": build_chain_anchor(card, chain_path),
        // Full scorecard embedded so the artifact is self-contained.
        "scorecard": serde_json::to_value(card).unwrap_or(Value::Null),
    })
}

/// Cryptographic anchor of the audit chain: the verified seq range plus the
/// tail entry's HMAC (read from the chain file when available), so a verifier
/// can pin exactly which log state this attestation covers.
fn build_chain_anchor(card: &Scorecard, chain_path: Option<&str>) -> Value {
    let outcome = card.evidence.outcomes.get("audit_chain_integrity");
    let (status, detail) = match outcome {
        Some(o) => (o.status.as_str().to_string(), o.detail.clone()),
        None => ("not_run".to_string(), Value::Null),
    };

    let mut anchor = json!({
        "status": status,
        "from_seq": detail.get("from_seq").cloned().unwrap_or(Value::Null),
        "to_seq": detail.get("to_seq").cloned().unwrap_or(Value::Null),
        "entries_checked": detail.get("entries_checked").cloned().unwrap_or(Value::Null),
        "signed": detail.get("signed").cloned().unwrap_or(Value::Null),
    });

    if let Some(path) = chain_path {
        if let Some(tail) = read_chain_tail(path) {
            if let Some(obj) = anchor.as_object_mut() {
                obj.insert(
                    "tail_entry_hmac".to_string(),
                    tail.get("entry_hmac").cloned().unwrap_or(Value::Null),
                );
                obj.insert(
                    "tail_seq".to_string(),
                    tail.get("seq").cloned().unwrap_or(Value::Null),
                );
                obj.insert(
                    "tail_key_id".to_string(),
                    tail.get("key_id").cloned().unwrap_or(Value::Null),
                );
            }
        }
    }
    anchor
}

/// Read the last entry of a chain export (JSONL or JSON array).
fn read_chain_tail(path: &str) -> Option<Value> {
    let raw = std::fs::read_to_string(path).ok()?;
    let trimmed = raw.trim_start();
    if trimmed.starts_with('[') {
        let arr: Vec<Value> = serde_json::from_str(&raw).ok()?;
        return arr.into_iter().last();
    }
    let mut last = None;
    for line in raw.lines() {
        let s = line.trim();
        if s.is_empty() || s.starts_with('#') {
            continue;
        }
        if let Ok(v) = serde_json::from_str::<Value>(s) {
            last = Some(v);
        }
    }
    last
}

// ── Canonicalisation ─────────────────────────────────────────────────────

/// Canonical JSON bytes: recursively sort object keys, serialise compactly.
fn canonical_json(v: &Value) -> Vec<u8> {
    serde_json::to_vec(&sort_value(v)).unwrap_or_default()
}

fn sort_value(v: &Value) -> Value {
    match v {
        Value::Object(m) => {
            let bt: std::collections::BTreeMap<String, Value> = m
                .iter()
                .map(|(k, val)| (k.clone(), sort_value(val)))
                .collect();
            Value::Object(bt.into_iter().collect())
        }
        Value::Array(a) => Value::Array(a.iter().map(sort_value).collect()),
        _ => v.clone(),
    }
}

// ── Keys ──────────────────────────────────────────────────────────────────

/// Load a signing key from a spec, or fall back to (and create if needed) the
/// stable per-user key at `~/.aperion-compass/attest-ed25519.key`.
fn load_signing_key(spec: Option<&str>) -> Result<SigningKey> {
    if let Some(spec) = spec {
        let seed = load_seed_spec(spec)
            .ok_or_else(|| anyhow!("could not read a 32-byte Ed25519 seed from `{spec}`"))?;
        return Ok(SigningKey::from_bytes(&seed));
    }
    let path = default_key_path()
        .ok_or_else(|| anyhow!("HOME is not set; pass --signing-key explicitly"))?;
    if let Ok(existing) = std::fs::read_to_string(&path) {
        if let Some(seed) = decode_seed(existing.trim()) {
            return Ok(SigningKey::from_bytes(&seed));
        }
    }
    // First run: mint a stable key from OS randomness, 0600.
    let seed = os_random_32().context(
        "no signing key found and could not read OS randomness; pass --signing-key file:<seed>",
    )?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let b64 = base64::engine::general_purpose::STANDARD.encode(seed);
    write_0600(&path, b64.as_bytes())?;
    eprintln!(
        "compass: created a new attestation signing key at {} (keep it safe)",
        path.display()
    );
    Ok(SigningKey::from_bytes(&seed))
}

fn load_seed_spec(spec: &str) -> Option<[u8; 32]> {
    if let Some(rest) = spec.strip_prefix("file:") {
        let raw = std::fs::read_to_string(rest).ok()?;
        return decode_seed(raw.trim());
    }
    if let Some(rest) = spec.strip_prefix("env:") {
        let v = std::env::var(rest).ok()?;
        return decode_seed(v.trim());
    }
    // base64:/hex:/bare
    decode_seed(spec)
}

/// Decode a 32-byte seed from base64 (std or url), hex, or a `base64:`/`hex:`
/// prefixed string.
fn decode_seed(s: &str) -> Option<[u8; 32]> {
    let s = s.trim();
    let candidates: Vec<Vec<u8>> = {
        let mut c = Vec::new();
        if let Some(rest) = s.strip_prefix("base64:") {
            if let Ok(b) = base64::engine::general_purpose::STANDARD.decode(rest.trim()) {
                c.push(b);
            }
        } else if let Some(rest) = s.strip_prefix("hex:") {
            if let Ok(b) = hex::decode(rest.trim()) {
                c.push(b);
            }
        } else {
            if let Ok(b) = base64::engine::general_purpose::STANDARD.decode(s) {
                c.push(b);
            }
            if let Ok(b) = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(s) {
                c.push(b);
            }
            if let Ok(b) = hex::decode(s) {
                c.push(b);
            }
        }
        c
    };
    for b in candidates {
        if b.len() == 32 {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&b);
            return Some(arr);
        }
    }
    None
}

fn os_random_32() -> Result<[u8; 32]> {
    use std::io::Read;
    let mut f = std::fs::File::open("/dev/urandom").context("open /dev/urandom")?;
    let mut buf = [0u8; 32];
    f.read_exact(&mut buf).context("read /dev/urandom")?;
    Ok(buf)
}

fn write_0600(path: &std::path::Path, bytes: &[u8]) -> Result<()> {
    use std::io::Write;
    let mut f = std::fs::File::create(path)?;
    f.write_all(bytes)?;
    f.flush()?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
    }
    Ok(())
}

fn keyid_for(vk: &VerifyingKey) -> String {
    let h = Sha256::digest(vk.to_bytes());
    hex::encode(&h[..8])
}

fn jwks_for(vk: &VerifyingKey, keyid: &str) -> Value {
    let x = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(vk.to_bytes());
    json!({
        "keys": [
            { "kty": "OKP", "crv": "Ed25519", "x": x, "kid": keyid, "use": "sig", "alg": "EdDSA" }
        ]
    })
}

fn load_verifying_key(path: &str) -> Option<VerifyingKey> {
    let raw = std::fs::read_to_string(path).ok()?;
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

#[cfg(test)]
mod tests {
    use super::*;

    /// A deterministic 32-byte seed for reproducible tests.
    const SEED: &str = "hex:0101010101010101010101010101010101010101010101010101010101010101";

    fn sample_card() -> Scorecard {
        // Minimal scorecard via JSON round-trip is not possible (Scorecard is
        // serialize-only), so build the pieces we read in build_payload.
        Scorecard {
            generated_at: "2026-07-16T00:00:00Z".to_string(),
            organization: Some("Acme".to_string()),
            system_name: Some("agent-x".to_string()),
            tool: "Aperion Compass".to_string(),
            tool_version: "0.3.0".to_string(),
            overall_score: 82.0,
            overall_label: "Strong".to_string(),
            counts: Default::default(),
            frameworks: vec![],
            evidence: Default::default(),
            pass_threshold: 70.0,
            passed: true,
            integrity_failure: false,
            recommended_exit_code: 0,
        }
    }

    #[test]
    fn generate_then_verify_round_trip() {
        let card = sample_card();
        let (envelope, keyid, jwks) = generate(&card, None, Some(SEED)).unwrap();

        let tmp = tempfile::TempDir::new().unwrap();
        let jwks_path = tmp.path().join("key.jwks.json");
        std::fs::write(&jwks_path, serde_json::to_string(&jwks).unwrap()).unwrap();

        let report = verify(&envelope, jwks_path.to_str().unwrap()).unwrap();
        assert!(report.valid, "freshly signed bundle must verify");
        assert_eq!(report.keyid.as_deref(), Some(keyid.as_str()));
        assert_eq!(report.overall_score, Some(82.0));
        assert_eq!(report.integrity_failure, Some(false));
    }

    #[test]
    fn tampering_with_score_breaks_signature() {
        let card = sample_card();
        let (mut envelope, _keyid, jwks) = generate(&card, None, Some(SEED)).unwrap();

        // Flip the score in the payload after signing.
        envelope
            .get_mut("payload")
            .unwrap()
            .as_object_mut()
            .unwrap()
            .insert("overall_score".to_string(), json!(99.0));

        let tmp = tempfile::TempDir::new().unwrap();
        let jwks_path = tmp.path().join("key.jwks.json");
        std::fs::write(&jwks_path, serde_json::to_string(&jwks).unwrap()).unwrap();

        let report = verify(&envelope, jwks_path.to_str().unwrap()).unwrap();
        assert!(!report.valid, "tampered payload must fail verification");
    }

    #[test]
    fn wrong_key_fails_verification() {
        let card = sample_card();
        let (envelope, _keyid, _jwks) = generate(&card, None, Some(SEED)).unwrap();

        // Verify against a DIFFERENT key's JWKS.
        let other_seed = "hex:0202020202020202020202020202020202020202020202020202020202020202";
        let other = SigningKey::from_bytes(&decode_seed(other_seed).unwrap());
        let jwks = jwks_for(&other.verifying_key(), &keyid_for(&other.verifying_key()));

        let tmp = tempfile::TempDir::new().unwrap();
        let jwks_path = tmp.path().join("other.jwks.json");
        std::fs::write(&jwks_path, serde_json::to_string(&jwks).unwrap()).unwrap();

        let report = verify(&envelope, jwks_path.to_str().unwrap()).unwrap();
        assert!(!report.valid, "wrong key must fail verification");
    }

    #[test]
    fn canonical_json_is_key_order_independent() {
        let a = json!({ "b": 1, "a": { "y": 2, "x": 3 } });
        let b = json!({ "a": { "x": 3, "y": 2 }, "b": 1 });
        assert_eq!(canonical_json(&a), canonical_json(&b));
    }
}
