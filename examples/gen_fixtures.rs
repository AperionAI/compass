//! Regenerate the `demo/` fixtures used by the README, the VHS tape, and the
//! integration tests. Run with `cargo run --example gen_fixtures`.
//!
//! Produces a self-consistent set: a signed audit chain + its key, Ed25519
//! agent credentials + the issuer JWKS, sample VAS + approval logs, and a
//! pre-filled `compass-assessment.yaml` wired to all of them. Everything is
//! deterministic so the demo report is stable.

use aperion_compass::catalog;
use aperion_compass::evidence::aida::canonical_payload;
use aperion_compass::questionnaire::{Answer, Assessment, EvidencePaths};
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine;
use ed25519_dalek::{Signer, SigningKey};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::collections::BTreeMap;
use std::io::Write;

type HmacSha256 = Hmac<Sha256>;

fn main() {
    std::fs::create_dir_all("demo").unwrap();
    gen_vas();
    gen_approvals();
    gen_chain();
    gen_credentials();
    gen_assessment();
    println!("Wrote demo fixtures to ./demo/");
}

fn write(path: &str, content: &str) {
    let mut f = std::fs::File::create(path).unwrap();
    f.write_all(content.as_bytes()).unwrap();
}

fn gen_vas() {
    // A realistic mix: reads (T1), writes (T2), and irreversible actions (T3)
    // -- one T3 with an approval, one without.
    let lines = [
        r#"{"request_id":"r1","model":"gpt-4o","provider":"openai","user_id":"alice","aida_principal_id":"alice@bank","action_risk_tier":"T1","tool_name":"read_account","perimeter_classification":"internal","shield_decision":"allow"}"#,
        r#"{"request_id":"r2","model":"claude-3.5","provider":"anthropic","user_id":"bob","aida_principal_id":"bob@bank","action_risk_tier":"T2","tool_name":"update_record","perimeter_classification":"internal","shield_decision":"allow"}"#,
        r#"{"request_id":"r3","model":"gpt-4o","provider":"openai","user_id":"alice","aida_principal_id":"alice@bank","action_risk_tier":"T3","tool_name":"make_payment","perimeter_classification":"external_trusted","shield_decision":"approval","shield_ticket_id":"tk-1001"}"#,
        r#"{"request_id":"r4","model":"gpt-4o","provider":"openai","user_id":"carol","aida_principal_id":"carol@bank","action_risk_tier":"T3","tool_name":"delete_customer","perimeter_classification":"internal","shield_decision":"block"}"#,
        r#"{"request_id":"r5","model":"llama-3","provider":"ollama","user_id":"bob","aida_principal_id":"bob@bank","action_risk_tier":"T1","tool_name":"search_docs","perimeter_classification":"internal","shield_decision":"allow"}"#,
    ];
    write("demo/vas-logs.jsonl", &format!("{}\n", lines.join("\n")));
}

fn gen_approvals() {
    // ~30% override rate, human-scale latencies -> healthy oversight.
    let mut out = String::new();
    let reviewers = ["priya", "sam"];
    for i in 0..24 {
        let reviewer = reviewers[i % 2];
        let denied = i % 10 < 3; // 30% denied
        let status = if denied { "denied" } else { "approved" };
        let created = format!("2026-06-20T10:{:02}:00Z", i);
        let decided = format!("2026-06-20T10:{:02}:{:02}Z", i, 25 + (i % 20));
        out.push_str(&format!(
            r#"{{"ticket_id":"tk-{i}","rule_id":"destructive_sql","severity":"High","status":"{status}","approver_id":"{reviewer}","created_at":"{created}","decided_at":"{decided}"}}"#
        ));
        out.push('\n');
    }
    write("demo/approvals.jsonl", &out);
}

fn gen_chain() {
    let key = b"compass-demo-audit-key-32-bytes!".to_vec();
    // The key file holds the raw base64 of the key bytes. The assessment
    // references it as `file:demo/chain.key`; the `base64:`/`hex:`/`env:`
    // prefixes are for the *value* form, not the file's contents.
    write("demo/chain.key", &STANDARD.encode(&key));

    let payloads = [
        serde_json::json!({"event":"request","request_id":"r1","action_risk_tier":"T1"}),
        serde_json::json!({"event":"request","request_id":"r3","action_risk_tier":"T3","approved_by":"priya"}),
        serde_json::json!({"event":"blocked_action","request_id":"r4","action_risk_tier":"T3","reason":"irreversible delete without approval"}),
        serde_json::json!({"event":"emergency_stop","mode":"read_only","action_risk_tier":"T3"}),
    ];

    let mut out = String::new();
    let mut prev = "genesis".to_string();
    for (i, p) in payloads.iter().enumerate() {
        let seq = (i + 1) as u64;
        let mut entry = serde_json::json!({
            "seq": seq,
            "prev_hash": prev,
            "key_id": "demo-key-v1",
            "payload": p,
        });
        let mac = hmac_hex(&key, &canonical(&entry));
        entry
            .as_object_mut()
            .unwrap()
            .insert("entry_hmac".into(), serde_json::json!(mac));
        out.push_str(&serde_json::to_string(&entry).unwrap());
        out.push('\n');
        prev = mac;
    }
    write("demo/chain.jsonl", &out);
}

fn gen_credentials() {
    // Deterministic demo issuer key (NOT for production).
    let sk = SigningKey::from_bytes(&[42u8; 32]);
    let vk = sk.verifying_key();
    let jwks = serde_json::json!({
        "keys": [{
            "kty": "OKP", "crv": "Ed25519", "use": "sig", "alg": "EdDSA",
            "kid": "aida-demo-v1", "x": URL_SAFE_NO_PAD.encode(vk.to_bytes())
        }]
    });
    write(
        "demo/jwks.json",
        &serde_json::to_string_pretty(&jwks).unwrap(),
    );

    let creds = [
        (
            "aida-payments-agent",
            "agent-payments",
            "alice@bank",
            "initiate_payments",
            Some(50000.0),
        ),
        (
            "aida-readonly-agent",
            "agent-analytics",
            "bob@bank",
            "read_only",
            None,
        ),
    ];
    let mut out = String::new();
    for (cred_id, agent_id, principal, scope, max_txn) in creds {
        let issued = 1_766_000_000i64;
        let expires = 4_102_444_800i64; // year 2100
        let payload = canonical_payload(
            cred_id, agent_id, principal, issued, expires, scope, max_txn,
        );
        let sig = STANDARD.encode(sk.sign(&payload).to_bytes());
        let cred = serde_json::json!({
            "cred_id": cred_id,
            "agent_id": agent_id,
            "principal_id": principal,
            "authorized_scopes": [scope],
            "max_transaction_usd": max_txn,
            "issued_at": chrono::DateTime::from_timestamp(issued, 0).unwrap().to_rfc3339(),
            "expires_at": chrono::DateTime::from_timestamp(expires, 0).unwrap().to_rfc3339(),
            "revoked": false,
            "alg": "ed25519",
            "keyid": "aida-demo-v1",
            "signature_b64": sig,
        });
        out.push_str(&serde_json::to_string(&cred).unwrap());
        out.push('\n');
    }
    write("demo/credentials.jsonl", &out);
}

fn gen_assessment() {
    let cats = catalog::load_selection(&["eu-ai-act".into(), "imda".into()]).unwrap();
    let mut a = Assessment::scaffold(&cats);
    a.organization = Some("Acme Financial (demo)".into());
    a.system_name = Some("Client-onboarding agent".into());

    // Deterministic, realistic answer mix keyed off the control id.
    for cat in &cats {
        if let Some(fa) = a.framework_mut(&cat.framework) {
            for ans in fa.answers.iter_mut() {
                let h = ans.control_id.bytes().map(|b| b as u32).sum::<u32>();
                ans.answer = match h % 5 {
                    0 => Answer::Partial,
                    1 => Answer::No,
                    _ => Answer::Yes,
                };
            }
        }
    }

    a.evidence = EvidencePaths {
        vas: Some("demo/vas-logs.jsonl".into()),
        chain: Some("demo/chain.jsonl".into()),
        chain_hmac_key: Some("file:demo/chain.key".into()),
        approvals: Some("demo/approvals.jsonl".into()),
        credentials: Some("demo/credentials.jsonl".into()),
        jwks: Some("demo/jwks.json".into()),
        generic: None,
    };

    a.save("demo/compass-assessment.yaml").unwrap();
}

// ── local canonicalisation (mirrors evidence::chain) ────────────────────────

fn canonical(entry: &serde_json::Value) -> String {
    let mut v = entry.clone();
    if let Some(obj) = v.as_object_mut() {
        obj.remove("entry_hmac");
    }
    serde_json::to_string(&sort_value(&v)).unwrap()
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

fn hmac_hex(key: &[u8], msg: &str) -> String {
    let mut mac = HmacSha256::new_from_slice(key).unwrap();
    mac.update(msg.as_bytes());
    hex::encode(mac.finalize().into_bytes())
}
