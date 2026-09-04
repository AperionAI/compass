//! Emergency-stop / kill-switch evidence in the audit chain.

use super::{make_outcome, CheckOutcome, CheckStatus};
use crate::catalog::AutoCheck;
use serde_json::Value;

/// True when a chain entry (top-level or nested `payload`) looks like a
/// kill-switch / emergency-stop event.
pub fn is_stop_event(v: &Value) -> bool {
    let payload = v.get("payload").unwrap_or(v);
    event_name(payload)
        .or_else(|| event_name(v))
        .map(|s| is_stop_name(&s))
        .unwrap_or(false)
        || mode_is_stop(payload)
        || mode_is_stop(v)
}

fn event_name(v: &Value) -> Option<String> {
    v.get("event")
        .or_else(|| v.get("type"))
        .or_else(|| v.get("kind"))
        .and_then(|x| x.as_str())
        .map(|s| s.to_string())
}

fn is_stop_name(s: &str) -> bool {
    let t = s.to_ascii_lowercase().replace(['-', ' '], "_");
    matches!(
        t.as_str(),
        "emergency_stop"
            | "emergencystop"
            | "kill_switch"
            | "killswitch"
            | "circuit_breaker"
            | "halt"
            | "blast_radius"
    ) || t.contains("emergency_stop")
        || t.contains("kill_switch")
}

fn mode_is_stop(v: &Value) -> bool {
    v.get("mode")
        .and_then(|m| m.as_str())
        .map(|s| {
            matches!(
                s.to_ascii_lowercase().as_str(),
                "off" | "read_only" | "readonly" | "halt" | "stopped"
            )
        })
        .unwrap_or(false)
        && event_name(v)
            .map(|e| {
                let t = e.to_ascii_lowercase();
                t.contains("stop")
                    || t.contains("kill")
                    || t.contains("breaker")
                    || t.contains("halt")
            })
            .unwrap_or(false)
}

/// Scan a chain file for kill-switch events.
pub fn check(chain_path: &str) -> CheckOutcome {
    let raw = match std::fs::read_to_string(chain_path) {
        Ok(r) => r,
        Err(e) => {
            return make_outcome(
                AutoCheck::EmergencyStop,
                CheckStatus::NotRun,
                format!("Could not read chain {chain_path}: {e}"),
                serde_json::json!({}),
            );
        }
    };
    let entries = match crate::evidence::chain::parse_entries(&raw) {
        Ok(e) => e,
        Err(e) => {
            return make_outcome(
                AutoCheck::EmergencyStop,
                CheckStatus::NotRun,
                format!("Could not parse chain: {e}"),
                serde_json::json!({}),
            );
        }
    };

    let mut hits = Vec::new();
    for e in &entries {
        if is_stop_event(e) {
            let seq = e.get("seq").and_then(|x| x.as_u64());
            hits.push(serde_json::json!({ "seq": seq }));
        }
    }

    if hits.is_empty() {
        return make_outcome(
            AutoCheck::EmergencyStop,
            CheckStatus::Warn,
            "Chain has no kill-switch / emergency-stop events.".to_string(),
            serde_json::json!({ "events": 0, "entries": entries.len() }),
        );
    }

    make_outcome(
        AutoCheck::EmergencyStop,
        CheckStatus::Pass,
        format!(
            "Found {} kill-switch event{} in the chain.",
            hits.len(),
            if hits.len() == 1 { "" } else { "s" }
        ),
        serde_json::json!({ "events": hits.len(), "hits": hits }),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nested_payload_counts() {
        let v = serde_json::json!({
            "seq": 4,
            "payload": { "event": "emergency_stop", "mode": "read_only" }
        });
        assert!(is_stop_event(&v));
    }

    #[test]
    fn ordinary_request_does_not() {
        let v = serde_json::json!({
            "seq": 1,
            "event": "request",
            "action_risk_tier": "T1"
        });
        assert!(!is_stop_event(&v));
    }
}
