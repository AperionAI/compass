//! MCP trust-registry check: ingested server allowlist vs observed calls.

use super::{make_outcome, CheckOutcome, CheckStatus};
use crate::catalog::AutoCheck;
use crate::evidence::vas::LogRecord;
use serde_json::Value;
use std::collections::BTreeSet;

/// Load an allowlist export. Accepts a JSON array of strings, JSONL of
/// strings or objects, or `{ "servers": [ … ] }` where each item is a string
/// or `{ "url" | "name" | "server" }`.
pub fn load_allowlist(path: &str) -> anyhow::Result<BTreeSet<String>> {
    let raw = std::fs::read_to_string(path)?;
    let mut out = BTreeSet::new();
    let trimmed = raw.trim_start();
    if trimmed.starts_with('[') || trimmed.starts_with('{') {
        let v: Value = serde_json::from_str(&raw)?;
        collect_names(&v, &mut out);
        if out.is_empty() {
            anyhow::bail!("no MCP servers found in {path}");
        }
        return Ok(out);
    }
    for (i, line) in raw.lines().enumerate() {
        let s = line.trim();
        if s.is_empty() || s.starts_with('#') {
            continue;
        }
        let v: Value = serde_json::from_str(s)
            .map_err(|e| anyhow::anyhow!("allowlist JSONL line {}: {e}", i + 1))?;
        collect_names(&v, &mut out);
        if v.is_string() {
            if let Some(s) = v.as_str() {
                if !s.is_empty() {
                    out.insert(s.to_string());
                }
            }
        }
    }
    if out.is_empty() {
        anyhow::bail!("no MCP servers found in {path}");
    }
    Ok(out)
}

fn collect_names(v: &Value, out: &mut BTreeSet<String>) {
    match v {
        Value::String(s) if !s.is_empty() => {
            out.insert(s.clone());
        }
        Value::Array(a) => {
            for item in a {
                collect_names(item, out);
            }
        }
        Value::Object(m) => {
            if let Some(servers) = m.get("servers") {
                collect_names(servers, out);
            }
            for key in ["url", "name", "server", "mcp_server", "id"] {
                if let Some(s) = m.get(key).and_then(|x| x.as_str()) {
                    if !s.is_empty() {
                        out.insert(s.to_string());
                    }
                }
            }
        }
        _ => {}
    }
}

fn observed_servers(records: &[LogRecord]) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    for r in records {
        if let Some(s) = r.str_any(&[
            "mcp_server",
            "mcp_url",
            "mcp_name",
            "server_url",
            "server_name",
        ]) {
            out.insert(s);
        }
    }
    out
}

fn is_denied(r: &LogRecord) -> bool {
    r.bool_any(&["blocked", "denied", "maestro_blocked"])
        .unwrap_or(false)
        || r.str_any(&["shield_decision", "decision", "event"])
            .map(|s| {
                let t = s.to_ascii_lowercase();
                t.contains("block") || t.contains("deny")
            })
            .unwrap_or(false)
}

/// Compare observed MCP servers against the allowlist.
/// Unlisted servers that were denied still count as the control working.
pub fn check(allowlist_path: &str, records: &[LogRecord]) -> CheckOutcome {
    let allow = match load_allowlist(allowlist_path) {
        Ok(a) => a,
        Err(e) => {
            return make_outcome(
                AutoCheck::McpAllowlist,
                CheckStatus::NotRun,
                format!("Could not read MCP allowlist {allowlist_path}: {e}"),
                serde_json::json!({}),
            );
        }
    };

    let observed = observed_servers(records);
    if observed.is_empty() {
        return make_outcome(
            AutoCheck::McpAllowlist,
            CheckStatus::Warn,
            format!(
                "Allowlist registered ({} server{}) but no MCP calls observed in logs.",
                allow.len(),
                if allow.len() == 1 { "" } else { "s" }
            ),
            serde_json::json!({ "allowlist": allow, "observed": [] }),
        );
    }

    let mut unlisted_allowed = Vec::new();
    let mut unlisted_denied = Vec::new();
    for r in records {
        let Some(server) = r.str_any(&[
            "mcp_server",
            "mcp_url",
            "mcp_name",
            "server_url",
            "server_name",
        ]) else {
            continue;
        };
        if allow.contains(&server) {
            continue;
        }
        if is_denied(r) {
            unlisted_denied.push(server);
        } else {
            unlisted_allowed.push(server);
        }
    }
    unlisted_allowed.sort();
    unlisted_allowed.dedup();
    unlisted_denied.sort();
    unlisted_denied.dedup();

    let detail = serde_json::json!({
        "allowlist": allow,
        "observed": observed,
        "unlisted_denied": unlisted_denied,
        "unlisted_allowed": unlisted_allowed,
    });

    if !unlisted_allowed.is_empty() {
        return make_outcome(
            AutoCheck::McpAllowlist,
            CheckStatus::Fail,
            format!(
                "{} MCP server(s) observed that are not on the allowlist and were not denied.",
                unlisted_allowed.len()
            ),
            detail,
        );
    }

    make_outcome(
        AutoCheck::McpAllowlist,
        CheckStatus::Pass,
        format!(
            "All observed MCP servers are on the allowlist ({} listed, {} observed).",
            allow.len(),
            observed.len()
        ),
        detail,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn listed_server_passes() {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        writeln!(f, r#"["https://mcp.internal/hr"]"#).unwrap();
        let recs = vec![LogRecord(serde_json::json!({
            "mcp_url": "https://mcp.internal/hr",
            "tool_name": "list_employees"
        }))];
        let o = check(f.path().to_str().unwrap(), &recs);
        assert_eq!(o.status, CheckStatus::Pass, "{}", o.summary);
    }

    #[test]
    fn unlisted_without_deny_fails() {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        writeln!(f, r#"{{"servers":[{{"name":"hr"}}]}}"#).unwrap();
        let recs = vec![LogRecord(serde_json::json!({
            "mcp_name": "shadow-mcp",
            "tool_name": "exfil"
        }))];
        let o = check(f.path().to_str().unwrap(), &recs);
        assert_eq!(o.status, CheckStatus::Fail);
    }

    #[test]
    fn unlisted_but_denied_passes() {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        writeln!(f, r#"["hr"]"#).unwrap();
        let recs = vec![LogRecord(serde_json::json!({
            "mcp_name": "shadow-mcp",
            "shield_decision": "block"
        }))];
        let o = check(f.path().to_str().unwrap(), &recs);
        assert_eq!(o.status, CheckStatus::Pass, "{}", o.summary);
    }
}
