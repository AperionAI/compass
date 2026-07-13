//! Minimal CSV → canonical-JSON converters (no external dependencies).
//!
//! A CSV export is the lowest common denominator: a claims team tracking
//! approvals in Jira or ServiceNow can export one in a few clicks. We parse it
//! with a small RFC 4180-ish reader (quoted fields, embedded commas, doubled
//! quotes, CR/LF) and map columns to canonical keys by header name, accepting a
//! spread of common aliases so users rarely have to rename anything.

use anyhow::{anyhow, Result};
use serde_json::{Map, Value};

/// Parse CSV text into a header row and data rows.
pub fn parse_csv(raw: &str) -> Result<(Vec<String>, Vec<Vec<String>>)> {
    let mut records: Vec<Vec<String>> = Vec::new();
    let mut field = String::new();
    let mut record: Vec<String> = Vec::new();
    let mut in_quotes = false;
    let mut chars = raw.chars().peekable();

    while let Some(c) = chars.next() {
        if in_quotes {
            match c {
                '"' => {
                    if chars.peek() == Some(&'"') {
                        field.push('"');
                        chars.next();
                    } else {
                        in_quotes = false;
                    }
                }
                _ => field.push(c),
            }
        } else {
            match c {
                '"' => in_quotes = true,
                ',' => {
                    record.push(std::mem::take(&mut field));
                }
                '\r' => { /* swallow; \n handles the row */ }
                '\n' => {
                    record.push(std::mem::take(&mut field));
                    records.push(std::mem::take(&mut record));
                }
                _ => field.push(c),
            }
        }
    }
    // Trailing field / row without a final newline.
    if !field.is_empty() || !record.is_empty() {
        record.push(field);
        records.push(record);
    }

    // Drop fully-empty trailing rows.
    records.retain(|r| !(r.len() == 1 && r[0].trim().is_empty()));

    if records.is_empty() {
        return Err(anyhow!("CSV had no rows"));
    }
    let headers: Vec<String> = records
        .remove(0)
        .into_iter()
        .map(|h| h.trim().to_ascii_lowercase())
        .collect();
    Ok((headers, records))
}

/// Find the index of the first header matching any alias (case-insensitive,
/// ignoring spaces/underscores/hyphens).
fn col(headers: &[String], aliases: &[&str]) -> Option<usize> {
    let norm = |s: &str| s.to_ascii_lowercase().replace([' ', '_', '-'], "");
    let wanted: Vec<String> = aliases.iter().map(|a| norm(a)).collect();
    headers.iter().position(|h| wanted.contains(&norm(h)))
}

fn get(row: &[String], idx: Option<usize>) -> Option<&str> {
    idx.and_then(|i| row.get(i))
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
}

fn ts(row: &[String], idx: Option<usize>) -> Option<String> {
    let v = get(row, idx)?;
    // Bare integer → unix seconds; else pass RFC 3339 through.
    if let Ok(secs) = v.parse::<i64>() {
        return chrono::DateTime::from_timestamp(secs, 0).map(|dt| dt.to_rfc3339());
    }
    Some(v.to_string())
}

/// Convert a generic request-log CSV into canonical log records.
pub fn convert_logs(raw: &str) -> Result<Vec<Value>> {
    let (headers, rows) = parse_csv(raw)?;

    let c_req = col(&headers, &["request_id", "id", "requestid", "trace_id"]);
    let c_model = col(&headers, &["model", "model_id", "modelid", "deployment"]);
    let c_provider = col(&headers, &["provider", "vendor", "custom_llm_provider"]);
    let c_tool = col(
        &headers,
        &[
            "tool_name",
            "tool",
            "function",
            "action",
            "method",
            "operation",
        ],
    );
    let c_user = col(
        &headers,
        &[
            "user_id",
            "user",
            "principal",
            "actor",
            "requested_by",
            "identity",
        ],
    );
    let c_ts = col(
        &headers,
        &["timestamp", "time", "created_at", "starttime", "date"],
    );
    let c_intent = col(&headers, &["intent", "task_class", "category"]);
    let c_tier = col(&headers, &["action_risk_tier", "risk_tier", "tier"]);

    let mut out = Vec::new();
    for row in &rows {
        let mut o = Map::new();
        put(&mut o, "request_id", get(row, c_req));
        put(&mut o, "model", get(row, c_model));
        put(&mut o, "provider", get(row, c_provider).or(Some("csv")));
        put(&mut o, "tool_name", get(row, c_tool));
        put(&mut o, "user_id", get(row, c_user));
        put(&mut o, "intent", get(row, c_intent));
        put(&mut o, "action_risk_tier", get(row, c_tier));
        if let Some(t) = ts(row, c_ts) {
            o.insert("timestamp".into(), Value::String(t));
        }
        out.push(Value::Object(o));
    }
    if out.is_empty() {
        return Err(anyhow!("no data rows in CSV"));
    }
    Ok(out)
}

/// Convert an approval / review CSV into oversight tickets (`TicketDto` shape:
/// `status`, `approver_id`, `created_at`, `decided_at`).
pub fn convert_approvals(raw: &str) -> Result<Vec<Value>> {
    let (headers, rows) = parse_csv(raw)?;

    let c_status = col(
        &headers,
        &["status", "decision", "outcome", "result", "action"],
    );
    let c_reviewer = col(
        &headers,
        &[
            "approver_id",
            "approver",
            "reviewer",
            "approved_by",
            "reviewed_by",
            "user",
        ],
    );
    let c_created = col(
        &headers,
        &[
            "created_at",
            "created",
            "requested_at",
            "opened_at",
            "start",
            "starttime",
        ],
    );
    let c_decided = col(
        &headers,
        &[
            "decided_at",
            "decided",
            "resolved_at",
            "closed_at",
            "approved_at",
            "end",
            "endtime",
        ],
    );

    if c_status.is_none() {
        return Err(anyhow!(
            "approvals CSV needs a decision column (one of: status, decision, outcome, result)"
        ));
    }

    let mut out = Vec::new();
    for row in &rows {
        let mut o = Map::new();
        if let Some(s) = get(row, c_status) {
            o.insert("status".into(), Value::String(normalize_status(s)));
        }
        put(&mut o, "approver_id", get(row, c_reviewer));
        if let Some(t) = ts(row, c_created) {
            o.insert("created_at".into(), Value::String(t));
        }
        if let Some(t) = ts(row, c_decided) {
            o.insert("decided_at".into(), Value::String(t));
        }
        out.push(Value::Object(o));
    }
    if out.is_empty() {
        return Err(anyhow!("no data rows in approvals CSV"));
    }
    Ok(out)
}

/// Map free-form decision text to the vocabulary `human_oversight` scores
/// (`approved` / `denied`); unknown values pass through unchanged so nothing is
/// silently dropped.
fn normalize_status(s: &str) -> String {
    match s.trim().to_ascii_lowercase().as_str() {
        "approved" | "approve" | "accept" | "accepted" | "yes" | "y" | "pass" | "allow"
        | "allowed" | "ok" | "redeemed" => "approved".to_string(),
        "denied" | "deny" | "reject" | "rejected" | "no" | "n" | "fail" | "blocked" | "block"
        | "override" | "overridden" => "denied".to_string(),
        other => other.to_string(),
    }
}

fn put(obj: &mut Map<String, Value>, key: &str, val: Option<&str>) {
    if let Some(v) = val {
        if !v.is_empty() {
            obj.insert(key.to_string(), Value::String(v.to_string()));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_quoted_fields_and_commas() {
        let raw = "a,b,c\n1,\"hello, world\",3\n4,\"say \"\"hi\"\"\",6\n";
        let (h, rows) = parse_csv(raw).unwrap();
        assert_eq!(h, vec!["a", "b", "c"]);
        assert_eq!(rows[0][1], "hello, world");
        assert_eq!(rows[1][1], "say \"hi\"");
    }

    #[test]
    fn logs_map_columns_by_alias() {
        let raw = "Request ID,Model,Tool,User,Time\n\
                   r1,gpt-4o,delete_database,alice,2026-01-01T00:00:00Z\n";
        let out = convert_logs(raw).unwrap();
        assert_eq!(out.len(), 1);
        assert_eq!(out[0]["request_id"], "r1");
        assert_eq!(out[0]["tool_name"], "delete_database");
        assert_eq!(out[0]["user_id"], "alice");
        assert_eq!(out[0]["provider"], "csv");
    }

    #[test]
    fn approvals_normalize_status_and_unix_time() {
        let raw = "reviewer,decision,created,decided\n\
                   bob,Approve,1735689600,1735689630\n\
                   carol,REJECTED,1735689600,1735689900\n";
        let out = convert_approvals(raw).unwrap();
        assert_eq!(out.len(), 2);
        assert_eq!(out[0]["status"], "approved");
        assert_eq!(out[0]["approver_id"], "bob");
        assert!(out[0]["created_at"]
            .as_str()
            .unwrap()
            .starts_with("2025-01-01"));
        assert_eq!(out[1]["status"], "denied");
    }

    #[test]
    fn approvals_requires_decision_column() {
        let raw = "reviewer,created\nbob,2026-01-01T00:00:00Z\n";
        assert!(convert_approvals(raw).is_err());
    }
}
