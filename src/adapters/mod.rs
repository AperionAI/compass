//! Native-export → Compass-canonical converters.
//!
//! Most teams downloading Compass don't have governance-grade logs lying
//! around; what they *do* have is whatever their model provider or gateway
//! already writes. These adapters lift those native shapes into the canonical
//! JSONL that the evidence checks read (`request_id`, `model`, `provider`,
//! `tool_name`, `user_id`, `timestamp`, …), so `compass ingest --from <src>`
//! turns an existing export into usable evidence in one step.
//!
//! Everything here is pure string/JSON transformation — no network, no new
//! dependencies. Log adapters emit records for the `generic` evidence slot;
//! the approvals adapter emits `TicketDto`-compatible rows for the
//! `human_oversight` check.

use anyhow::{anyhow, Context, Result};
use serde_json::{Map, Value};

mod csv;

/// A supported native export format.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Adapter {
    /// OpenAI chat-completion / responses objects (JSONL or array).
    Openai,
    /// LiteLLM standard-logging payloads or spend-log rows.
    LiteLlm,
    /// AWS Bedrock model-invocation logging records.
    Bedrock,
    /// Generic request-log CSV (header row mapped by column name).
    Csv,
    /// Approval / review CSV → oversight tickets.
    CsvApprovals,
}

/// Which evidence slot a converted file should be registered under.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputKind {
    /// Request/tool logs → `generic` slot (action-risk + logging checks).
    Logs,
    /// Approval tickets → `approvals` slot (human-oversight check).
    Approvals,
}

impl Adapter {
    /// Parse a `--from` token.
    pub fn parse(s: &str) -> Option<Adapter> {
        match s.trim().to_ascii_lowercase().replace(['-', '_'], "") {
            ref t if t == "openai" => Some(Adapter::Openai),
            ref t if t == "litellm" => Some(Adapter::LiteLlm),
            ref t if t == "bedrock" || t == "awsbedrock" => Some(Adapter::Bedrock),
            ref t if t == "csv" || t == "csvlogs" => Some(Adapter::Csv),
            ref t if t == "csvapprovals" || t == "approvalscsv" => Some(Adapter::CsvApprovals),
            _ => None,
        }
    }

    /// Every accepted token, for help text.
    pub fn known() -> &'static [&'static str] {
        &["openai", "litellm", "bedrock", "csv", "csv-approvals"]
    }

    pub fn output_kind(&self) -> OutputKind {
        match self {
            Adapter::CsvApprovals => OutputKind::Approvals,
            _ => OutputKind::Logs,
        }
    }

    /// A sensible default output filename for this adapter.
    pub fn default_out(&self) -> &'static str {
        match self.output_kind() {
            OutputKind::Logs => "compass-logs.jsonl",
            OutputKind::Approvals => "compass-approvals.jsonl",
        }
    }

    /// Convert a raw native export into canonical records.
    pub fn convert(&self, raw: &str) -> Result<Vec<Value>> {
        match self {
            Adapter::Openai => convert_json(raw, openai_record),
            Adapter::LiteLlm => convert_json(raw, litellm_record),
            Adapter::Bedrock => convert_json(raw, bedrock_record),
            Adapter::Csv => csv::convert_logs(raw),
            Adapter::CsvApprovals => csv::convert_approvals(raw),
        }
    }
}

/// Read JSONL (one object per line) or a JSON array, then map each element with
/// `f`. `f` returns one *or more* canonical records (e.g. one per tool call).
fn convert_json<F>(raw: &str, f: F) -> Result<Vec<Value>>
where
    F: Fn(&Value) -> Vec<Value>,
{
    let items = read_json_items(raw)?;
    let mut out = Vec::new();
    for item in &items {
        out.extend(f(item));
    }
    Ok(out)
}

/// Parse JSONL or a top-level JSON array into a flat list of values. Also
/// unwraps a common `{ "data": [ … ] }` list envelope (OpenAI list exports).
pub(crate) fn read_json_items(raw: &str) -> Result<Vec<Value>> {
    let trimmed = raw.trim_start();
    if trimmed.starts_with('[') {
        let arr: Vec<Value> = serde_json::from_str(raw).context("parsing JSON array")?;
        return Ok(arr);
    }
    if trimmed.starts_with('{') {
        // Could be a single object, or a list envelope. Try full-file parse
        // first (fails for true JSONL of multiple objects).
        if let Ok(v) = serde_json::from_str::<Value>(raw) {
            if let Some(data) = v.get("data").and_then(|d| d.as_array()) {
                return Ok(data.clone());
            }
            return Ok(vec![v]);
        }
    }
    // JSONL.
    let mut out = Vec::new();
    for (i, line) in raw.lines().enumerate() {
        let s = line.trim();
        if s.is_empty() || s.starts_with('#') {
            continue;
        }
        let v: Value =
            serde_json::from_str(s).with_context(|| format!("parsing JSONL line {}", i + 1))?;
        out.push(v);
    }
    if out.is_empty() {
        return Err(anyhow!("no records found in input"));
    }
    Ok(out)
}

// ── Small canonical-record builder ──────────────────────────────────────────

fn set_str(obj: &mut Map<String, Value>, key: &str, val: Option<String>) {
    if let Some(v) = val {
        if !v.is_empty() {
            obj.insert(key.to_string(), Value::String(v));
        }
    }
}

/// First present string among dotted paths (e.g. `identity.arn`).
fn dig_str(v: &Value, paths: &[&str]) -> Option<String> {
    for p in paths {
        let mut cur = v;
        let mut ok = true;
        for seg in p.split('.') {
            match cur.get(seg) {
                Some(next) => cur = next,
                None => {
                    ok = false;
                    break;
                }
            }
        }
        if ok {
            if let Some(s) = cur.as_str() {
                if !s.is_empty() {
                    return Some(s.to_string());
                }
            }
            if let Some(n) = cur.as_i64() {
                return Some(n.to_string());
            }
        }
    }
    None
}

/// Normalise a timestamp value to RFC 3339. Accepts a unix-seconds integer,
/// a unix-millis integer, or an already-formatted string (passed through).
fn ts_to_rfc3339(v: &Value) -> Option<String> {
    match v {
        Value::Number(n) => {
            let raw = n.as_i64()?;
            // Heuristic: > 10^12 → milliseconds.
            let secs = if raw > 1_000_000_000_000 {
                raw / 1000
            } else {
                raw
            };
            chrono::DateTime::from_timestamp(secs, 0).map(|dt| dt.to_rfc3339())
        }
        Value::String(s) if !s.is_empty() => {
            // If it's a bare integer string, treat as unix seconds.
            if let Ok(secs) = s.parse::<i64>() {
                return chrono::DateTime::from_timestamp(secs, 0).map(|dt| dt.to_rfc3339());
            }
            Some(s.clone())
        }
        _ => None,
    }
}

/// Extract every tool/function name from an OpenAI-shaped message/response.
fn openai_tool_names(v: &Value) -> Vec<String> {
    let mut names = Vec::new();
    if let Some(choices) = v.get("choices").and_then(|c| c.as_array()) {
        for choice in choices {
            if let Some(calls) = choice
                .get("message")
                .and_then(|m| m.get("tool_calls"))
                .and_then(|t| t.as_array())
            {
                for call in calls {
                    if let Some(name) = call
                        .get("function")
                        .and_then(|f| f.get("name"))
                        .and_then(|n| n.as_str())
                    {
                        names.push(name.to_string());
                    }
                }
            }
            // Legacy single function_call.
            if let Some(name) = choice
                .get("message")
                .and_then(|m| m.get("function_call"))
                .and_then(|f| f.get("name"))
                .and_then(|n| n.as_str())
            {
                names.push(name.to_string());
            }
        }
    }
    names
}

// ── Per-provider record builders ────────────────────────────────────────────

fn openai_record(v: &Value) -> Vec<Value> {
    let request_id = dig_str(v, &["id", "request_id"]);
    let model = dig_str(v, &["model"]);
    let user_id = dig_str(v, &["user", "metadata.user_id", "metadata.user"]);
    let ts = v.get("created").and_then(ts_to_rfc3339);

    let base = |tool: Option<String>| -> Value {
        let mut o = Map::new();
        set_str(&mut o, "request_id", request_id.clone());
        set_str(&mut o, "model", model.clone());
        o.insert("provider".into(), Value::String("openai".into()));
        set_str(&mut o, "user_id", user_id.clone());
        set_str(&mut o, "timestamp", ts.clone());
        set_str(&mut o, "tool_name", tool);
        Value::Object(o)
    };

    let tools = openai_tool_names(v);
    if tools.is_empty() {
        vec![base(None)]
    } else {
        tools.into_iter().map(|t| base(Some(t))).collect()
    }
}

fn litellm_record(v: &Value) -> Vec<Value> {
    let request_id = dig_str(v, &["request_id", "id", "litellm_call_id"]);
    let model = dig_str(v, &["model", "response.model"]);
    let provider =
        dig_str(v, &["custom_llm_provider", "provider"]).unwrap_or_else(|| "litellm".to_string());
    let user_id = dig_str(v, &["user", "end_user", "metadata.user_api_key_user_id"]);
    let ts = v
        .get("startTime")
        .or_else(|| v.get("start_time"))
        .and_then(ts_to_rfc3339);

    // LiteLLM mirrors the OpenAI response shape under `response`.
    let tools = v.get("response").map(openai_tool_names).unwrap_or_default();

    let base = |tool: Option<String>| -> Value {
        let mut o = Map::new();
        set_str(&mut o, "request_id", request_id.clone());
        set_str(&mut o, "model", model.clone());
        o.insert("provider".into(), Value::String(provider.clone()));
        set_str(&mut o, "user_id", user_id.clone());
        set_str(&mut o, "timestamp", ts.clone());
        set_str(&mut o, "tool_name", tool);
        Value::Object(o)
    };

    if tools.is_empty() {
        vec![base(None)]
    } else {
        tools.into_iter().map(|t| base(Some(t))).collect()
    }
}

fn bedrock_record(v: &Value) -> Vec<Value> {
    let request_id = dig_str(v, &["requestId", "request_id"]);
    let model = dig_str(v, &["modelId", "model_id"]);
    let user_id = dig_str(v, &["identity.arn", "identity.principalId", "accountId"]);
    let ts = v
        .get("timestamp")
        .and_then(ts_to_rfc3339)
        .or_else(|| dig_str(v, &["timestamp"]));

    // Bedrock Converse tool use lives under output → message content blocks.
    let mut tools = Vec::new();
    collect_bedrock_tool_names(v, &mut tools);

    let base = |tool: Option<String>| -> Value {
        let mut o = Map::new();
        set_str(&mut o, "request_id", request_id.clone());
        set_str(&mut o, "model", model.clone());
        o.insert("provider".into(), Value::String("bedrock".into()));
        set_str(&mut o, "user_id", user_id.clone());
        set_str(&mut o, "timestamp", ts.clone());
        set_str(&mut o, "tool_name", tool);
        Value::Object(o)
    };

    if tools.is_empty() {
        vec![base(None)]
    } else {
        tools.into_iter().map(|t| base(Some(t))).collect()
    }
}

/// Walk a Bedrock invocation record for `toolUse.name` occurrences anywhere in
/// the output body (Converse) — the structure nests differently across models,
/// so a recursive scan is the most robust option.
fn collect_bedrock_tool_names(v: &Value, out: &mut Vec<String>) {
    match v {
        Value::Object(m) => {
            if let Some(name) = m
                .get("toolUse")
                .and_then(|t| t.get("name"))
                .and_then(|n| n.as_str())
            {
                out.push(name.to_string());
            }
            for val in m.values() {
                collect_bedrock_tool_names(val, out);
            }
        }
        Value::Array(a) => {
            for val in a {
                collect_bedrock_tool_names(val, out);
            }
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_adapter_tokens() {
        assert_eq!(Adapter::parse("openai"), Some(Adapter::Openai));
        assert_eq!(Adapter::parse("LiteLLM"), Some(Adapter::LiteLlm));
        assert_eq!(Adapter::parse("aws-bedrock"), Some(Adapter::Bedrock));
        assert_eq!(Adapter::parse("csv"), Some(Adapter::Csv));
        assert_eq!(Adapter::parse("csv-approvals"), Some(Adapter::CsvApprovals));
        assert_eq!(Adapter::parse("nope"), None);
    }

    #[test]
    fn openai_emits_one_record_per_tool_call() {
        let raw = r#"{"id":"cmpl-1","model":"gpt-4o","created":1735689600,"user":"u1",
          "choices":[{"message":{"tool_calls":[
            {"function":{"name":"read_file"}},
            {"function":{"name":"delete_database"}}
          ]}}]}"#;
        let out = Adapter::Openai.convert(raw).unwrap();
        assert_eq!(out.len(), 2);
        assert_eq!(out[0]["request_id"], "cmpl-1");
        assert_eq!(out[0]["provider"], "openai");
        assert_eq!(out[1]["tool_name"], "delete_database");
        assert!(out[0]["timestamp"]
            .as_str()
            .unwrap()
            .starts_with("2025-01-01"));
    }

    #[test]
    fn openai_no_tools_still_emits_record() {
        let raw = r#"{"id":"c2","model":"gpt-4o","choices":[{"message":{"content":"hi"}}]}"#;
        let out = Adapter::Openai.convert(raw).unwrap();
        assert_eq!(out.len(), 1);
        assert!(out[0].get("tool_name").is_none());
    }

    #[test]
    fn litellm_reads_response_tool_calls() {
        let raw = r#"{"request_id":"r1","model":"gpt-4o","custom_llm_provider":"azure",
          "user":"alice","startTime":"2026-01-01T00:00:00Z",
          "response":{"choices":[{"message":{"tool_calls":[{"function":{"name":"make_payment"}}]}}]}}"#;
        let out = Adapter::LiteLlm.convert(raw).unwrap();
        assert_eq!(out.len(), 1);
        assert_eq!(out[0]["provider"], "azure");
        assert_eq!(out[0]["tool_name"], "make_payment");
        assert_eq!(out[0]["user_id"], "alice");
    }

    #[test]
    fn bedrock_finds_nested_tool_use() {
        let raw = r#"{"requestId":"req-9","modelId":"anthropic.claude-3",
          "identity":{"arn":"arn:aws:iam::1:user/bob"},"timestamp":"2026-02-02T10:00:00Z",
          "output":{"outputBodyJson":{"output":{"message":{"content":[
            {"toolUse":{"name":"transfer_funds"}}]}}}}}"#;
        let out = Adapter::Bedrock.convert(raw).unwrap();
        assert_eq!(out.len(), 1);
        assert_eq!(out[0]["tool_name"], "transfer_funds");
        assert_eq!(out[0]["user_id"], "arn:aws:iam::1:user/bob");
        assert_eq!(out[0]["provider"], "bedrock");
    }

    #[test]
    fn reads_openai_list_envelope() {
        let raw = r#"{"object":"list","data":[
          {"id":"a","model":"gpt-4o","choices":[{"message":{"content":"x"}}]},
          {"id":"b","model":"gpt-4o","choices":[{"message":{"content":"y"}}]}]}"#;
        let out = Adapter::Openai.convert(raw).unwrap();
        assert_eq!(out.len(), 2);
    }
}
