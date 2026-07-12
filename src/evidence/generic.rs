//! Generic log adapter for non-Smartflow users.
//!
//! Accepts any JSONL / JSON-array log and normalises a few common shapes into
//! the canonical keys [`LogRecord`](super::vas::LogRecord) reads, so users who
//! are not on Smartflow still get action-risk and logging-completeness signal.
//! Today it lifts OpenAI-style tool/function-call names to a top-level
//! `tool_name` and copies a nested `function.name` up, then defers to the same
//! forgiving accessors.

use super::vas::{self, LogRecord};
use anyhow::Result;
use serde_json::Value;

/// Load and normalise a generic log file.
pub fn load(path: &str) -> Result<Vec<LogRecord>> {
    let recs = vas::load(path)?;
    Ok(recs
        .into_iter()
        .map(|r| LogRecord(normalize(r.0)))
        .collect())
}

/// Best-effort normalisation of common third-party log shapes.
pub fn normalize(mut v: Value) -> Value {
    // Already has a recognised tool key → leave as-is.
    let has_tool = ["tool_name", "tool", "mcp_method", "method"]
        .iter()
        .any(|k| v.get(k).and_then(|x| x.as_str()).is_some());
    if has_tool {
        return v;
    }

    // OpenAI chat-completion style: choices[0].message.tool_calls[0].function.name
    if let Some(name) = openai_tool_name(&v) {
        if let Some(obj) = v.as_object_mut() {
            obj.insert("tool_name".to_string(), Value::String(name));
        }
        return v;
    }

    // Anthropic / generic: top-level `function` object with a `name`.
    if let Some(name) = v
        .get("function")
        .and_then(|f| f.get("name"))
        .and_then(|n| n.as_str())
    {
        let name = name.to_string();
        if let Some(obj) = v.as_object_mut() {
            obj.insert("tool_name".to_string(), Value::String(name));
        }
    }

    v
}

fn openai_tool_name(v: &Value) -> Option<String> {
    let choices = v.get("choices")?.as_array()?;
    for choice in choices {
        if let Some(calls) = choice
            .get("message")
            .and_then(|m| m.get("tool_calls"))
            .and_then(|t| t.as_array())
        {
            if let Some(first) = calls.first() {
                if let Some(name) = first
                    .get("function")
                    .and_then(|f| f.get("name"))
                    .and_then(|n| n.as_str())
                {
                    return Some(name.to_string());
                }
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lifts_openai_tool_call_name() {
        let v = serde_json::json!({
            "model": "gpt-4o",
            "choices": [{
                "message": {
                    "tool_calls": [{"function": {"name": "delete_record"}}]
                }
            }]
        });
        let n = normalize(v);
        assert_eq!(n.get("tool_name").unwrap(), "delete_record");
    }

    #[test]
    fn lifts_top_level_function_name() {
        let v = serde_json::json!({"function": {"name": "send_email"}});
        let n = normalize(v);
        assert_eq!(n.get("tool_name").unwrap(), "send_email");
    }

    #[test]
    fn leaves_existing_tool_name() {
        let v = serde_json::json!({"tool_name": "read_file", "function": {"name": "x"}});
        let n = normalize(v);
        assert_eq!(n.get("tool_name").unwrap(), "read_file");
    }
}
