//! Machine-readable JSON report — the full scorecard, pretty-printed.

use crate::scoring::Scorecard;
use anyhow::{Context, Result};

pub fn render(card: &Scorecard) -> Result<String> {
    serde_json::to_string_pretty(card).context("serialising scorecard to JSON")
}
