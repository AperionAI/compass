//! Report renderers: JSON, Markdown, and a self-contained HTML dashboard.

pub mod html;
pub mod json;
pub mod markdown;

use crate::scoring::Scorecard;
use anyhow::Result;

/// Output formats `compass report` can emit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    Html,
    Markdown,
    Json,
}

impl Format {
    pub fn parse(s: &str) -> Option<Format> {
        match s.trim().to_ascii_lowercase().as_str() {
            "html" => Some(Format::Html),
            "md" | "markdown" => Some(Format::Markdown),
            "json" => Some(Format::Json),
            _ => None,
        }
    }

    pub fn ext(&self) -> &'static str {
        match self {
            Format::Html => "html",
            Format::Markdown => "md",
            Format::Json => "json",
        }
    }
}

/// Render a scorecard in the requested format to a string.
pub fn render(card: &Scorecard, format: Format) -> Result<String> {
    match format {
        Format::Html => html::render(card),
        Format::Markdown => Ok(markdown::render(card)),
        Format::Json => json::render(card),
    }
}
