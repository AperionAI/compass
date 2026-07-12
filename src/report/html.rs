//! Self-contained HTML dashboard — the bundled template with the scorecard
//! JSON embedded, so it opens straight from `file://` and can be attached to
//! an email or board deck with no server.

use crate::scoring::Scorecard;
use anyhow::{Context, Result};

const TEMPLATE: &str = include_str!("../../templates/dashboard.html");
const PLACEHOLDER: &str = "__COMPASS_DATA__";

/// Render the scorecard into the dashboard template with data embedded.
pub fn render(card: &Scorecard) -> Result<String> {
    let json = serde_json::to_string(card).context("serialising scorecard for HTML")?;
    // Guard against `</script>` sequences in the embedded JSON breaking out of
    // the data island (JSON has no raw `<`, but be defensive).
    let safe = json.replace("</", "<\\/");
    Ok(TEMPLATE.replace(PLACEHOLDER, &safe))
}

/// The raw template with a `null` data island, for `serve` mode (data is
/// fetched live from `/api/scorecard`).
pub fn template_for_serve() -> String {
    TEMPLATE.replace(PLACEHOLDER, "null")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{catalog, evidence::EvidenceBundle, questionnaire::Assessment, scoring};

    #[test]
    fn embeds_data_and_has_no_placeholder() {
        let cats = catalog::load_selection(&["imda".into()]).unwrap();
        let a = Assessment::scaffold(&cats);
        let card = scoring::score(&cats, &a, &EvidenceBundle::default(), 70.0);
        let html = render(&card).unwrap();
        assert!(!html.contains(PLACEHOLDER));
        assert!(html.contains("Aperion Compass"));
        assert!(html.contains("overall_score"));
    }
}
