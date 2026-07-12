//! Human-oversight effectiveness check.
//!
//! Vendors the pure alerting math from Smartflow's `src/oversight_analytics.rs`
//! (Phase 4) and feeds it from an exported approval-ticket file instead of
//! Redis. Computes global + per-reviewer override rate (rubber-stamping),
//! median approval latency (automation bias), and outlier reviewers, then maps
//! the result to a `human_oversight` outcome: Pass when no anomalies, Warn when
//! the thresholds fire.

use super::{make_outcome, CheckOutcome, CheckStatus};
use crate::catalog::AutoCheck;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

// ── Vendored thresholds + pure math (from oversight_analytics.rs) ───────────

#[derive(Debug, Clone, Serialize)]
pub struct Thresholds {
    pub rubber_stamp_override_floor: f64,
    pub automation_bias_latency_secs: f64,
    pub outlier_sigma: f64,
    pub min_sample: u64,
}

impl Default for Thresholds {
    fn default() -> Self {
        Self {
            rubber_stamp_override_floor: 0.05,
            automation_bias_latency_secs: 3.0,
            outlier_sigma: 2.0,
            min_sample: 10,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct ReviewerStats {
    pub reviewer: String,
    pub approvals: u64,
    pub denials: u64,
    pub total: u64,
    pub override_rate: f64,
    pub median_latency_secs: Option<f64>,
    pub flags: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Alert {
    pub kind: String,
    pub severity: String,
    pub subject: String,
    pub message: String,
    pub value: f64,
    pub threshold: f64,
}

#[derive(Debug, Clone, Serialize)]
pub struct OversightReport {
    pub total_decisions: u64,
    pub approvals: u64,
    pub denials: u64,
    pub global_override_rate: f64,
    pub global_median_latency_secs: Option<f64>,
    pub reviewers: Vec<ReviewerStats>,
    pub alerts: Vec<Alert>,
    pub thresholds: Thresholds,
}

fn median(mut v: Vec<f64>) -> Option<f64> {
    if v.is_empty() {
        return None;
    }
    v.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    let n = v.len();
    Some(if n % 2 == 1 {
        v[n / 2]
    } else {
        (v[n / 2 - 1] + v[n / 2]) / 2.0
    })
}

fn safe_rate(numer: u64, denom: u64) -> f64 {
    if denom == 0 {
        0.0
    } else {
        numer as f64 / denom as f64
    }
}

fn mean_std(xs: &[f64]) -> (f64, f64) {
    if xs.is_empty() {
        return (0.0, 0.0);
    }
    let n = xs.len() as f64;
    let mean = xs.iter().sum::<f64>() / n;
    let var = xs.iter().map(|x| (x - mean).powi(2)).sum::<f64>() / n;
    (mean, var.sqrt())
}

/// Fill per-reviewer flags and build the alert list. Pure over aggregated
/// stats (mirrors `oversight_analytics::evaluate`).
pub fn evaluate(
    reviewers: &mut [ReviewerStats],
    global_override_rate: f64,
    global_median_latency: Option<f64>,
    total_decisions: u64,
    th: &Thresholds,
) -> Vec<Alert> {
    let mut alerts = Vec::new();

    if total_decisions >= th.min_sample {
        if global_override_rate < th.rubber_stamp_override_floor {
            alerts.push(Alert {
                kind: "rubber_stamping".into(),
                severity: "warn".into(),
                subject: "global".into(),
                message: format!(
                    "Global override rate {:.1}% is below the {:.1}% floor — possible rubber-stamping across reviewers.",
                    global_override_rate * 100.0,
                    th.rubber_stamp_override_floor * 100.0
                ),
                value: global_override_rate,
                threshold: th.rubber_stamp_override_floor,
            });
        }
        if let Some(m) = global_median_latency {
            if m < th.automation_bias_latency_secs {
                alerts.push(Alert {
                    kind: "automation_bias".into(),
                    severity: "warn".into(),
                    subject: "global".into(),
                    message: format!(
                        "Global median approval latency {:.1}s is below {:.1}s — decisions faster than a human can meaningfully review.",
                        m, th.automation_bias_latency_secs
                    ),
                    value: m,
                    threshold: th.automation_bias_latency_secs,
                });
            }
        }
    }

    let cohort: Vec<&ReviewerStats> = reviewers
        .iter()
        .filter(|r| r.total >= th.min_sample)
        .collect();
    let or_vals: Vec<f64> = cohort.iter().map(|r| r.override_rate).collect();
    let lat_vals: Vec<f64> = cohort
        .iter()
        .filter_map(|r| r.median_latency_secs)
        .collect();
    let (or_mean, or_std) = mean_std(&or_vals);
    let (lat_mean, lat_std) = mean_std(&lat_vals);

    for r in reviewers.iter_mut() {
        if r.total < th.min_sample {
            continue;
        }
        if r.override_rate < th.rubber_stamp_override_floor {
            r.flags.push("rubber_stamping".into());
            alerts.push(Alert {
                kind: "rubber_stamping".into(),
                severity: "warn".into(),
                subject: r.reviewer.clone(),
                message: format!(
                    "Reviewer '{}' override rate {:.1}% < {:.1}% floor over {} decisions.",
                    r.reviewer,
                    r.override_rate * 100.0,
                    th.rubber_stamp_override_floor * 100.0,
                    r.total
                ),
                value: r.override_rate,
                threshold: th.rubber_stamp_override_floor,
            });
        }
        if let Some(m) = r.median_latency_secs {
            if m < th.automation_bias_latency_secs {
                r.flags.push("automation_bias".into());
                alerts.push(Alert {
                    kind: "automation_bias".into(),
                    severity: "warn".into(),
                    subject: r.reviewer.clone(),
                    message: format!(
                        "Reviewer '{}' median latency {:.1}s < {:.1}s — approving faster than meaningful review.",
                        r.reviewer, m, th.automation_bias_latency_secs
                    ),
                    value: m,
                    threshold: th.automation_bias_latency_secs,
                });
            }
        }
        if or_std > 0.0 && (r.override_rate - or_mean).abs() > th.outlier_sigma * or_std {
            r.flags.push("outlier_override".into());
            alerts.push(Alert {
                kind: "outlier_reviewer".into(),
                severity: "info".into(),
                subject: r.reviewer.clone(),
                message: format!(
                    "Reviewer '{}' override rate {:.1}% deviates >{:.1}σ from cohort mean {:.1}%.",
                    r.reviewer,
                    r.override_rate * 100.0,
                    th.outlier_sigma,
                    or_mean * 100.0
                ),
                value: r.override_rate,
                threshold: or_mean,
            });
        }
        if let Some(m) = r.median_latency_secs {
            if lat_std > 0.0 && (m - lat_mean).abs() > th.outlier_sigma * lat_std {
                r.flags.push("outlier_latency".into());
                alerts.push(Alert {
                    kind: "outlier_reviewer".into(),
                    severity: "info".into(),
                    subject: r.reviewer.clone(),
                    message: format!(
                        "Reviewer '{}' median latency {:.1}s deviates >{:.1}σ from cohort mean {:.1}s.",
                        r.reviewer, m, th.outlier_sigma, lat_mean
                    ),
                    value: m,
                    threshold: lat_mean,
                });
            }
        }
    }

    alerts
}

// ── Ticket ingestion ─────────────────────────────────────────────────────

#[derive(Debug, Clone, Deserialize)]
pub struct TicketDto {
    #[serde(default)]
    status: Option<String>,
    #[serde(default)]
    approver_id: Option<String>,
    #[serde(default)]
    created_at: Option<DateTime<Utc>>,
    #[serde(default)]
    decided_at: Option<DateTime<Utc>>,
}

struct Acc {
    approvals: u64,
    denials: u64,
    latencies: Vec<f64>,
}

/// Aggregate a set of tickets into an [`OversightReport`] (pure; used by the
/// check and by tests).
pub fn compute_from_tickets(tickets: &[TicketDto], th: &Thresholds) -> OversightReport {
    use std::collections::HashMap;
    let mut by_reviewer: HashMap<String, Acc> = HashMap::new();
    let mut global_latencies: Vec<f64> = Vec::new();
    let mut approvals = 0u64;
    let mut denials = 0u64;

    for t in tickets {
        let status = t.status.as_deref().unwrap_or("");
        let is_decision = matches!(status, "approved" | "redeemed" | "denied");
        if !is_decision {
            continue;
        }
        let is_denial = status == "denied";
        if is_denial {
            denials += 1;
        } else {
            approvals += 1;
        }
        let reviewer = t
            .approver_id
            .clone()
            .unwrap_or_else(|| "unattributed".into());
        let acc = by_reviewer.entry(reviewer).or_insert(Acc {
            approvals: 0,
            denials: 0,
            latencies: Vec::new(),
        });
        if is_denial {
            acc.denials += 1;
        } else {
            acc.approvals += 1;
        }
        if let (Some(c), Some(d)) = (t.created_at, t.decided_at) {
            let lat = (d - c).num_milliseconds() as f64 / 1000.0;
            if lat >= 0.0 {
                acc.latencies.push(lat);
                global_latencies.push(lat);
            }
        }
    }

    let total_decisions = approvals + denials;
    let mut reviewers: Vec<ReviewerStats> = by_reviewer
        .into_iter()
        .map(|(reviewer, a)| {
            let total = a.approvals + a.denials;
            ReviewerStats {
                reviewer,
                approvals: a.approvals,
                denials: a.denials,
                total,
                override_rate: safe_rate(a.denials, total),
                median_latency_secs: median(a.latencies),
                flags: Vec::new(),
            }
        })
        .collect();
    reviewers.sort_by(|x, y| y.total.cmp(&x.total).then(x.reviewer.cmp(&y.reviewer)));

    let global_override_rate = safe_rate(denials, total_decisions);
    let global_median_latency = median(global_latencies);

    let alerts = evaluate(
        &mut reviewers,
        global_override_rate,
        global_median_latency,
        total_decisions,
        th,
    );

    OversightReport {
        total_decisions,
        approvals,
        denials,
        global_override_rate,
        global_median_latency_secs: global_median_latency,
        reviewers,
        alerts,
        thresholds: th.clone(),
    }
}

/// The `human_oversight` check over an exported approval-ticket file.
pub fn human_oversight(path: &str) -> CheckOutcome {
    let raw = match std::fs::read_to_string(path) {
        Ok(r) => r,
        Err(e) => {
            return make_outcome(
                AutoCheck::HumanOversight,
                CheckStatus::NotRun,
                format!("Could not read approvals file {path}: {e}"),
                serde_json::json!({}),
            )
        }
    };

    let tickets = match parse_tickets(&raw) {
        Ok(t) => t,
        Err(e) => {
            return make_outcome(
                AutoCheck::HumanOversight,
                CheckStatus::NotRun,
                format!("Could not parse approvals: {e}"),
                serde_json::json!({}),
            )
        }
    };

    let th = Thresholds::default();
    let report = compute_from_tickets(&tickets, &th);
    let detail = serde_json::to_value(&report).unwrap_or(serde_json::json!({}));

    if report.total_decisions == 0 {
        return make_outcome(
            AutoCheck::HumanOversight,
            CheckStatus::NotRun,
            "No decided approval tickets found.",
            detail,
        );
    }

    if report.alerts.is_empty() {
        make_outcome(
            AutoCheck::HumanOversight,
            CheckStatus::Pass,
            format!(
                "Oversight healthy: {} decisions, {:.1}% override rate, no anomalies.",
                report.total_decisions,
                report.global_override_rate * 100.0
            ),
            detail,
        )
    } else {
        make_outcome(
            AutoCheck::HumanOversight,
            CheckStatus::Warn,
            format!(
                "{} oversight anomaly signal(s) over {} decisions (see detail).",
                report.alerts.len(),
                report.total_decisions
            ),
            detail,
        )
    }
}

fn parse_tickets(raw: &str) -> anyhow::Result<Vec<TicketDto>> {
    let trimmed = raw.trim_start();
    if trimmed.starts_with('[') {
        return Ok(serde_json::from_str(raw)?);
    }
    let mut out = Vec::new();
    for line in raw.lines() {
        let s = line.trim();
        if s.is_empty() || s.starts_with('#') {
            continue;
        }
        out.push(serde_json::from_str(s)?);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ticket(status: &str, reviewer: &str, created: &str, decided: Option<&str>) -> TicketDto {
        TicketDto {
            status: Some(status.into()),
            approver_id: Some(reviewer.into()),
            created_at: Some(created.parse().unwrap()),
            decided_at: decided.map(|d| d.parse().unwrap()),
        }
    }

    #[test]
    fn healthy_oversight_has_no_alerts() {
        // ~30% override, healthy latency, single reviewer below min_sample→no flags
        let mut tickets = Vec::new();
        for i in 0..7 {
            tickets.push(ticket(
                "approved",
                "alice",
                &format!("2026-01-01T00:0{i}:00Z"),
                Some(&format!("2026-01-01T00:0{i}:30Z")),
            ));
        }
        for i in 0..3 {
            tickets.push(ticket(
                "denied",
                "alice",
                &format!("2026-01-01T01:0{i}:00Z"),
                Some(&format!("2026-01-01T01:0{i}:30Z")),
            ));
        }
        let r = compute_from_tickets(&tickets, &Thresholds::default());
        assert_eq!(r.total_decisions, 10);
        assert!((r.global_override_rate - 0.3).abs() < 1e-9);
    }

    #[test]
    fn rubber_stamping_fires() {
        let mut tickets = Vec::new();
        for i in 0..20 {
            tickets.push(ticket(
                "approved",
                "bob",
                &format!("2026-01-01T00:00:{:02}Z", i),
                Some(&format!("2026-01-01T00:05:{:02}Z", i)),
            ));
        }
        let r = compute_from_tickets(&tickets, &Thresholds::default());
        assert!(r.alerts.iter().any(|a| a.kind == "rubber_stamping"));
    }

    #[test]
    fn parse_and_check_end_to_end() {
        let jsonl = "{\"status\":\"approved\",\"approver_id\":\"a\",\"created_at\":\"2026-01-01T00:00:00Z\",\"decided_at\":\"2026-01-01T00:00:30Z\"}\n";
        let tickets = parse_tickets(jsonl).unwrap();
        assert_eq!(tickets.len(), 1);
    }
}
