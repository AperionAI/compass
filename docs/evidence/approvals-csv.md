# Approvals (human oversight)

The `human_oversight` check measures whether your review of agent actions is
real: override rate (rubber-stamping), review latency (automation bias), and
outlier reviewers. It needs a record of decisions. A CSV works, which means you
can usually get it out of Jira, ServiceNow, or a spreadsheet in a few minutes.

## The four columns that matter

| Canonical | Accepted headers (any of) |
|-----------|---------------------------|
| decision  | `status`, `decision`, `outcome`, `result`, `action` |
| reviewer  | `approver_id`, `approver`, `reviewer`, `approved_by`, `reviewed_by` |
| created   | `created_at`, `created`, `requested_at`, `opened_at`, `start` |
| decided   | `decided_at`, `decided`, `resolved_at`, `closed_at`, `approved_at` |

Only the decision column is required. Reviewer + the two timestamps unlock
per-reviewer override rates and latency, which is where the interesting signal
lives.

Decision values are normalised: `approve/approved/accept/yes/ok/allow` →
approved; `deny/denied/reject/rejected/no/blocked/override` → denied. Anything
else passes through unchanged.

Timestamps can be RFC 3339 (`2026-07-01T14:03:00Z`) or unix seconds.

## Example

```csv
reviewer,decision,created,decided
alice,approved,2026-07-01T14:00:00Z,2026-07-01T14:00:40Z
alice,denied,2026-07-01T15:00:00Z,2026-07-01T15:02:10Z
bob,approved,2026-07-01T16:00:00Z,2026-07-01T16:00:03Z
```

## Convert + register

```bash
compass ingest --from csv-approvals --input approvals.csv
compass doctor
```

## Exporting from common systems

- **Jira** — filter to your approval issue type, then *Export → CSV (current
  fields)*. Map: Assignee → reviewer, Resolution → decision, Created → created,
  Resolved → decided.
- **ServiceNow** — on the approval table list, right-click the header →
  *Export → CSV*. Map: `approver` → reviewer, `state` → decision,
  `sys_created_on` → created, `sys_updated_on` → decided.
- **Spreadsheet** — just name the columns as above and *Save as CSV*.

## What "healthy" looks like

Compass flags: a global or per-reviewer override rate below 5% (rubber-stamping
over ≥10 decisions), a median review latency under 3 seconds (faster than a
human can meaningfully review), and reviewers whose rate or speed sits more
than 2σ from the cohort. These thresholds mirror what Singapore's IMDA agentic
framework recommends tracking.
