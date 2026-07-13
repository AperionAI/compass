# Evidence playbooks

Compass scores a self-assessment on its own. The automated checks are what let
you *prove* the answers instead of just asserting them, and they run over logs
you already have. This folder shows how to get those logs out of the systems
you already run.

If you don't have any logs yet, that's the common case. Two ways forward:

1. **Convert an existing export.** Most providers already write request logs.
   Pull one and convert it in a single step:

   ```bash
   compass ingest --from openai   --input openai-export.jsonl
   compass ingest --from litellm  --input litellm-logs.jsonl
   compass ingest --from bedrock  --input bedrock-invocations.jsonl
   compass ingest --from csv      --input requests.csv
   ```

2. **Record from live traffic.** No logs at all? Put Compass in front of your
   model endpoint for a couple of weeks and it captures tamper-evident evidence
   as you go. See [record.md](record.md).

Then see where you stand and what's still missing:

```bash
compass doctor
```

## What each check needs

| Check | Evidence | Playbook |
|-------|----------|----------|
| `logging_completeness` | request logs | this page + provider guide below |
| `action_risk_coverage` | request/tool logs | this page + provider guide below |
| `human_oversight` | approval / review decisions | [approvals-csv.md](approvals-csv.md) |
| `audit_chain_integrity` | tamper-evident audit chain | [audit-chain.md](audit-chain.md), [record.md](record.md) |
| `agent_identity` | signed agent credentials + issuer key | [agent-identity.md](agent-identity.md) |

## Provider guides

- [OpenAI](openai.md)
- [Azure OpenAI](azure-openai.md)
- [LiteLLM](litellm.md)
- [AWS Bedrock](bedrock.md)
- [LangSmith](langsmith.md)

## Roll your own (minimal field spec)

Any adapter is optional. If your logs don't match a provider shape, emit JSONL
(one JSON object per line) with as many of these fields as you have. Compass is
forgiving — more fields mean more of the checks can run, but nothing is
required.

| Field | Aliases accepted | Feeds |
|-------|------------------|-------|
| `request_id` | `id`, `trace_id` | logging completeness |
| `model` | `model_id`, `deployment` | logging completeness |
| `provider` | `vendor` | logging completeness |
| `user_id` | `user`, `principal`, `actor` | identity coverage |
| `tool_name` | `tool`, `function`, `action`, `method` | action-risk tiering |
| `timestamp` | `time`, `created_at` | (context) |
| `action_risk_tier` | `risk_tier`, `tier` (`T1`/`T2`/`T3`) | action-risk (pre-stamped) |
| `intent` | `task_class` | action-risk hint |
| `approved_by` / `approval_id` | `approver_id` | links a T3 action to an approval |

Minimal example line:

```json
{"request_id":"r-1","model":"gpt-4o","provider":"openai","user_id":"u-42","tool_name":"send_wire_transfer","timestamp":"2026-07-01T14:03:00Z"}
```

Register it with `--generic`:

```bash
compass ingest --generic my-logs.jsonl
```

Everything here runs locally. Compass never uploads your logs anywhere.
