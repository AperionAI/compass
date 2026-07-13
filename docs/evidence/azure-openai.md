# Azure OpenAI

Azure OpenAI response bodies use the same shape as OpenAI, so the `openai`
adapter handles them once you have the logs out of Azure. The usual path is
**diagnostic settings → Log Analytics**, then a query export.

## 1. Turn on request/response logging

In the Azure portal, open your Azure OpenAI resource →
**Monitoring → Diagnostic settings → Add diagnostic setting**. Send
`RequestResponse` (and `Audit`) logs to a **Log Analytics workspace**.

## 2. Export with a Kusto query

In Log Analytics, run a query that projects the fields Compass wants, then use
**Export → JSON**:

```kusto
AzureDiagnostics
| where ResourceProvider == "MICROSOFT.COGNITIVESERVICES"
| where Category == "RequestResponse"
| project
    id           = CorrelationId,
    model        = properties_modelDeploymentName_s,
    user         = properties_user_s,
    created      = TimeGenerated,
    choices      = todynamic(properties_response_s).choices
| limit 1000
```

Adjust column names to match your workspace schema (they drift between API
versions). The goal is an array of objects with `id`, `model`, `user`,
`created`, and a `choices` array carrying any `tool_calls`.

## 3. Convert + register

```bash
compass ingest --from openai --input azure-export.json
compass doctor
```

If your Azure export is flat (no nested `choices`), export it as a CSV with
columns like `request_id, model, user, tool, time` and use the `csv` adapter
instead — see [the CSV field spec](README.md#roll-your-own-minimal-field-spec).

## Simpler: record going forward

Most Azure OpenAI users front their traffic with a gateway. Point that gateway
(or your SDK) at `compass record` to capture evidence directly — see
[record.md](record.md).
