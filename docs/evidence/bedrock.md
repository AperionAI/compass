# AWS Bedrock

Bedrock writes structured invocation logs when you enable **model invocation
logging**. Compass reads those records and finds tool use anywhere in the
Converse output.

## 1. Enable model invocation logging

In the Bedrock console → **Settings → Model invocation logging**, enable logging
to **S3** (or CloudWatch Logs). Include request and response body data.

## 2. Pull the logs

From S3:

```bash
aws s3 cp --recursive s3://your-bedrock-logs-bucket/AWSLogs/…/ ./bedrock-logs/
cat ./bedrock-logs/*.json.gz | gunzip > bedrock-invocations.jsonl
```

Each record looks roughly like:

```json
{"requestId":"…","modelId":"anthropic.claude-3-5-sonnet",
 "identity":{"arn":"arn:aws:iam::123:role/agent"},"timestamp":"2026-07-01T…",
 "output":{"outputBodyJson":{"output":{"message":{"content":[
   {"toolUse":{"name":"transfer_funds"}}]}}}}}
```

## 3. Convert + register

```bash
compass ingest --from bedrock --input bedrock-invocations.jsonl
compass doctor
```

Compass extracts:

- `request_id` ← `requestId`
- `model` ← `modelId`
- `user_id` ← `identity.arn` (the IAM principal — good identity evidence)
- `timestamp` ← `timestamp`
- `tool_name` ← every `toolUse.name` found in the output body (recursive scan,
  since the nesting varies by model)

## Note on data residency

Bedrock invocation logs stay in your AWS account and region. Compass runs
locally against the export — nothing leaves your environment. This is the same
point worth making to any customer asking about residency: assessing the logs
doesn't move them.
