# OpenAI

Compass reads OpenAI chat-completion / responses objects and lifts each tool
call into a canonical record.

## Option A — stored completions export

If you have [stored completions](https://platform.openai.com/docs/api-reference/chat)
enabled (`store: true` on your requests), list them and save the array:

```bash
curl https://api.openai.com/v1/chat/completions?limit=100 \
  -H "Authorization: Bearer $OPENAI_API_KEY" > openai-export.json
```

The export is a `{ "object": "list", "data": [ … ] }` envelope — Compass unwraps
`data` automatically.

## Option B — your own request/response log

If you already log each response object your app receives (recommended anyway),
concatenate them as JSONL — one response object per line:

```
{"id":"chatcmpl-…","model":"gpt-4o","created":1735689600,"user":"u-42","choices":[{"message":{"tool_calls":[{"function":{"name":"send_email"}}]}}]}
```

## Convert + register

```bash
compass ingest --from openai --input openai-export.json
compass doctor
```

Compass extracts:

- `request_id` ← `id`
- `model` ← `model`
- `user_id` ← `user` (set the `user` field on your requests so oversight and
  identity coverage light up)
- `tool_name` ← each `choices[].message.tool_calls[].function.name` (one record
  per tool call, so multi-tool responses are tiered individually)
- `timestamp` ← `created`

## Tip: capture it going forward

If you don't have a clean export, point your OpenAI SDK's `base_url` at
`compass record` for a couple of weeks — it captures the same fields plus a
tamper-evident chain. See [record.md](record.md).
