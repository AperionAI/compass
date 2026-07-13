# LiteLLM

LiteLLM is a common gateway in front of many providers, and it already logs
every call. Two shapes work.

## Option A — file logging (standard logging payload)

Enable the JSON file logger on your LiteLLM proxy (`config.yaml`):

```yaml
litellm_settings:
  json_logs: true
  # or a callback that writes the standard logging payload to disk
```

Each line carries `request_id`, `model`, `custom_llm_provider`, `user`,
`startTime`, and a `response` object mirroring the OpenAI shape (so tool calls
come through).

## Option B — spend logs (database export)

If you run LiteLLM with a database, export the `LiteLLM_SpendLogs` table to
JSON. Compass reads `request_id`, `model`, `user`, and `startTime` from each
row; tool names come through when the row includes the `response` payload.

```sql
COPY (SELECT request_id, model, "user", "startTime", custom_llm_provider, response
      FROM "LiteLLM_SpendLogs")
TO STDOUT WITH (FORMAT csv, HEADER);
```

(JSON export works too; the adapter reads JSONL or a JSON array.)

## Convert + register

```bash
compass ingest --from litellm --input litellm-logs.jsonl
compass doctor
```

Compass extracts `request_id`, `model`, `provider` (from
`custom_llm_provider`), `user_id` (from `user`), `timestamp` (from
`startTime`), and every `tool_name` in the response.

## Record instead

Because LiteLLM speaks the OpenAI API over http on localhost, it's also the
easiest upstream for `compass record`:

```bash
compass record --upstream http://localhost:4000
```

Point your app at the recorder, and the recorder forwards to LiteLLM while
writing a tamper-evident chain. See [record.md](record.md).
