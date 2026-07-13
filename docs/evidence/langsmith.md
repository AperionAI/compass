# LangSmith

If you trace your agent with LangSmith, you can export runs and feed them to
Compass. LangSmith runs aren't a single fixed shape, so the cleanest path is to
project the fields you need and register them as generic logs (or a CSV).

## Export runs

Using the LangSmith SDK, list runs and write one JSON object per line:

```python
from langsmith import Client
import json

client = Client()
with open("langsmith-runs.jsonl", "w") as f:
    for run in client.list_runs(project_name="my-agent", run_type="llm"):
        f.write(json.dumps({
            "request_id": str(run.id),
            "model": (run.extra or {}).get("metadata", {}).get("ls_model_name"),
            "provider": (run.extra or {}).get("metadata", {}).get("ls_provider"),
            "user_id": (run.extra or {}).get("metadata", {}).get("user_id"),
            "timestamp": run.start_time.isoformat() if run.start_time else None,
            # tool calls: pull the function name off tool/child runs
            "tool_name": next(
                (c.name for c in client.list_runs(parent_run_id=run.id, run_type="tool")),
                None,
            ),
        }) + "\n")
```

Adjust the metadata keys to whatever you set on your runs. Tool runs in
LangSmith are usually child runs of the LLM run, hence the `parent_run_id`
lookup.

## Register

The output already matches Compass's canonical field names, so register it
directly (no adapter needed):

```bash
compass ingest --generic langsmith-runs.jsonl
compass doctor
```

If you'd rather export a table, write a CSV with columns like
`request_id, model, provider, user_id, tool, timestamp` and use
`compass ingest --from csv --input langsmith.csv`.
