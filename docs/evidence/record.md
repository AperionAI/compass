# Recording live traffic (`compass record`)

No logs to export? Capture them as you go. `compass record` runs a localhost
reverse proxy that speaks the OpenAI-compatible HTTP API. Point your app's
`base_url` at it, and every call is forwarded to your real model endpoint while
Compass writes one tamper-evident, hash-chained record per call. Run it for a
week or two, then assess against real traffic.

## Start it

```bash
compass record --upstream http://localhost:4000 --port 8788 --out compass-record.jsonl
```

- `--upstream` — where to forward (http only; see TLS note below)
- `--port` — where your app connects (default 8788)
- `--out` — the JSONL file it writes (default `compass-record.jsonl`)
- `--hmac-key` — optional; when omitted, a key is generated and written to
  `<out>.key`

Point your client at it:

```python
from openai import OpenAI
client = OpenAI(base_url="http://localhost:8788/v1", api_key="…")
```

Your API key and headers pass straight through to the upstream. Compass reads
the request and response to record the model, user, and tool calls — it does
not alter them.

## What it writes

Each proxied call appends a sealed entry:

```json
{"seq":1,"prev_hash":"genesis","type":"llm_call","timestamp":"…","provider":"openai",
 "status_code":200,"model":"gpt-4o","request_id":"chatcmpl-…","user_id":"u-42",
 "tool_name":"send_wire_transfer","tool_names":["send_wire_transfer"],"entry_hmac":"<hex>"}
```

That one file is both the audit chain *and* the request log, so it powers three
checks at once:

```bash
compass verify --chain compass-record.jsonl --chain-hmac-key file:compass-record.jsonl.key

compass ingest \
  --chain   compass-record.jsonl --chain-hmac-key file:compass-record.jsonl.key \
  --generic compass-record.jsonl
compass report
```

Restarting the recorder against the same `--out` continues the chain rather
than forking it.

## Supported upstreams

Any OpenAI-compatible endpoint over **http**:

- Local model servers: Ollama (`:11434/v1`), vLLM, LM Studio, LocalAI
- Gateways: LiteLLM (`:4000`), your own proxy

## TLS note

This build forwards to `http://` upstreams only. To record traffic bound for a
hosted HTTPS API (OpenAI, Anthropic, Bedrock), put a local gateway such as
LiteLLM in front — your app → `compass record` (http) → LiteLLM → provider
(https). LiteLLM terminates TLS; Compass records the exchange. Direct-HTTPS
upstream support is on the roadmap.

## Privacy

`compass record` talks to exactly two things: the client on localhost and the
`--upstream` you name. It never contacts Aperion. The chain and key are written
locally. Request/response bodies are parsed only to extract the fields above;
the full bodies are not stored.
