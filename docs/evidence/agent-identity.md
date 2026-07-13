# Agent identity

The `agent_identity` check verifies **Ed25519-signed agent credentials**
offline against an issuer public key or JWKS. It answers the question the IMDA
framework and the "who owns your agent" debate keep circling: can you prove
which agent acted, and that its authority traces back to a named principal?

## What you need

1. A credential export — one JSON object per line (JSONL) or a JSON array —
   where each credential carries at least:
   - an agent id and the principal (human/org) it acts for
   - its scopes and validity window
   - `alg: "EdDSA"`, a base64 `signature`, and a `keyid`
2. The issuer's **public** key, as a JWKS document or a base64 Ed25519 key.
   Only the public key is needed — verification is offline and never touches a
   private key.

```bash
compass ingest \
  --credentials agent-credentials.jsonl \
  --jwks issuer-jwks.json
compass doctor
```

## Credential shape

Compass rebuilds the same canonical payload the issuer signed (agent id,
principal, scopes, issued/expiry) and checks the signature against the key
whose `kid` matches the credential's `keyid`. HMAC-only credentials (no
asymmetric signature) verify as **Warn** — present but not cryptographically
provable to a third party.

## If you're on Smartflow

Smartflow's AIDA issues exactly this: Ed25519 credentials binding each agent to
a human principal, published via a JWKS endpoint. Export the live credentials
and point `--jwks` at the AIDA JWKS URL's saved response. The offline check
reproduces the verification Smartflow does on the hot path.

## If you don't issue signed identities yet

That's a real finding, and it's the gap Smartflow's identity layer closes.
Compass will report `agent_identity` as a gap until you can produce signed
credentials — which is the honest state for most deployments today.
