# AI Audit Assistant

Open **Security Results → AI Audit Assistant** using an identity with the current on-chain audit permission. Generate a report for 1, 24 or 168 hours, optionally filtered by stable identity address. Save the result as JSON for later review. Reports are downloaded, not persisted server-side. Scheduling is not implemented.

## Optional local model

The assistant uses Ollama's `/api/chat` endpoint (https://docs.ollama.com/api/chat). Install Ollama and pull a locally supported instruction model. Set `AUDIT_AI_MODEL` to its exact installed name. No automatic model download or external AI request occurs.

For a Node backend on the same host:

```
AUDIT_AI_URL=http://127.0.0.1:11434
AUDIT_AI_MODEL=<your-installed-model>
```

For the supplied Docker Compose app on macOS, put the following in your existing `.env`, preserving generated database passwords and encryption keys:

```
AUDIT_AI_URL=http://host.docker.internal:11434
AUDIT_AI_MODEL=<your-installed-model>
```

Restart/rebuild the app with `docker compose up -d --build app`. Ollama must be reachable from the container; a loopback-only listener may need configuration. Do not expose an unauthenticated model endpoint publicly. Native Linux needs an explicitly reachable host/service address. Keep the checkbox off until the model endpoint is configured. Select **Add AI explanations** to opt into inference. A failed or invalid model response yields an explicitly labelled rules-only report.

Model location is controlled by the operator. Indian/local data residency requires keeping the endpoint, its storage, logs and backups within that boundary. No third-party model is hardcoded.

## What the report means

- Counts and the five-denials-within-15-minutes rule are calculated in code, not by the LLM.
- Queries include at most 100 application records and at most 100 candidate contract events in the latest 2000 blocks. Time and identity filters apply. Reports expose bounds and truncation; these are samples, not complete histories.
- Failed login coverage is limited to events already recorded by the application. Not all rejected requests are logged by the existing app.
- Reverted transactions have no retained event logs. Supply up to five LedgerGuard contract transaction hashes to inspect receipts. Receipts are excluded from identity-filtered reports because historical controller-to-identity mapping is not reconstructed.
- Confirmed execution does not prove benign intent. Event counts are distinct from transaction counts.
- No document bodies, free-text log details, tokens or private keys are sent to the model. Actors/action names remain untrusted evidence. Log hashes are evidence references; the assistant does not verify checkpoint integrity or log completeness.
- Output must conform to a bounded JSON shape and cite known evidence IDs. This checks references, not semantic truth or immunity to prompt injection. Human review remains necessary.
- The model has no tools, signing keys or write actions. The UI renders explanations as escaped React text, not executable HTML/Markdown.
- Authentication and current audit permission are enforced before collection and rechecked after inference. Requests are limited to three per identity per minute and two concurrent jobs per app process, with a 45-second model timeout. Multi-instance deployments need shared concurrency controls.

## Verification

Run `npm test` and `npm run build`. Focused tests exercise report access, live permission revocation, deterministic counts, evidence references, context minimisation and rules-only fallback using a mock model. A real local model still needs evaluation for grounded explanations, malicious event text, false positives, latency and reviewer usefulness. Existing security tests do not prove model accuracy.
