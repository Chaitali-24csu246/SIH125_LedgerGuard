# LedgerGuard

### Blockchain Identity, Secure Ownership Aware Access and AI Audit Assistance

**Team ADVITYAS · Smart India Hackathon 2026 · Problem Statement 26125 · Issuing organisation: BEL**

**Who owns this document, who can still open it, and what changed?**

LedgerGuard brings identity, access and digital asset ownership into one workflow. Employees can work with their assigned documents, administrators can manage handovers and permissions, and auditors can trace changes and generate readable activity summaries.

The current implementation is a **local working prototype** with a four-validator Hyperledger Besu **QBFT** network, encrypted off-chain documents and an optional locally hosted AI audit assistant. It is designed for organisational document workflows; it is not specific to BEL alone.

[Run the prototype](#run-the-prototype) · [Demo guide](DEMO.md) · [Architecture](docs/ARCHITECTURE.md) · [Security model](docs/SECURITY.md) · [AI assistant](docs/AI_AUDIT_ASSISTANT.md)

## What makes the workflow useful?

| Capability | What it means for the user |
|---|---|
| Ownership-aware access | A transfer invalidates earlier delegated grants, so access from the previous owner does not silently carry forward. |
| Identity continuity | Wallet rotation and controlled recovery preserve the same registered identity and its asset history. |
| Separate management and reading permissions | Someone allowed to manage or transfer an asset does not automatically get permission to read its contents. |
| Verifiable history | Ownership and access events can be checked against blockchain records when reviewing a handover or dispute. |
| AI-assisted audit review | An authorised reviewer can get an evidence-linked summary without first reading every event individually. |

These are the project's design strengths, not claims that no other system offers similar capabilities. The value is in bringing them together for the same identity and asset lifecycle.

## A document's journey

1. **Sign in:** unlock a local encrypted test wallet or connect a wallet extension, then sign a single-use challenge. The signature proves control of the registered wallet; current permissions determine allowed actions.
2. **Register:** an authorised administrator registers a document and creates its unique ERC-721 asset token. The encrypted document stays off-chain; its content commitment and asset records are on-chain.
3. **Allocate and share:** assign ownership and grant time-limited document access.
4. **Transfer:** hand over responsibility. Earlier delegated grants become invalid, and the new owner can decide access next.
5. **Download:** the server checks current permissions, decrypts the file and verifies its content hash against the contract.
6. **Review:** inspect recorded events and transaction receipts, or generate an advisory audit report.

The NFTs are created by LedgerGuard's own smart contract on its permissioned network. No public NFT marketplace or cryptocurrency purchase is needed.

## AI Audit Assistant

Available under **Security Results → AI Audit Assistant** to identities with current audit permission.

- Generate an on-demand report for **1, 24 or 168 hours**, optionally filtered by identity.
- Review activity counts and repeated-denial signals, with optional Ollama-generated explanations.
- Follow evidence references back to the events used in the report.
- Export the report as JSON.
- Receive a labelled **rules-only report** when the model is unavailable or its output fails validation.

**AI assists the reviewer; it does not authorise access, transfer assets, change roles or revoke identities.** Counts and policy signals are calculated in code. The model has no signing keys or write tools.

Reports use bounded event samples rather than a guaranteed complete history. Valid evidence references do not guarantee that an explanation is correct. Scheduled reporting is not implemented. See [AI scope and limitations](docs/AI_AUDIT_ASSISTANT.md).

## Technical approach

| Component | Technology | Why it is used |
|---|---|---|
| User interface | React + Vite | Role-aware views for assets, identity controls and audit review. |
| API | Node.js + Express | Shared JavaScript tooling for requests, signatures and contract integration. |
| Operational storage | PostgreSQL | Linked application records and encrypted off-chain documents. |
| Permissioned blockchain | Hyperledger Besu + QBFT | Shared contract state and transaction history across four local validators. |
| Contracts | Solidity + OpenZeppelin | Identity controls, ERC-721 assets, roles, grants and transfers. |
| Blockchain connection | ethers.js | Wallet signing, contract calls and receipt inspection. |
| Optional AI | Ollama + a configured local model | Read-only explanations over selected audit events. |
| Local deployment | Docker Compose | Repeatable application, database and blockchain setup. |

**Why a hybrid model?** PostgreSQL keeps document storage and application queries practical. Besu provides a shared record against which ownership and permissions can be checked. Blockchain adds operating complexity; it is most useful where multiple parties need shared verification. Traditional databases can also provide access controls and audit logs.

## Run the prototype

### Requirements

- Docker Desktop or Docker Engine with **Docker Compose v2**, running Linux containers.
- A current browser and free local ports **8080** and **8545**.
- Internet access for the first image and package downloads.
- Start with roughly **6–8 GB available to Docker**; this is a starting allocation, not a measured minimum. A local AI model needs additional host resources.

Python and a virtual environment are **not required**. The Docker setup supplies the Node, database and blockchain dependencies. Ollama is optional.

### 1. Get the project

```bash
git clone https://github.com/Chaitali-24csu246/SIH125_LedgerGuard.git
cd SIH125_LedgerGuard
```

If you already have the project, open a terminal in that folder instead.

### 2. Initialise and start

macOS / Linux:

```bash
sh scripts/setup.sh
```

Windows PowerShell:

```powershell
powershell -ExecutionPolicy Bypass -File scripts/setup.ps1
```

The script creates local test credentials and network configuration, starts PostgreSQL and four validators, deploys contracts when needed, then builds the app. It does not automatically erase an existing deployment.

### 3. Sign in

1. Open **http://localhost:8080**.
2. Select `generated/wallets/Admin.json` in the encrypted-wallet login.
3. Enter the password stored in `generated/WALLET-PASSWORD.txt`.
4. Click **Unlock locally**, then **Sign in with a signed challenge**.

The wallet is decrypted in the browser; the login request sends a signature, not the private key. Generated accounts are for this isolated test network only. Use the Manager, Auditor, Rahul or Priya wallets to explore other views.

For extension setup, recovery and native development, follow [SETUP.md](SETUP.md). For a guided presentation, follow [DEMO.md](DEMO.md).

### Preserve the generated configuration

Use **`--env-file generated/config.env`** in routine Compose commands. This file contains the credentials and encryption key created for this deployment. Do not replace it with guessed `.env` values or commit it to Git.

Changing database environment variables does not change a password already stored in the database. Replacing `FILE_KEY` does not re-encrypt existing documents and can make them unreadable.

### Optional: enable Ollama explanations

The rules-only report works without a model. To enable AI explanations:

1. Install and run [Ollama](https://ollama.com/), then download a model appropriate for your hardware and intended use.
2. Add these settings to **`generated/config.env`**, preserving every existing setting:

```dotenv
# Docker Desktop on macOS: model runs on the host
AUDIT_AI_URL=http://host.docker.internal:11434
AUDIT_AI_MODEL=your-installed-model-name
```

3. Ensure the model endpoint is reachable from the app container, then recreate the app:

```bash
docker compose --env-file generated/config.env up -d --build app
```

4. Open the assistant and select **Add AI explanations**.

On native Linux, configure an explicitly reachable private host/service address; the Docker Desktop hostname is not automatically available in every setup. Keep the model endpoint private: Ollama's local API does not require authentication. Do not expose port 11434 publicly.

Local inference avoids a per-request hosted-model API charge, but still uses compute and memory. Check the selected model's licence before organisational deployment. The prototype's `qwen2.5:3b` model has a [research licence with separate commercial-use requirements](https://huggingface.co/Qwen/Qwen2.5-3B-Instruct/blob/main/LICENSE).

## Routine commands

Run these from the project root:

```bash
# Service status and app logs
docker compose --env-file generated/config.env ps
docker compose --env-file generated/config.env logs --tail=80 app

# Check the local deployment
docker compose --env-file generated/config.env run --rm tools node scripts/doctor.mjs

# Stop without deleting stored state
docker compose --env-file generated/config.env stop

# Resume an existing deployment
docker compose --env-file generated/config.env up -d postgres besu1 besu2 besu3 besu4 app

# Rebuild after frontend/API changes
docker compose --env-file generated/config.env up -d --build app
```

On macOS/Linux, if the tools container cannot write generated files, run the following in the same terminal before invoking it:

```bash
export LOCAL_UID=$(id -u)
export LOCAL_GID=$(id -g)
```

Contract changes require a deliberate new deployment: these contracts are not upgradeable. See [SETUP.md](SETUP.md) and [RESET.md](RESET.md) before changing deployed state.

## Testing and validation

```bash
# Rebuild the tools image after changing tests or scripts
docker compose --env-file generated/config.env build tools

# Regression suite: isolated development chain + PostgreSQL WASM engine
docker compose --env-file generated/config.env run --rm tools npm test

# Experiments against the running local Besu/PostgreSQL application
docker compose --env-file generated/config.env run --rm tools npm run experiments

# Performance workload using isolated contracts
docker compose --env-file generated/config.env run --rm tools node experiments/benchmark.mjs
```

The live experiment runner writes test activity and imports a report into the app. Use the local demo environment, keep seeded identities active with their initial roles, and ensure asset operations are unpaused. See [verification instructions](SETUP.md#5-run-verification).

### Recorded prototype evidence

| Evidence reported for the demo | Scope |
|---|---|
| **26/26 regression tests passed** | Development-chain/API checks, including mocked AI handling. |
| **11/11 local Besu checks passed** | Checks against the local Besu deployment. |
| **40 seeded policy transitions** | Exercises changes in policy state; not 40 additional independent security tests. |

These are recorded results for the demonstrated prototype, not a live CI badge or a guarantee for every revision. Rerun the commands above for your checkout. The Security Results tab displays imported evidence; it does not itself run or create regression tests.

Checks cover scenarios such as reused login challenges, incorrect signatures, unauthorised access, stale grants, ownership-cache tampering and invalid/unavailable AI output. Tests support confidence in the behaviours exercised; they do not establish production security or real-model accuracy.

**Initial manual local timings:** approximately **1.6 seconds** to download a **189-byte file**, and **18 seconds** to generate an AI audit report. These observations do not establish large-file performance, concurrent-user capacity or measured audit-time savings.

See [VERIFICATION.md](docs/VERIFICATION.md) for stored evidence and environment distinctions, and [SECURITY.md](docs/SECURITY.md) for trust boundaries.

## Current boundaries and next steps

- **Local prototype:** four validators on one machine do not demonstrate independent infrastructure resilience. Cloud deployment and production load testing remain future work.
- **Identity model:** `did:sih` is a documented prototype DID method, not a registered or certified production DID implementation. See [DID_METHOD.md](docs/DID_METHOD.md).
- **Document protection:** revoked access blocks future authorised retrieval; it cannot recall copies already downloaded. A content hash detects changes relative to the recorded fingerprint, not whether the original document was truthful.
- **AI evaluation:** real-model factual accuracy, malicious event text, false positives and reviewer usefulness need separate evaluation.
- **Operations:** deployment needs protected keys, backup/restore drills, monitoring, maintenance funding and organisation-specific onboarding.
- **Adaptation:** roles and policies can be configured for different workflows; enterprise integrations and approval processes may require additional engineering.

### Indian infrastructure: Vishvasya / NBF

Our core technical future direction is to explore **Vishvasya / India's National Blockchain Framework**, beginning with an **NBFLite compatibility trial** where access is available. The aim is to evaluate Indian infrastructure while preserving the document and identity workflow.

**The current prototype uses Besu. No NBF integration or migration is claimed.** A decision depends on access eligibility, contract/runtime compatibility, APIs, data handling, performance, operating responsibilities and cost. See the [MeitY launch announcement](https://www.pib.gov.in/PressReleasePage.aspx?PRID=2051934).

## Troubleshooting

| Symptom | First check |
|---|---|
| Browser says connection refused | Check `docker compose --env-file generated/config.env ps`, then app logs. A restarting app is not ready to serve requests. |
| Missing/invalid `FILE_KEY` | Use the original generated configuration. Do not generate a replacement key for existing encrypted files. |
| PostgreSQL password authentication failed | Restore the credentials matching the existing database volume; editing environment values alone does not reset database passwords. |
| `EISDIR` reading deployment/artifact JSON | These paths must be generated files, not directories created by a missing bind mount. Inspect setup state before restarting. |
| Besu cannot find `static-nodes.json` | Network initialisation is incomplete or its mount is wrong. Inspect `generated/network` and the setup logs. |
| Ollama says address already in use | A process may already be serving port 11434. Check `curl http://localhost:11434/api/tags` before starting another instance. |
| AI returns a rules-only report | Check the model name, endpoint reachability and app logs. Core reporting remains available. |
| Encrypted file integrity verification failed | Check the original encryption key, stored ciphertext and chain commitment. Do not bypass integrity verification. |

For more detail, use [SETUP.md](SETUP.md). Preserve `generated/`, database backups and validator state before troubleshooting. Never use a volume-deleting reset as a routine restart.

## Repository guide

| Path | Contents |
|---|---|
| `contracts/` | IdentityRegistry and AssetPlatform contracts. |
| `server/` | API, encryption, application logging and audit assistant. |
| `web/` | React interface. |
| `infra/` | Besu startup and database initialisation. |
| `scripts/` | Setup, compilation, deployment and diagnostics. |
| `tests/` | Contract, API and audit-assistant regression tests. |
| `experiments/` | Security, performance and resilience experiments. |
| `docs/` | Architecture, security, DID method, AI scope and verification. |
| `generated/` | Local credentials, wallets, network configuration and deployment addresses; excluded from Git. |

## Team ADVITYAS

| Member | Contribution |
|---|---|
| Sia | Team lead and prototype development |
| Chaitali | Prototype development and demo video |
| Aaditiya | Research and presentation |
| Upasna | Research and presentation |
| Vanshika | Testing and research |
| Urvi | Research |

For the implementation scope, see [BUILD_CHECKLIST.md](BUILD_CHECKLIST.md). For the research background, see [RESEARCH.md](docs/RESEARCH.md).
