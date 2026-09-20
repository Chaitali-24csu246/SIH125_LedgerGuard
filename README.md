# LedgerGuard SIH 26125 prototype

An executable local prototype for BEL's **Blockchain-Based Secure Platform for Identity, Access Control, and Digital Asset Management**. The product includes a four-validator Besu QBFT network, PostgreSQL, signed identity authentication, Solidity access controls, encrypted documents, NFT allocation and transfer, an audit explorer, and security experiments.

Start with **[SETUP.md](SETUP.md)**. Then follow **[DEMO.md](DEMO.md)**. The concrete scope and build checklist are in **[BUILD_CHECKLIST.md](BUILD_CHECKLIST.md)**.

## Quick setup

Install and start Docker Desktop with Docker Compose v2. Allocate approximately 6–8 GB RAM to Docker for the local stack. This is a starting allocation, not a measured minimum. The first build needs internet access to pull images and npm packages.

On macOS or Linux, from the extracted project directory:

```bash
sh scripts/setup.sh
```

On Windows PowerShell:

```powershell
powershell -ExecutionPolicy Bypass -File scripts/setup.ps1
```

Open **http://localhost:8080**. Import `generated/wallets/Admin.json` using the password in `generated/WALLET-PASSWORD.txt`, then sign in. All generated accounts are for this isolated test chain only. No cryptocurrency purchase is needed.

## What is implemented

- Stable on-chain identities with user-controlled signing keys, DID resolution, key rotation, guardian recovery with a 24-hour delay, and deactivation.
- Admin, Manager, Auditor and User roles associated with identities rather than fragile session claims.
- Administrator-controlled policy updates, organisation suspension and emergency pause.
- ERC-721 NFTs with content commitments, unique asset-code commitments, Admin-only minting and initial allocation.
- Controlled transfers, disabled approval bypasses, permanent retirement, time-limited file grants and automatic grant invalidation after ownership transfer.
- PostgreSQL metadata and AES-256-GCM encrypted document storage; content hashes verified against the contract before download.
- Single-use signed login challenges, short-lived server sessions, live permission checks, origin restrictions, request limits and security headers.
- Contract event explorer, transaction receipt inspection, validator reachability and database/chain ownership comparison.
- Hash-linked application logs, on-chain evidence checkpoints, imported experiment reports and report fingerprint anchoring.
- Contract/API tests, seeded model-based tests, latency/workload benchmarking and a validator-stop experiment.

## Product structure

| Path | Purpose |
|---|---|
| `contracts/` | IdentityRegistry and AssetPlatform Solidity contracts |
| `server/` | Express API, PostgreSQL schema, encryption and security logging |
| `web/` | React interface and stylesheet |
| `infra/` | Besu startup and least-privilege database initialisation |
| `scripts/` | Setup, network initialisation, compilation, deployment and diagnostics |
| `tests/` | Contract and API regression tests |
| `experiments/` | Reproducible security, performance and resilience experiments |
| `docs/` | Architecture, threat model, DID method, research and verification evidence |
| `generated/` | Your locally generated keys, wallets, secrets and deployed addresses; never commit |

## Important implementation choices

The API is Node/Express instead of the early FastAPI baseline. This lets the browser, deployment scripts, tests and API use the same ethers contract definitions and signature handling. PostgreSQL and Besu are the deployment stack requested. The original role-switching baseline is not part of the authenticated product.

`did:sih` is a documented **prototype DID method**, not `did:ethr`, a registered production method, or a certified standards implementation. Its on-chain controller and resolver are implemented; review `docs/DID_METHOD.md` before presenting it.

The working prototype has implemented security controls and repeatable tests. It is not an independently audited production system. See `docs/SECURITY.md` for exact trust boundaries and `docs/VERIFICATION.md` for what was run here versus what needs local Docker verification.

## Routine commands

```bash
# Status and diagnostics
docker compose --env-file generated/config.env ps
docker compose --env-file generated/config.env run --rm tools node scripts/doctor.mjs

# Contract and API tests: isolated Ganache + PostgreSQL WASM engine
docker compose --env-file generated/config.env run --rm tools npm test

# Experiments against your live local Besu/PostgreSQL app
docker compose --env-file generated/config.env run --rm tools npm run experiments

# Performance workload, using isolated contracts
docker compose --env-file generated/config.env run --rm tools node experiments/benchmark.mjs

# Stop without deleting state
docker compose --env-file generated/config.env stop

# Resume the existing deployment
docker compose --env-file generated/config.env up -d postgres besu1 besu2 besu3 besu4 app
```

On Linux/macOS, if tools cannot write the mounted output directory, export `LOCAL_UID=$(id -u)` and `LOCAL_GID=$(id -g)` in that terminal, as the setup script does. Do not change blockchain addresses or recreate the genesis file to repair a file-permission problem.

## Before your presentation

1. Complete setup and check that all four validators produce the same chain.
2. Follow the happy-path and security-path steps in `DEMO.md`.
3. Run the experiment suite on **Besu**, retaining its raw results.
4. Capture your own screenshots of Assets, Audit Explorer and Security Results.
5. Label local verification evidence accurately; never present simulator results as Besu measurements.
6. Keep a backup of `generated/`, the database and validator data before making experimental modifications.


## AI Audit Assistant

The Security Results page includes on-demand, read-only audit reports with an optional local Ollama explanation layer. See [setup, scope and validation](docs/AI_AUDIT_ASSISTANT.md). No model is required for the rules-only report.
