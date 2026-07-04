# Vorcaro Enterprises Sovereign Finance Ledger

A local-first, encrypted, offline-capable finance operations platform for Vorcaro
Enterprises C-level leadership. Not a dashboard — a **secure financial command
system**: every action is a signed event, the Vorcaro-owned server is the
authoritative ledger, and executives can operate fully offline with their work
treated as signed intentions until the server accepts them.

**North star:** simplicity is the highest level of sophistication. The product's
job is to make truth legible — who did what, when, from which device, and whether
it is cryptographically verified.

## Architecture at a glance

* **Electron desktop app** — hardened shell, encrypted local replica (SQLCipher),
  offline pending-event queue, sync engine with checkpoint-based rollback detection.
* **Vorcaro finance server** — Node.js 22 + Express 5, embedded SQLite
  (SQLCipher-encrypted) append-only ledger, mTLS-only API, Vorcaro-owned PKI
  (`step-ca`), HSM-backed keys, Dockerized deployment.
* **Shared protocol package** — canonical serialization (RFC 8785 JCS), Ed25519
  signing, zod schemas; the same bytes on both sides.

## Repository layout

```text
├── packages/protocol/   # shared schemas, canonicalization, crypto helpers
├── server/              # Vorcaro finance server
├── client/              # Electron desktop app
└── LLM/                 # project documentation (below)
```

## Documentation

| Document | Contents |
|---|---|
| [`LLM/PLAN.md`](LLM/PLAN.md) | **Product spec and source of truth.** Vision, principles, architecture, ledger/event model, sync, security, governance, MVP scope, phases. Where any doc disagrees with it, `PLAN.md` wins. |
| [`LLM/SERVER_IMPLEMENTATION_PLAN.md`](LLM/SERVER_IMPLEMENTATION_PLAN.md) | How to build the server: stack, append pipeline, network interface/API, PKI, KMS & recovery, policy engine, Docker operations, milestones. |
| [`LLM/APP_IMPLEMENTATION_PLAN.md`](LLM/APP_IMPLEMENTATION_PLAN.md) | How to build the Electron client: hardened shell, vault & key hierarchy, local replica, sync engine, enrollment/recovery, executive UI, local AI. |
| [`LLM/DATABASE_OVERVIEW.md`](LLM/DATABASE_OVERVIEW.md) | Server database schema (SQLite/SQLCipher): DDL, append-only enforcement, transactions, backups, migration discipline. |
| [`LLM/COMMON_TYPES.md`](LLM/COMMON_TYPES.md) | Shared entity types (ledger envelope, identity, finance domain, audit, AI) implemented as zod schemas in `packages/protocol`. |
| [`LLM/DESIGN.md`](LLM/DESIGN.md) | Design guidelines: principles, truth-state system, color palette, typography, motion, accessibility, voice. |
| [`AGENTS.md`](AGENTS.md) | Rules for AI coding agents: security invariants, change discipline, conventions. |

## Development

Requires Node.js >= 22 and pnpm >= 10 (pnpm workspaces monorepo, see
`pnpm-workspace.yaml`).

```bash
pnpm install    # install all workspaces
pnpm build      # build all workspaces (pnpm -r build)
pnpm test       # run all workspace tests
```

The server ships as a Docker container; see `LLM/SERVER_IMPLEMENTATION_PLAN.md`
§14 for the compose stack and operator runbook.
