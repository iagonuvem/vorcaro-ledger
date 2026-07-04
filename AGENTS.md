# AGENTS.md — Guidelines for AI Agents

This repository is the **Vorcaro Enterprises Sovereign Finance Ledger**: a
security-critical financial command system, not a CRUD app. Code you write here
protects executive signing keys, an append-only cryptographic ledger, and the
company's ability to prove what happened. Read this file fully before making
changes.

## North Star

> **Simplicity is the highest level of sophistication.**

Prefer the smallest change that satisfies the spec. Do not add abstractions,
options, fallbacks, or "flexibility" the plans don't call for. In this codebase,
every unnecessary code path is attack surface, and every clever indirection makes
the audit harder. Boring, obvious, verifiable code wins.

## Authoritative Documents (read before non-trivial changes)

| Document | Role |
|---|---|
| [`LLM/PLAN.md`](LLM/PLAN.md) | **Source of truth.** Product spec, security model, ledger/event semantics, AI boundaries. Where any document or code disagrees with it, `PLAN.md` wins — fix the disagreement, don't code around it. |
| [`LLM/SERVER_IMPLEMENTATION_PLAN.md`](LLM/SERVER_IMPLEMENTATION_PLAN.md) | Server: stack, append pipeline, network/API security, PKI, KMS, Docker ops. |
| [`LLM/APP_IMPLEMENTATION_PLAN.md`](LLM/APP_IMPLEMENTATION_PLAN.md) | Electron client: hardened shell, vault, sync engine, enrollment/recovery. |
| [`LLM/DATABASE_OVERVIEW.md`](LLM/DATABASE_OVERVIEW.md) | SQLite schema, append-only enforcement, transactions, backups, migrations. |
| [`LLM/COMMON_TYPES.md`](LLM/COMMON_TYPES.md) | Shared entity types; implemented as zod schemas in `packages/protocol`. |
| [`LLM/DESIGN.md`](LLM/DESIGN.md) | UI guidelines. **Must match** for any UI change. |

When your change makes any of these documents stale, update the document in the
same change. Documentation drift in a system whose product is *provable truth* is
a defect, not a chore.

## Repository & Commands

pnpm workspaces monorepo (`pnpm-workspace.yaml`), Node >= 22, pnpm >= 10.

```text
packages/protocol/   # shared schemas, JCS canonicalization, crypto — NO I/O in here
server/              # Vorcaro finance server (Express 5, SQLite/SQLCipher)
client/              # Electron desktop app
LLM/                 # project documentation
```

* `pnpm install` — install all workspaces.
* `pnpm build` / `pnpm test` / `pnpm lint` — recursive across workspaces.
* Run build, tests, and lint before reporting any task complete. The protocol
  golden-bytes tests are release gates — never skip or "temporarily disable" them.

## Security Invariants (never violate, never "temporarily" bypass)

These are structural properties of the system. A PR that weakens any of them is
wrong even if it fixes the bug at hand.

1. **The ledger is append-only.** No UPDATE/DELETE on `ledger_events`,
   `checkpoints`, `audit_log`, `recovery_approvals`, `revocation_list_versions`,
   `snapshots` — in code, in migrations, or in "one-off" scripts. Status changes
   are appended `STATUS_TRANSITION` events. Migrations are additive only.
2. **One appender.** Exactly one writer assigns `server_sequence`. Never
   parallelize, shard, or "optimize" the append path with a second writer.
3. **Canonical bytes or nothing.** All signatures are Ed25519 over RFC 8785 JCS
   bytes produced by `packages/protocol`. Never sign or verify
   `JSON.stringify` output. If a protocol change alters the golden fixtures,
   that is a protocol break: it requires explicit human sign-off and updates to
   both implementation plans — it is never a side effect of another change.
4. **Identity comes from cryptography, not from requests.** Device identity is
   read from the mTLS peer certificate on the socket. Never trust an
   identity-shaped header, body field, or query param.
5. **Closed error enum.** Clients branch on `ErrorCode` values from
   `COMMON_TYPES.md`. Never invent ad-hoc error strings or leak stack traces,
   paths, or version banners in responses.
6. **Forward-only revocation.** Revoking a key or device never invalidates
   previously accepted events; verification uses the key version whose authority
   window covers the event. Quarantine, never rewrite.
7. **Keys never leave their boundary.** HSM keys stay behind PKCS#11; client
   keys stay in guarded main-process memory. No key material in the renderer,
   in SQLite unwrapped, in logs, in test fixtures with real values, or in error
   messages.
8. **No plaintext finance data leaks.** Not in logs, crash dumps, exports
   (policy-gated), console output, commit messages, or test snapshots. Scrub
   before you print.
9. **The client boots offline from bundled assets.** No remote code, no CDN, no
   telemetry, no startup network dependency. Renderer: `sandbox: true`,
   `contextIsolation: true`, `nodeIntegration: false`, no direct network access.
   Do not relax these to make a feature easier.
10. **No third-party AI APIs** for finance data. Product AI is advisory only:
    no code path may let AI output reach `createEvent`, signing, approval, or
    the ledger without an explicit human action.

## Change Discipline

* **Don't resolve spec conflicts silently.** If two documents disagree, or the
  spec and code disagree, surface it — `PLAN.md` wins, and the losing document
  gets fixed in the same change.
* **Security-relevant changes need a failing test first** where feasible: replay
  rejection, append-only triggers, signature verification, checkpoint tripwire.
  The threat drills in the plans are the definition of done, not suggestions.
* **New dependencies are a security decision.** This system's sovereignty claim
  is "no vendor can take us down." Prefer the standard library and existing
  dependencies; justify any new package (maintenance, provenance, license
  compatibility with GPL-3.0-only) in the PR description.
* **Never commit secrets** — no `.env`, tokens, cert private parts, or HSM PINs.
  Config comes from host-mounted files (server) or the OS keystore (client).
* Do not create commits or push unless explicitly asked.

## Coding Conventions

* TypeScript strict everywhere; prefer `type` aliases over `interface`.
* Types shared between client and server live in `packages/protocol` (specified
  in `COMMON_TYPES.md`) — never fork or duplicate them per side.
* Validation at boundaries with zod, strict mode (unknown fields rejected).
* Timestamps: ISO 8601 UTC strings; server time is authoritative for policy.
  Money: integer minor units + ISO 4217 currency code — never floats.
* Comments explain **why**, never restate the code. No narration comments, no
  `console.log` left in committed code, no `TODO` without context.
* UI work follows `LLM/DESIGN.md` exactly: truth-state colors are law, green is
  earned (§3.3), pending vs. accepted must differ structurally, no decorative
  motion. UI status vocabulary uses the exact `EventStatus` values.

## Do

* Read the relevant plan section before touching unfamiliar areas (append
  pipeline, sync engine, vault, recovery, policy engine).
* Keep the tree shallow; prefer editing existing files over creating new ones.
* Write terse, factual user-facing copy (`DESIGN.md` §8) — no exclamation marks.
* Update golden fixtures, plans, and `COMMON_TYPES.md` together when the
  protocol legitimately evolves.
* Surface anything that looks like a security gap, even if out of scope.

## Don't

* Weaken a hardening setting, PRAGMA, trigger, fuse, or CSP to fix a bug or
  test — fix the code instead.
* Add endpoints, IPC channels, message types, or event types without updating
  the plans that enumerate them.
* Introduce parallel state systems, caching layers, or "temporary" adapters the
  plans don't describe.
* Mock away signature or chain verification in integration tests — those paths
  are the product.
* Let generated or copied code smuggle in network calls, telemetry, or eval-like
  constructs. Zero external resources at startup is a hard client guarantee.
