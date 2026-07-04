# Vorcaro Sovereign Finance App (Electron) — Implementation Plan

Companion to `PLAN.md` (product spec) and `SERVER_IMPLEMENTATION_PLAN.md`.
This document describes **how to build the desktop client**, in dependency order.
The app is a hardened shell around three cores: the encrypted local replica, the
signing/sync engine, and the executive UI. Where this document and `PLAN.md`
disagree, `PLAN.md` wins.

---

## 1. Scope

The app:

* Boots fully offline from bundled assets — zero external resources at startup.
* Unlocks an encrypted local vault (SQLCipher) holding the ledger replica.
* Creates, signs, and queues events; syncs them when the Vorcaro server is reachable.
* Verifies everything it receives: server signatures, hash chain continuity, and
  checkpoint ancestry (rollback detection per `PLAN.md` §4.3).
* Enforces local policy for immediate UX feedback (the server re-enforces; local
  policy is a convenience mirror, never the authority).
* Runs advisory local AI (Phase 4), clearly labeled, with no signing/approval power.

Non-goals for v1: mobile, browser version, remote UI loading, auto-executed payments,
third-party AI APIs.

---

## 2. Stack Decisions

| Concern | Choice | Rationale |
|---|---|---|
| Shell | **Electron (current LTS) + @electron/fuses** | Required by `PLAN.md`; fuses burn off `runAsNode`, cookie encryption bypass, etc. at package time. |
| UI | **React + TypeScript + Vite** | Team competence; renderer is pure UI with zero Node access. |
| Local DB | **better-sqlite3-multiple-ciphers (SQLCipher-compatible)**, main process only | Full-database encryption; synchronous API suits the main-process data layer. |
| Crypto | `sodium-native` (Ed25519, X25519, AES-256-GCM), **shared `packages/protocol`** | Identical canonical bytes and signing rules as the server — same package, not a port. |
| KEK derivation | **Argon2id** from vault passphrase | Memory-hard; parameters stored beside the vault header. |
| OS key storage | Electron `safeStorage` (Keychain / DPAPI / libsecret) | Wraps the vault KEK for biometric-ish convenience unlock; passphrase remains the recovery path. |
| Hardware keys | TPM / Secure Enclave **when available** via native module; software fallback | `PLAN.md` says "hardware-backed where possible" — do not block v1 on it, but bind device identity to hardware where the platform allows. |
| Packaging/updates | electron-builder; **custom update feed from the Vorcaro server only**, Ed25519-signed manifests verified in-app before install | No Squirrel/GitHub/vendor update endpoints. Update check is user-triggered or on-sync — never a startup blocker. |
| State | React Query for main-process data (via IPC), Zustand for UI-local state | Server-ish state (the local DB) behaves like a queryable backend to the renderer. |

Process architecture — this split is load-bearing:

```text
┌─ Main process ────────────────────────────────────────────────┐
│ vault/     open/close SQLCipher DB, key wrapping, Argon2id    │
│ signer/    holds unlocked signing key handle; signs events    │
│ sync/      sync engine state machine, mTLS client, verifier   │
│ policy/    local policy interpreter (same document as server) │
│ store/     DB access layer, projections for the UI            │
│ ipc/       zod-validated, allowlisted IPC handlers            │
└──────────────▲────────────────────────────────────────────────┘
               │ contextBridge (typed, schema-validated, no raw ipcRenderer)
┌─ Preload ────┴────────────────────────────────────────────────┐
│ exposes ~20 named methods; nothing generic, no channels API   │
└──────────────▲────────────────────────────────────────────────┘
┌─ Renderer ───┴────────────────────────────────────────────────┐
│ React UI only. sandbox=true, contextIsolation=true,           │
│ nodeIntegration=false. Sees decrypted view models, never      │
│ keys, never raw DB handles, never the network.                │
└───────────────────────────────────────────────────────────────┘
```

The renderer **never talks to the network**. All server I/O happens in the main
process sync engine. This makes "no remote code, no exfiltration from UI" a
structural property instead of a lint rule.

---

## 3. Build Order Overview

1. Hardened shell skeleton + IPC contract (§4).
2. Vault: key derivation, encrypted DB, unlock flow (§5, §6).
3. Local ledger replica + event creation/signing + pending queue (§7).
4. Sync engine + verification (checkpoints, hash chain) (§8) — **Phase 1 complete**
   when the two-client convergence test passes against the real server.
5. Enrollment, revocation handling, recovery client flow (§9) — **Phase 2**.
6. Finance UI: dashboard, approvals, conflicts, audit (§10, §11) — **Phase 3**.
7. Local AI runtime (§12) — **Phase 4**.

---

## 4. Hardened Shell (build first, keep forever)

Startup sequence implements the `PLAN.md` §4.1 diagram:

1. **Integrity check**: verify ASAR/app signature (OS code-signing + our own
   Ed25519 manifest over bundled files). Refuse to run on mismatch.
2. Register a custom `app://` protocol serving only bundled files; the
   `BrowserWindow` loads `app://index.html`. No `file://`, no `http(s)://` for UI.
3. Show the vault unlock screen. No network activity has occurred yet.

Hard settings (enforced in one `createWindow()` used everywhere):

* `contextIsolation: true`, `sandbox: true`, `nodeIntegration: false`,
  `webviewTag: false`, `enableRemoteModule` absent (dead API, keep it dead).
* `will-navigate` / `setWindowOpenHandler`: deny everything except `app://`.
* CSP: `default-src 'app:'; connect-src 'none'; object-src 'none'` in the renderer
  (the renderer genuinely needs no `connect-src` — see process architecture).
* Fuses: `runAsNode=off`, `nodeCliInspect=off`, `embeddedAsarIntegrityValidation=on`,
  `onlyLoadAppFromAsar=on`.
* IPC: every handler validates its payload with a zod schema from a single
  `ipc/contract.ts`; unknown channels are logged to the local audit table and dropped.
* No telemetry, no crash-report upload. Crash dumps stay local and are scrubbed of
  payload plaintext.

Exit test: `npx @electron/fiddle`-style checklist + an automated test that greps the
packaged app for `http://`/`https://` loads and asserts the window cannot navigate
away from `app://`.

---

## 5. Key Management (client side)

Per `PLAN.md` §5.1, the executive experiences one key; internally:

```text
Vault passphrase ──Argon2id──▶ KEK
KEK ─unwraps─▶ Executive Root Key (stored wrapped in vault header)
Root Key ─derives (HKDF)─▶ Signing Key (Ed25519)
                          ▶ Encryption-Unwrapping Key (X25519)
                          ▶ Device-Binding Key
safeStorage(OS keystore) ─optionally wraps─▶ KEK   (convenience unlock)
TPM/Secure Enclave (if present) ─holds─▶ Device-Binding private key
```

Rules:

* Unwrapped keys live only in main-process memory (`sodium_malloc` guarded buffers),
  zeroized on lock/quit. The renderer can request *signatures*, never keys.
* Key material never touches the SQLite file unwrapped, never appears in logs.
* Executive key rotation (post-recovery): the app downloads its new `key_package`,
  unwraps DEKs with the new key, re-encrypts the vault header, bumps `key_version`.
  Old-version public keys are retained for verifying historical events
  (forward-only revocation, `PLAN.md` §5.2).
* Auto-lock: configurable idle timeout (default 10 min) + lock on suspend/lid close.

---

## 6. Encrypted Local Database

One SQLCipher database per executive profile. Schema mirrors the server where it
must and diverges where the client's job differs:

```sql
meta               (key, value)         -- schema version, key_version, argon2 params
snapshots          (up_to_sequence, content_hash, verified_at, body BLOB)
ledger_replica     (server_sequence PK, event JSONB, resulting_ledger_hash, ...)
pending_events     (event_id PK, device_event_counter, envelope BLOB,
                    created_at, submit_state)   -- submit_state: queued|submitted|acked|rejected|conflicted
checkpoints        (sequence PK, ledger_hash, signature, verified_at)  -- NEVER pruned
sync_state         (singleton: last_verified_sequence, revocation_list_version,
                    active_policy_version, last_sync_at)
object_cache       (object_type, object_id, current_state JSONB, conflicted BOOL)
local_audit        (hash-chained: unlocks, signs, syncs, IPC anomalies, exports)
ai_insights_cache  (id, kind, body, model_version, created_at)  -- always labeled in UI
```

Rules:

* `checkpoints` is append-only and survives vault re-keys — it is the device's
  rollback-detection memory (`PLAN.md` §4.3). Deleting it requires re-enrollment.
* `device_event_counter` is allocated from a monotonic counter in `meta` inside the
  same transaction that inserts into `pending_events` — no gaps, no reuse, even
  across crashes.
* No plaintext finance data outside this file: exports are gated (see §11), logs are
  scrubbed, renderer state is memory-only.

---

## 7. Event Creation & Signing

One function is the only way an event comes into existence:

```text
createEvent(type, object, payload):
  1. Load current base: last_verified_sequence from sync_state.
  2. Build envelope per packages/protocol (ULID event_id, device_event_counter,
     plaintext policy_metadata, encrypted payload, payload_hash).
  3. Local policy check (same policy document version as server) → immediate UX
     feedback: "will require CFO co-approval", "exceeds threshold", etc.
  4. Sign with the executive signing key (protocol package canonical bytes).
  5. Insert into pending_events atomically with the counter bump.
  6. UI shows it as PENDING — visually distinct from accepted truth, always.
```

The PENDING / ACCEPTED / REJECTED / CONFLICTED distinction is a first-class UI
concept (badges, separate list sections), because `PLAN.md` §2.2's entire model is
"offline actions are signed intentions, not truth."

---

## 8. Sync Engine

A main-process state machine; runs on connectivity change, on interval, and on
demand. States: `offline → connecting → verifying → pulling → pushing → idle`.

```text
1. Connect      mTLS with the device certificate (client cert from OS store or
                vault). Server identity pinned to the Vorcaro CA — no public roots.
2. Verify       GET /v1/state → check server_signature; check the advertised
                checkpoint is a DESCENDANT of every stored checkpoint (sequence ≥
                stored, hash chain reachable). Mismatch = HALT sync, red-banner
                security alert, write local_audit, notify server if possible.
                This is the rollback tripwire — it must not be skippable in UI.
3. Revocations  Pull revocation list + active policy version; apply locally.
4. Pull         GET /v1/events?after_seq=last_verified → verify each event's chain
                hash and server signature → apply to ledger_replica + object_cache.
5. Push         Submit pending_events in device_event_counter order (batched).
                For each ack: verify server_signature, mark acked/rejected/
                conflicted, update UI state. DUPLICATE_EVENT after a dropped ack
                is resolved by the idempotent event_id — treat as acked.
6. Checkpoint   Store any new checkpoints (append-only).
7. Snapshot     If far behind, bootstrap from GET /v1/snapshots/latest (verify
                manifest signature + content hash) then tail events.
```

Failure discipline: any verification failure stops the pipeline *at that step*;
partial progress is fine (verified pulls are kept), unverified data is never
applied. The engine never deletes a pending event except on verified ack/reject.

Exit test (Phase 1): two app instances + real server; scripted offline edits on
both; reconnect; assert identical `resulting_ledger_hash` on both replicas and
conflicts surfaced in both UIs. Also: replay a captured push (must fail), and a
mock rolled-back server (must trip the checkpoint tripwire).

---

## 9. Enrollment, Revocation, Recovery (client side)

* **Enrollment wizard**: enter one-time enrollment token → generate device keys
  (hardware-backed if available) → CSR to `POST /v1/enroll/*` → store cert →
  initial snapshot bootstrap. First unlock creates the vault.
* **Certificate renewal**: automatic during sync when cert lifetime < 50%; silent
  unless it fails.
* **Being revoked**: server refuses sync with `CERT_REVOKED`. The app locks the
  vault, shows a "device quarantined — contact Vorcaro Security" screen, and
  optionally executes a remote-wipe order (delete vault file + keys) if the last
  verified revocation list carried a signed wipe directive for this device.
* **Recovery (new device for an executive)**: enrollment wizard variant — after the
  ceremony completes server-side, the app pulls the new `key_package`, verifies the
  `RECOVERY_PERFORMED` event on the ledger, and rebuilds the vault from snapshot.
  The app must show which key_version signed what when displaying history.

---

## 10. Local Policy Engine

Same interpreter as the server (import from `packages/protocol` if extracted there,
otherwise a faithful shared module) evaluating the same signed policy document
pulled during sync. Purpose is UX honesty: show approval requirements and denials
*before* the executive signs, so offline work doesn't queue up doomed events.
The server's evaluation remains authoritative; local disagreement (stale policy)
resolves to whatever the server says at push time, surfaced in the UI as a
rejection with the policy version mismatch called out.

---

## 11. Executive UI

Screens (v1, mapped to `PLAN.md` §12 MVP dashboard list):

* **Unlock** — passphrase (+ OS-keystore quick unlock), lockout after N failures.
* **Dashboard** — cash position, accounts, inflows/outflows, sync status widget
  (last verified sequence, pending count, checkpoint age), pending approvals.
* **Approvals** — queue of operations awaiting this executive's signature;
  multi-party progress shown per operation ("1 of 2 signatures").
* **Conflicts** — conflicted objects, both event versions side by side, resolution
  flow producing a signed `CONFLICT_RESOLVED` event (governance-gated).
* **Ledger / Audit** — filterable event history with verification status per event
  (chain-verified ✓, key version, device, pending/accepted/rejected/conflicted).
* **Sync & Device** — connection state, checkpoint history, revocation list
  version, certificate expiry, enrollment info.
* **Exports** — gated: every export produces a signed `DATA_EXPORTED` event and,
  above policy threshold, requires multi-party approval before the file is
  written. No plaintext export by default (`PLAN.md` §8): exports are encrypted
  archives unless policy explicitly allows plaintext for that role.
* **Settings** — auto-lock, appearance, key/version info. No network toggles that
  could weaken verification.

UI rules: pending vs. accepted truth visually distinct everywhere; AI content
always inside a labeled "AI analysis — advisory" container; a global security
banner slot for the checkpoint-tripwire and quarantine states that cannot be
dismissed without acknowledgement (which is itself locally audited).

---

## 12. Local AI Runtime (Phase 4)

* Local model via `node-llama-cpp` in a **separate utility process** with no network
  access and no IPC surface except a narrow request/response channel from main.
* Inputs: decrypted view models the current executive is already authorized to see
  (main process assembles them; the AI process never touches the vault or keys).
* Capabilities per `PLAN.md` §10: summaries, variance explanations, anomaly
  flags, NL queries over local data, conflict-resolution *proposals*.
* Structural restrictions: the AI process has no handle to the signer, the sync
  engine, or the DB. Its outputs land in `ai_insights_cache` and render only in
  labeled containers. There is no code path from AI output to `createEvent` without
  an explicit human action in the UI.

---

## 13. Packaging, Updates, CI

* **Builds**: electron-builder, OS code-signing (Apple Developer ID + notarization,
  Windows EV cert) with Vorcaro-controlled certificates, plus the internal Ed25519
  file-manifest for startup integrity.
* **Updates**: app checks the Vorcaro server's update endpoint during sync (never at
  startup, never blocking). Manifest = `{version, file_hash, min_version, signature}`
  signed by an offline release key. Verify before download completes → staged
  install on next launch. A tampered or unsigned update is discarded + audited.
* **CI**: typecheck, lint, unit tests, protocol golden-bytes tests (shared with
  server), Playwright-driven Electron e2e for unlock/sync/approval flows, packaged-
  app hardening asserts (fuses set, CSP present, no external URLs). Humans approve
  releases (`PLAN.md` §8 AI boundary).

---

## 14. Testing Strategy

| Layer | Approach |
|---|---|
| Protocol | Shared golden fixtures with the server — byte-identical signatures. |
| Vault | Unit: wrong passphrase, corrupted header, Argon2 param migration, crash mid-write (WAL recovery). |
| Sync | Integration against real server in Docker: convergence, replay, dropped-ack idempotency, rollback tripwire, revoked-cert behavior. |
| Policy | Table-driven: same fixture policies evaluated on client and server must agree. |
| UI | Playwright e2e for the five golden paths (unlock, create+sign offline, reconnect+converge, approve multi-party, resolve conflict). |
| Security | Packaged-app checks (§13); manual pen-test pass before Phase 3 sign-off; ASVS L3 checklist shared with the server repo. |

---

## 15. Milestones

| Milestone | Contents | Exit criterion |
|---|---|---|
| A0 | Hardened shell + IPC contract + integrity check | Hardening assert suite green on packaged app |
| A1 | Vault + key hierarchy + unlock/lock | Vault unit suite green; keys never leave main |
| A2 | Local replica + createEvent + pending queue | Offline event creation with correct counters |
| A3 | Sync engine + verification + checkpoints | Phase 1 two-client convergence test passes |
| A4 | Enrollment + revocation + recovery client | Phase 2 drill passes end-to-end with server |
| A5 | Finance UI (dashboard, approvals, conflicts, audit, exports) | Phase 3 workflows usable + audited |
| A6 | Signed updater + release pipeline | Tampered update rejected in test |
| A7 | Local AI runtime | Advisory insights render labeled; zero write paths |
