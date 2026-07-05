# Vorcaro Finance Server — Implementation Plan

Companion to `PLAN.md` (product spec), `APP_IMPLEMENTATION_PLAN.md` (Electron client),
`COMMON_TYPES.md` (shared entities), and `DATABASE_OVERVIEW.md` (physical schema).
This document describes **how to build the server**, in dependency order, with concrete
stack choices. Where this document and `PLAN.md` disagree, `PLAN.md` wins — fix the
disagreement, don't code around it.

---

## 1. Scope

The server is the operational source of truth. It:

* Accepts signed events from enrolled devices over mTLS.
* Validates identity, device, signature, replay counters, and policy **before** append.
* Assigns global order, maintains the ledger hash chain, and signs acknowledgements.
* Detects conflicts via `base_server_sequence` vs. per-object last-accepted sequence.
* Tracks **any number of bank accounts**: accounts are ledger objects
  (`object_type = 'account'`), created via `ACCOUNT_CREATED` events and referenced by
  `account_id` in the plaintext `policy_metadata` of every money-moving event, so
  per-account policy, conflict detection, and projections work without payload
  decryption. There is no fixed account limit anywhere in the schema or API.
* Tracks multi-currency finance data: each money-moving event carries
  `transaction_currency`, `exchange_rate`, `default_currency_snapshot_id`, and
  `local_rate`, while the active policy defines the enterprise default currency
  used for thresholds and reporting totals.
* Emits signed checkpoints (rollback evidence) and periodic snapshots.
* Runs the PKI, KMS integration, recovery ceremonies, and the admin console.
* Serves reporting projections derived from the ledger.

Non-goals for v1: public blockchain, third-party AI APIs, multi-region active-active,
end-to-end payload encryption between executives (see "Payload Visibility Decision" in
`PLAN.md` §4.3 — the server is a trusted decryptor in v1).

---

## 2. Stack Decisions

| Concern | Choice | Rationale |
|---|---|---|
| Language/runtime | **TypeScript on Node.js 22 LTS** | Same language as the Electron client → the protocol package (canonical serialization, crypto, schemas) is shared verbatim, which eliminates an entire class of "client and server disagree about bytes" bugs. |
| HTTP framework | **Express 5** | Ubiquitous, minimal, stable. Request validation is explicit zod middleware using the shared `packages/protocol` schemas (no framework-level schema layer to drift from them), and the mTLS client certificate is read directly off the TLS socket (`req.socket.getPeerCertificate()`) behind an `https.Server` with `requestCert: true`. |
| Database | **SQLite (SQLCipher-encrypted, WAL mode)** | Embedded, zero-server datastore matching the single-writer append discipline; sovereign single-file storage on Vorcaro hardware, encrypted at rest with an HSM-wrapped key. Full schema, PRAGMAs, and compensating controls in `DATABASE_OVERVIEW.md`. |
| Signatures | **Ed25519** (libsodium via `sodium-native`) | Small keys, fast verification, misuse-resistant. |
| Hashing | **SHA-256** for the ledger hash chain | Ubiquitous, auditable by any third party tool. |
| Payload encryption | **AES-256-GCM** DEKs, envelope-wrapped | Standard envelope encryption; DEK wrap keys live in the HSM/KMS. |
| Canonical serialization | **RFC 8785 JCS (JSON Canonicalization Scheme)** | Signatures are over canonical bytes. Both sides use the shared implementation from `packages/protocol`. Never sign "whatever JSON.stringify produced". |
| PKI / CA | **smallstep `step-ca`, self-hosted** | Vorcaro-owned internal CA; short-lived device certs; ACME-style renewal without vendor dependency. |
| HSM / KMS | **PKCS#11 interface**; SoftHSMv2 in dev, real HSM (e.g. Thales/YubiHSM) in prod | Server ledger-signing key and DEK-wrapping keys never exist in application memory unwrapped. |
| Object storage | **MinIO, self-hosted** | S3 API for encrypted attachments without a cloud dependency. |
| ID scheme | **ULID** for event ids | Client-generated, sortable, doubles as idempotency key. |
| Deployment | **Docker container + Compose stack** | One `docker compose up -d` starts/restarts the whole server on Vorcaro hardware; DB files live on a host bind mount and are never stored inside the container (see §14). |

Repository layout (separate repo from the Electron app is fine, but the protocol
package must be shared — publish to a Vorcaro-internal npm registry or use a monorepo):

```text
vorcaro-ledger/
├── packages/
│   └── protocol/          # SHARED with the app. Event schemas (zod), JCS
│                          # canonicalization, hash/sign/verify helpers,
│                          # checkpoint format, error codes. No I/O in here.
├── server/
│   ├── src/
│   │   ├── api/           # Express routers, zod validation middleware, mTLS identity extraction
│   │   ├── ledger/        # append pipeline, hash chain, checkpoints, snapshots
│   │   ├── policy/        # policy engine + versioned policy documents
│   │   ├── conflicts/     # detection + resolution event handling
│   │   ├── pki/           # step-ca client, enrollment, revocation lists
│   │   ├── kms/           # PKCS#11 wrapper, DEK wrap/unwrap, recovery
│   │   ├── projections/   # ledger → reporting read models
│   │   ├── audit/         # audit log writer (hash-chained)
│   │   └── admin/         # admin console API (separate listener + cert policy)
│   ├── migrations/
│   └── test/
└── admin-ui/              # minimal internal web console (see §12)
```

---

## 3. Build Order Overview

Mapped to `PLAN.md` phases. Each stage below lists its exit test.

1. **Protocol package** (§4) — canonical bytes, schemas, crypto helpers.
2. **Database schema + append pipeline** (§5, §6) — the single-writer ledger core.
3. **API surface + mTLS** (§7, §8) — enrollment, sync, submission.
4. **Conflict detection + checkpoints + snapshots** (§9, §10) — Phase 1 complete.
5. **PKI, revocation, KMS, recovery ceremony** (§8, §11) — Phase 2 complete.
6. **Policy engine + finance projections + reporting** (§12) — Phase 3 complete.
7. **Server-side AI workers** (§13) — Phase 4, advisory only.

---

## 4. The Protocol Package (build this first)

Everything the client and server must agree on, byte-for-byte, lives here.

* **Event schema** (zod): the client-signed envelope exactly as specified in
  `PLAN.md` §6 — `event_id`, `event_type`, `actor_id`, `device_id`,
  `client_timestamp`, `base_server_sequence`, `device_event_counter`,
  `object_type`, `object_id`, `payload_hash`, `encrypted_payload`, plus
  plaintext policy metadata required so threshold policy can run pre-decryption.
  Monetary events must include `account_id`, `entity_id`,
  `transaction_currency`, `exchange_rate`, `default_currency_snapshot_id`, and
  `local_rate`; `exchange_rate` is a decimal string paired with the referenced
  default-currency snapshot, `local_rate` is integer minor units in
  `transaction_currency`, and no floating-point money is accepted.
* **Signing rule**: `client_signature = Ed25519.sign(JCS(envelope minus signature fields))`.
  One function, `canonicalEventBytes(event)`, used by both sides. Test it with a
  golden-bytes fixture file — if the fixture changes, that's a protocol break.
* **Server chain rule**:
  `resulting_ledger_hash = SHA256(previous_ledger_hash ‖ server_sequence ‖ canonicalEventBytes)`.
  `server_signature = Ed25519.sign(JCS({server_sequence, event_id, resulting_ledger_hash, server_timestamp, status}))`.
* **Checkpoint format**: `{sequence, ledger_hash, issued_at, key_version, signature}`.
* **Shared entity types**: every domain entity (Account, Transaction, Approval, …) is
  specified in `COMMON_TYPES.md` and implemented here as zod schemas — the single
  definition both server and client import.
* **Error codes**: a closed enum (`CERT_REVOKED`, `STALE_BASE`, `REPLAY_COUNTER`,
  `POLICY_DENIED`, `CONFLICT`, `DUPLICATE_EVENT`, …). Clients branch on codes, never
  on message strings.

Exit test: property test — any schema-valid event round-trips through
serialize → sign → verify on 10k random inputs; golden fixtures pinned.

---

## 5. Database Schema

**Full physical schema lives in `DATABASE_OVERVIEW.md`** — SQLite (SQLCipher) DDL,
PRAGMAs, triggers, indexes, file layout, and backup procedure. This section keeps
only the rules the rest of this plan depends on.

Storage model:

* Two files: `ledger.db` (authoritative — ledger, identity, PKI, recovery,
  policies, audit) and `projections.db` (rebuildable reporting cache). Attachments
  and snapshot bodies live in MinIO; the DB stores refs + content hashes.
* SQLCipher full-database encryption; the DB key is HSM-wrapped (same envelope
  discipline as payload DEKs, §11). WAL mode, `synchronous = FULL`, STRICT tables.
* `ledger_events` matches the `LedgerEvent` type in `COMMON_TYPES.md` §2.1, with
  generated columns exposing `policy_metadata` fields (`account_id`,
  `entity_id`, `transaction_currency`, `exchange_rate`,
  `default_currency_snapshot_id`, `local_rate`) for per-account indexing, policy
  threshold checks, and projection rebuilds.

Hard rules:

* Append-only tables (`ledger_events`, `checkpoints`, `audit_log`,
  `recovery_approvals`, `revocation_list_versions`, `snapshots`) are protected by
  unconditional `RAISE(ABORT)` UPDATE/DELETE triggers. SQLite has no roles/GRANTs,
  so the compensating controls are: single read-write connection held by the
  appender only, `mode=ro` + `PRAGMA query_only=ON` for every other component, OS
  file permissions per process user, and nightly full-chain verification
  (`DATABASE_OVERVIEW.md` §3).
* Status transitions are events, not UPDATEs: the transition is appended as a
  `STATUS_TRANSITION` event; `object_heads` and projections materialize current
  status.
* `object_heads` and `devices` (`max_event_counter`, `last_seen_at`) are the only
  mutable rows in the append path; everything else materializes asynchronously in
  projections.
* Nightly job verifies the full hash chain from genesis and compares against the
  latest checkpoint. A mismatch pages security — it is never auto-repaired.
* Multi-account: money-moving events carry `account_id` (and
  `counterparty_account_id` for internal transfers) in `policy_metadata`; the
  generated-column index `idx_ledger_account` supports per-account reads and
  projection rebuilds. Account state itself is event-sourced — there is no mutable
  `accounts` table; `proj_accounts` (§10) is the read model.
* Multi-currency: money-moving events preserve the original
  `transaction_currency` and `local_rate`, plus the immutable `exchange_rate`
  into the active enterprise default currency and the
  `default_currency_snapshot_id` that proves which currency policy snapshot was
  used. Default-currency totals are derived in projections; ledger rows are never
  rewritten when the default currency changes later.

---

## 6. Ledger Append Pipeline (the heart of the server)

Single-writer discipline: exactly one appender assigns `server_sequence`. Implement as
one worker consuming an in-process queue. v1 runs a single server node — SQLite's
single-writer model enforces this at the engine level. If HA is added later, appender
election must be external (failover onto the replicated snapshot, see
`DATABASE_OVERVIEW.md` §7) — do not shard the sequence.

Validation pipeline, in order, fail-fast with the closed error enum:

```text
1. Idempotency      — event_id already present? Return the original outcome verbatim.
2. Device cert      — fingerprint matches enrolled device; device not revoked/quarantined.
3. Executive        — actor bound to this device; executive active.
4. Replay           — device_event_counter > devices.max_event_counter.
5. Signature        — verify client_signature against the executive key version whose
                      authority window covers base_server_sequence (forward-only
                      revocation rule from PLAN.md §5.2).
6. Payload hash     — SHA256(encrypted_payload) == payload_hash.
7. Policy           — run policy engine on plaintext policy_metadata + decrypted payload
                      (server is trusted decryptor). Monetary payload fields must
                      agree with policy_metadata transaction_currency,
                      exchange_rate, default_currency_snapshot_id, and local_rate.
                      Thresholds compare the default-currency value derived from
                      the referenced active default-currency snapshot; multi-party
                      requirements produce status=pending awaiting co-approval
                      events, not rejection.
8. Conflict         — base_server_sequence < object_heads.head_sequence for the same
                      (object_type, object_id)? → status=conflicted, object flagged.
9. Append           — assign server_sequence (gapless), compute previous/resulting
                      ledger hash, sign server acknowledgement, update object_heads
                      and max_event_counter — all in ONE transaction
                      (BEGIN IMMEDIATE, see DATABASE_OVERVIEW.md §7).
10. Acknowledge     — return {status, server_sequence, resulting_ledger_hash,
                      server_signature} (or the error code + signed rejection record).
```

Notes:

* **Rejections are appended too** (with `server_sequence` assigned) — a rejected
  intention is audit evidence per `PLAN.md` §11. Only malformed garbage that fails
  schema validation is refused without append (still written to `audit_log`).
* Batch submission (reconnect flow) processes events **in device_event_counter order**
  per device; a conflict on event N does not block event N+1 unless it touches the
  same object.
* Checkpoint emission: every K accepted events (K=1000) and at least every 15 minutes,
  the appender writes a signed checkpoint. Checkpoints are served to every client on
  every sync (`PLAN.md` §4.3 checkpoint anchoring).

Exit test (Phase 1 success criterion): simulation harness with two simulated offline
clients producing interleaved pending events; after reconnection both converge to the
identical ledger hash, all conflicts explicitly marked, replay of any captured request
is rejected with `REPLAY_COUNTER` or `DUPLICATE_EVENT`.

---

## 7. Network Interface & API Surface

The server exposes exactly **two HTTPS listeners** — the device API and the admin
API. Nothing else is network-reachable: SQLite is embedded (no DB port), MinIO and
`step-ca` are bound to the internal Docker network only (§14.1), and there is no
plain-HTTP, redirect, or "health on port 80" listener.

### 7.1 Listeners & transport security

| | Device listener | Admin listener |
|---|---|---|
| Port | `8443` | `9443` |
| Purpose | Electron client sync, enrollment, recovery | Admin console, device/executive management, audit search |
| Client certs | Device certs from the Vorcaro device-CA intermediate | Admin certs from a **separate** admin-CA intermediate |
| Network exposure | Vorcaro network / VPN reachable by executive devices | Vorcaro security VLAN only |

Transport rules (both listeners):

* **TLS 1.3 only**, no version fallback, no renegotiation. Server certificate is
  issued by the Vorcaro CA; clients pin the Vorcaro root and reject public roots
  (`PLAN.md` §8 — no unauthenticated sync path exists).
* **mTLS is mandatory** (`requestCert: true, rejectUnauthorized: true` on the
  Node.js `https.Server`). The TLS handshake verifies the client chain against the
  matching Vorcaro intermediate *and* the current revocation state — a revoked
  cert fails at handshake, before any route code runs.
* **Identity comes from the socket, never from the request**: the Express identity
  middleware reads `req.socket.getPeerCertificate()`, matches the fingerprint
  against `devices.certificate_fingerprint`, loads device + executive status, and
  attaches `{device, executive}` to the request context. Any `X-Device-*` or
  identity-shaped header is ignored and its presence is written to `audit_log`
  (`category = 'auth'`).
* Certificate errors map to the closed error enum (`CERT_UNKNOWN`, `CERT_REVOKED`,
  `EXECUTIVE_INACTIVE`) so clients can branch deterministically — e.g. the app's
  quarantine screen on `CERT_REVOKED` (`APP_IMPLEMENTATION_PLAN.md` §9).
* The enrollment endpoints are the **single deliberate exception**: `POST
  /v1/enroll/*` accepts a TLS connection without a client cert (the device doesn't
  have one yet) but is guarded by one-time admin-issued enrollment tokens, a
  possession challenge, and aggressive rate limiting (§7.4).

### 7.2 Request security pipeline

Every request passes, in order, fail-fast:

```text
1. mTLS handshake      — chain, expiry, revocation (transport layer, §7.1)
2. Identity binding    — cert fingerprint → device → executive; status checks
3. Size & shape guards — body limit 1 MiB (batch submissions 10 MiB), JSON only,
                         no multipart; attachments go to MinIO via signed refs
4. Schema validation   — zod schemas imported from packages/protocol; unknown
                         fields rejected (strict mode), never silently stripped
5. Authorization       — policy engine: may this executive call this route /
                         see this object_type? (coarse RBAC/ABAC, §12)
6. Handler             — e.g. the append pipeline (§6) for POST /v1/events
```

Failures at steps 1–2 are audited with cert details; failures at 3–5 are audited
with the error code but **never** echo the payload back. Responses carry the closed
error enum only — no stack traces, no internal paths, no version banners.

### 7.3 Response integrity

Clients must be able to verify every byte they act on (`PLAN.md` §4.3 "server
trust rule"), so transport security is not enough:

* Every state-bearing response (`/v1/state`, event acks, checkpoints, snapshot
  manifests, revocation lists, policy documents) embeds an **Ed25519 server
  signature over JCS canonical bytes** per the protocol package — verification is
  independent of TLS.
* Event submission returns the signed `ServerAck` (`COMMON_TYPES.md` §2.2)
  including `resulting_ledger_hash`, so the client extends its verified chain
  without a second round trip.
* Responses are deterministic: same request against the same ledger state yields
  byte-identical signed bodies (idempotent `event_id` handling included) — a
  dropped-connection retry is always safe.

### 7.4 Availability & abuse controls

* Per-device token-bucket rate limits (sync endpoints generous, enrollment and
  recovery endpoints strict); global connection cap sized for the executive fleet
  — this is a ~tens-of-devices system, not a public API.
* Slow-loris and oversized-header protection via server timeouts
  (`headersTimeout`, `requestTimeout`) and the size guards in §7.2.
* Repeated handshake failures or revoked-cert attempts from one source trip an
  alert (§14.2) — a stolen laptop probing the API must be visible within minutes.
* Backpressure: if the appender queue exceeds its high-water mark, `POST
  /v1/events` returns a retryable `503` with `Retry-After`; reads stay available.

### 7.5 Endpoints

The device identity for every route below comes from the certificate, never from a
header. JSON bodies validated against protocol-package schemas. No cookies, no
bearer tokens for device APIs.

```text
POST /v1/enroll/begin        # enrollment challenge (see §8) — the only pre-cert endpoint,
POST /v1/enroll/complete     # guarded by one-time enrollment tokens issued by admins

GET  /v1/state               # latest sequence, ledger hash, latest checkpoint,
                             # revocation list version, active policy version
GET  /v1/checkpoints?after=  # checkpoint history for anchoring verification
GET  /v1/events?after_seq=   # incremental ledger pull (only events the caller may see)
GET  /v1/snapshots/latest    # signed snapshot manifest + MinIO fetch refs
POST /v1/events              # submit one or a batch of signed events
GET  /v1/revocations         # signed device/key revocation list (versioned)
GET  /v1/policies/active     # signed active policy document

POST /v1/recovery/ceremonies             # initiate (Security Recovery Officer role)
POST /v1/recovery/ceremonies/:id/approve # threshold approvals (signed)
POST /v1/recovery/ceremonies/:id/execute # runs KMS re-wrap after threshold met

# Admin listener (separate port, separate cert policy — admin certs only):
/admin/v1/devices…  /admin/v1/executives…  /admin/v1/quarantine…  /admin/v1/audit…
```

Read authorization: events and snapshots are filtered by the executive's role/ABAC
attributes (the policy engine answers "may this executive see this object_type?").
v1 keeps this coarse (per object_type + entity), not per-row.

---

## 8. PKI, Enrollment, Revocation

* `step-ca` runs on Vorcaro infrastructure with an **offline root** (air-gapped, in a
  safe) and an online intermediate. Device certs are short-lived (7 days) and renewed
  automatically over mTLS with the existing cert — renewal is refused for revoked
  devices, so revocation converges within the cert lifetime even if the CRL is dodged.
* **Enrollment flow**: admin issues a one-time enrollment token out-of-band → device
  generates keypair in hardware where available → `POST /v1/enroll/begin` returns a
  challenge → device proves possession + token → CA issues cert bound to
  (executive, device, public key) → enrollment recorded as a `DEVICE_ENROLLED` ledger
  event.
* **Revocation**: admin action → cert revoked at CA → device row marked revoked →
  signed revocation list version bumped (clients pull it on every sync) → pending
  events from the device transition to `quarantined` via appended status-transition
  events. Forward-only: previously accepted events remain valid (`PLAN.md` §5.2).

---

## 9. Conflict Detection & Resolution

Detection is already in the append pipeline (step 8). Resolution:

* A conflicted object blocks *material* actions (payments, approvals) via a policy
  rule keyed on `object_heads.conflicted` — reads and annotations still work.
* Resolution is a normal signed event (`CONFLICT_RESOLVED`) whose policy requirement
  is the Finance Governance role (multi-party if the object is above threshold). On
  acceptance it clears `object_heads.conflicted` and establishes the new head.
* The server never auto-merges. AI reconciliation proposals (Phase 4) are stored as
  `AIInsight` rows attached to the conflict, clearly labeled, never auto-applied.

---

## 10. Snapshots & Projections

* **Snapshots**: every N events / nightly, a worker folds the ledger into a compact
  state document per financial entity, encrypts it, stores it in MinIO, and writes a
  signed manifest (`up_to_sequence`, `content_hash`). Clients bootstrap from
  snapshot + tail events instead of replaying from genesis.
* **Projections** (reporting read models): tables in the separate `projections.db`
  file (schema in `DATABASE_OVERVIEW.md` §5)
  (`proj_accounts` — one row per bank account with current balance, currency,
  institution, and status; `proj_cash_position` — aggregated across all accounts,
  grouped by entity and currency; `proj_budget_lines`, `proj_approvals_open`,
  …) built by idempotent projection workers keyed on `server_sequence`. Rebuildable
  from scratch at any time — projections are cache, the ledger is truth.
  Monetary projections must retain original `transaction_currency`/`local_rate`
  values, the `default_currency_snapshot_id`, and the derived default-currency
  amount used for policy, cash-position, and board reporting. Reports must label
  the currency basis rather than mixing raw transaction values with
  default-currency totals.
* Reporting APIs read projections only, never the ledger directly.

---

## 11. KMS, Envelope Encryption, Recovery Ceremony

* Server ledger-signing key and the recovery master wrap key live behind PKCS#11.
  Application code sees handles, never key material.
* Per-entity DEKs (AES-256-GCM) encrypt payloads at rest. Each DEK is wrapped twice:
  for the server's operational wrap key (HSM) and for the recovery master key.
* `key_packages` per executive hold DEKs wrapped for that executive's current key
  version (used by clients for local replica decryption).
* **Recovery ceremony** (implements `PLAN.md` §5.2 diagram):
  1. Ceremony row created; target executive + devices quarantined.
  2. M-of-N custodians each submit an Ed25519-signed approval over
     `JCS({ceremony_id, executive_id, new_public_key})`. N and M come from
     `RecoveryPolicy` (default 3-of-5).
  3. On threshold, the execute step re-wraps the executive's DEKs for the new key
     version inside the HSM boundary, writes a new `executive_keys` row
     (`valid_from_sequence` = current head), revokes the old version, and appends
     `RECOVERY_PERFORMED` + `KEY_ROTATED` ledger events.
  4. Every step also lands in `audit_log`. There is no single-admin path — the
     execute endpoint verifies the approval signatures itself, it does not trust a
     UI flag.

Exit test (Phase 2 success criterion): scripted drill — revoke a device, run a full
3-of-5 recovery, confirm the executive's new device can decrypt historical data,
confirm the revoked device's replayed requests are rejected, confirm pre-revocation
events still verify.

---

## 12. Policy Engine & Admin Console

* Policies are versioned JSON documents (thresholds, role permissions, multi-party
  matrices, ABAC conditions, and the enterprise `default_currency`) stored in
  `policies`, activated by a signed `POLICY_CHANGED` ledger event that itself
  requires multi-party approval. The active policy hash is served to clients so
  the local policy engine (app plan §10) evaluates the *same* document.
  Each accepted default-currency policy state also produces a signed
  default-currency snapshot id/hash derived from the policy id, policy hash,
  currency code, and effective ledger sequence. Monetary event `exchange_rate`
  values must reference that snapshot so later audits can prove which default
  currency and policy basis were used.
* Engine: a small pure-function interpreter over the document
  (`evaluate(policy, event, context) → allow | deny | require_approvals[]`).
  Deliberately not a general-purpose language in v1 — auditable over expressive.
* **Admin console** (`admin-ui/`): minimal internal React app served only on the admin
  listener, mTLS with admin certs. Screens: devices (enroll/revoke/quarantine),
  executives & keys, recovery ceremonies, conflicts, checkpoint & chain-verification
  status, audit log search, policy versions, and default currency. The default
  currency control is a policy edit, not a database setting; it shows pending vs.
  accepted states and lands only after the signed `POLICY_CHANGED` event is
  accepted. Every admin action goes through the same signed-event machinery — the
  console has no side door to the database.

---

## 13. Server-Side AI Workers (Phase 4)

* Vorcaro-hosted models only (e.g. vLLM/llama.cpp on Vorcaro GPUs). No third-party APIs.
* Workers read projections + decrypted payloads under a dedicated read-only service
  identity whose access is itself logged and policy-scoped.
* Outputs are written exclusively to `ai_insights` (labeled, versioned, linked to the
  triggering objects). AI has no write path to `ledger_events`, `policies`, or
  `devices` — enforce with DB grants, not just code review.

---

## 14. Operations & Security Baseline

### 14.1 Containerized Deployment (Docker)

The server runs as a Docker container on Vorcaro-owned hardware — no cloud dependency
for core operation. The design goal: the person responsible for the Vorcaro server can
start, stop, restart, and upgrade the service with plain `docker compose` commands,
and **the database files are never touched by container lifecycle**.

```yaml
# /opt/vorcaro/docker-compose.yml (illustrative)
services:
  ledger-server:
    image: registry.vorcaro.internal/ledger-server:1.4.2   # pinned digest in prod
    restart: unless-stopped
    stop_grace_period: 30s          # allow the appender to finish + WAL-checkpoint
    ports:
      - "8443:8443"                 # device mTLS listener
      - "9443:9443"                 # admin listener (separate cert policy)
    volumes:
      - /var/lib/vorcaro:/var/lib/vorcaro        # ledger.db, projections.db, backups/
      - /etc/vorcaro/certs:/etc/vorcaro/certs:ro # server certs, CA bundle
    devices:
      - /dev/bus/usb                # HSM passthrough (hardware-dependent)
    environment:
      - VORCARO_DATA_DIR=/var/lib/vorcaro
  step-ca:
    image: registry.vorcaro.internal/step-ca:…
    restart: unless-stopped
    volumes: [ /var/lib/vorcaro-ca:/home/step ]
  minio:
    image: registry.vorcaro.internal/minio:…
    restart: unless-stopped
    volumes: [ /var/lib/vorcaro-minio:/data ]
```

Rules that make this safe:

* **Data outlives the container.** `ledger.db`, `projections.db`, and `backups/`
  live on the host bind mount `/var/lib/vorcaro` (a **local** filesystem — never
  NFS/SMB; SQLite WAL locking requires it, `DATABASE_OVERVIEW.md` §2). Containers
  are stateless and disposable: `docker compose down && up -d`, image upgrades, and
  crash-restarts never touch the data directory. Deleting the container loses nothing;
  deleting `/var/lib/vorcaro` is the only destructive act, and it is not a Docker verb.
* **Exactly one instance.** SQLite's single-writer discipline means the service must
  never be scaled (`deploy.replicas` > 1 or a second `up` against the same mount is
  forbidden). The server takes an exclusive flock on a lockfile in the data dir at
  boot and refuses to start if it is held — a double-start fails loudly instead of
  corrupting.
* **Graceful shutdown.** On SIGTERM the appender drains its queue, commits or aborts
  the in-flight transaction, runs `wal_checkpoint(TRUNCATE)`, and exits within
  `stop_grace_period`. A hard kill is still safe (WAL recovery), but the graceful
  path keeps restarts boring.
* **Images are Vorcaro-built and signed**, stored in the internal registry, pinned
  by digest in prod. No `latest` tags, no public registries at runtime. Secrets
  (DB-key unwrap config, PKCS#11 PINs) come from host-mounted files readable only
  by the service user — never baked into the image or passed as plain env vars.
* **Container hardening**: read-only root filesystem (`read_only: true`) with the
  data dir as the only writable mount, non-root user, `no-new-privileges`, only the
  two listeners published. The HSM device passthrough is the single hardware grant.
* **Health & runbook**: `HEALTHCHECK` hits a local status endpoint (appender alive,
  DB open, chain-verification age). The operator runbook is three commands —
  `docker compose up -d` (start), `docker compose restart ledger-server` (restart),
  `docker compose pull && docker compose up -d` (upgrade) — plus "never edit
  `/var/lib/vorcaro` by hand."

Single node in v1 + warm standby fed by encrypted snapshot shipping (the standby
machine has the same compose file; failover = restore snapshot + `up -d`). Backups:
nightly `VACUUM INTO` encrypted SQLite snapshots (written into the mounted
`backups/`, so they survive container replacement) shipped to a second Vorcaro site
+ quarterly restore drills (a backup that hasn't been restored is a rumor). Full
procedure in `DATABASE_OVERVIEW.md` §8.

### 14.2 Observability, Verification, Drills
* **Observability**: structured logs (no payload plaintext, no key material, no cert
  private parts), Prometheus metrics, alerting on chain-verification failure, replay
  spikes, revoked-cert connection attempts, appender queue depth.
* **ASVS Level 3 mapping**: maintain a `SECURITY_VERIFICATION.md` checklist mapping
  each ASVS control to its implementation/test. CI runs dependency audit, semgrep,
  and the golden-bytes protocol tests on every commit. Humans approve releases.
* **Threat drills before Phase 3 sign-off**: stolen-device replay, forged-server
  rollback (client checkpoint anchoring must catch it), duplicate submission after
  dropped ack, custodian-collusion tabletop for recovery.

---

## 15. Milestones

| Milestone | Contents | Exit criterion |
|---|---|---|
| S0 | Protocol package + golden fixtures | Cross-package byte-identical signatures |
| S1 | Schema + append pipeline + checkpoints | Phase 1 convergence simulation passes |
| S2 | mTLS API + enrollment + revocation lists | Two real clients enroll and sync |
| S3 | KMS + recovery ceremony + key versioning | Phase 2 recovery drill passes |
| S4 | Policy engine + conflicts end-to-end | Multi-party payment approval works |
| S5 | Snapshots + projections + reporting APIs | Client cold-start from snapshot < 30s |
| S6 | Admin console + audit search | Security sign-off drill list green |
| S7 | AI workers (advisory) | Insights land labeled, zero write paths |
