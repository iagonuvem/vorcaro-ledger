# Vorcaro Finance Server — Database Overview (SQLite)

Companion to `PLAN.md`, `SERVER_IMPLEMENTATION_PLAN.md`, and `COMMON_TYPES.md`.
This document is the authoritative description of the **server** database schema.
The server uses **SQLite** (SQLCipher-encrypted) as its embedded datastore. Where
this document and `PLAN.md` disagree, `PLAN.md` wins.

Entity field semantics (types, enums, ID prefixes, money-as-minor-units) are
defined in `COMMON_TYPES.md`; this document maps them to physical storage.

---

## 1. Why SQLite Fits This Server

* **Single-writer by design.** The append pipeline already mandates exactly one
  appender assigning `server_sequence` (`SERVER_IMPLEMENTATION_PLAN.md` §6).
  SQLite's one-writer model is not a limitation here — it is the same
  discipline, enforced by the engine.
* **Sovereignty.** No database server process, no network listener, no DBA
  surface. The datastore is a file on Vorcaro hardware, encrypted at rest,
  readable forever with public tooling — consistent with `PLAN.md` §2.1
  ("if every vendor vanished, could Vorcaro still read its data?").
* **Determinism and auditability.** A single file with a hash-chained ledger
  can be copied, archived, and independently re-verified from genesis with
  nothing but the SQLite CLI and the protocol package.

Accepted trade-offs (stated, not hidden):

* **No roles/GRANTs.** SQLite has no user system. Postgres-style "revoke
  UPDATE/DELETE from the app role" is replaced by the compensating controls in
  §3. This is acceptable because the DB is embedded in a single trusted server
  process — there is no shared-database attack surface to begin with.
* **Single node.** Warm standby is periodic snapshot shipping (§8), not
  streaming replication. v1 explicitly targets one server node
  (`SERVER_IMPLEMENTATION_PLAN.md` §14).

---

## 2. File Layout & Engine Configuration

Two database files, one purpose each:

```text
/var/lib/vorcaro/
├── ledger.db          # AUTHORITATIVE. Ledger, identity, PKI state, recovery,
│                      # policies, audit log. SQLCipher-encrypted. Backed up.
├── projections.db     # REBUILDABLE CACHE. Reporting read models only.
│                      # Deletable at any time; rebuilt from ledger.db.
└── backups/           # VACUUM INTO snapshots (encrypted), shipped off-box.
```

Attachments and snapshot bodies stay in MinIO (encrypted); the DB stores only
references and content hashes.

Required PRAGMAs, set on every connection at open:

```sql
PRAGMA journal_mode = WAL;        -- concurrent readers alongside the single writer
PRAGMA synchronous  = FULL;       -- durability over throughput (PLAN.md §2.2:
                                  -- "Speed is optional. Truth is not.")
PRAGMA foreign_keys = ON;         -- off by default in SQLite; must be explicit
PRAGMA busy_timeout = 5000;
PRAGMA trusted_schema = OFF;
```

Additional rules:

* **Encryption at rest**: SQLCipher full-database encryption. The database key
  is a server DEK wrapped by the HSM/KMS (PKCS#11) — same envelope discipline
  as payload DEKs (`SERVER_IMPLEMENTATION_PLAN.md` §11). The unwrapped DB key
  exists only in guarded server-process memory.
* **STRICT tables everywhere** (SQLite ≥ 3.37): no silent type coercion in a
  finance ledger.
* **Types mapping** (from `COMMON_TYPES.md` conventions): IDs and hashes are
  `TEXT`; sequences and counters are `INTEGER` (64-bit, safe for `bigint`
  protocol fields); money amounts are `INTEGER` minor units + `TEXT` currency;
  timestamps are `TEXT` ISO 8601 UTC; JSON documents are `TEXT` with
  `json_valid()` CHECKs; encrypted payloads are `BLOB`.
* File permissions `0600`, owned by the dedicated service user. The OS account
  boundary is part of the security model (§3).

---

## 3. Security Enforcement Without GRANTs

SQLite cannot revoke UPDATE/DELETE per role, so append-only is enforced in
depth:

1. **Triggers** (primary in-engine control): `BEFORE UPDATE` / `BEFORE DELETE`
   triggers on every append-only table `RAISE(ABORT, ...)` unconditionally
   (§6). The appender never needs UPDATE on these tables — rows are inserted
   complete, including server-assigned fields.
2. **Connection separation**: only the appender worker holds a read-write
   connection to `ledger.db`. Every other component (API reads, projections,
   AI workers, admin queries) opens `mode=ro` connections and additionally
   sets `PRAGMA query_only = ON`. AI workers get read access to
   `projections.db` only — the "no AI write path" rule
   (`SERVER_IMPLEMENTATION_PLAN.md` §13) becomes a file-permission fact.
3. **OS boundary**: `ledger.db` is writable by the ledger service user alone;
   the AI worker and admin-console processes run as different users with
   read-only file access where granted.
4. **Hash-chain verification** (detective control): the nightly job re-derives
   the full chain from genesis and compares against the latest checkpoint.
   Because `resulting_ledger_hash` covers canonical event bytes, any tamper —
   even by root editing the file — breaks the chain or the server signatures.
   A mismatch pages security; it is never auto-repaired.
5. **Mutable-row discipline**: the only tables the appender may UPDATE are
   `object_heads` and `devices` (`max_event_counter`, `last_seen_at`) — the
   two hot rows named in `SERVER_IMPLEMENTATION_PLAN.md` §5. Identity/PKI
   status changes happen via appended ledger events first; the materialized
   rows follow.

---

## 4. Authoritative Schema — `ledger.db`

### 4.1 The ledger

```sql
CREATE TABLE ledger_events (
  id                    TEXT PRIMARY KEY,       -- client ULID (idempotency key)
  server_sequence       INTEGER UNIQUE,         -- NULL until appended; gapless for accepted
  event_type            TEXT NOT NULL,
  actor_id              TEXT NOT NULL REFERENCES executives(id),
  device_id             TEXT NOT NULL REFERENCES devices(id),
  device_event_counter  INTEGER NOT NULL,
  base_server_sequence  INTEGER NOT NULL,
  object_type           TEXT NOT NULL,
  object_id             TEXT NOT NULL,
  policy_metadata       TEXT NOT NULL DEFAULT '{}'
                          CHECK (json_valid(policy_metadata)),
  -- generated columns expose plaintext-signed routing fields for indexing
  account_id            TEXT GENERATED ALWAYS AS
                          (json_extract(policy_metadata, '$.account_id')) STORED,
  entity_id             TEXT GENERATED ALWAYS AS
                          (json_extract(policy_metadata, '$.entity_id')) STORED,
  encrypted_payload     BLOB NOT NULL,
  payload_hash          TEXT NOT NULL,
  previous_ledger_hash  TEXT,                   -- server-assigned at append
  resulting_ledger_hash TEXT,                   -- server-assigned at append
  client_signature      TEXT NOT NULL,
  server_signature      TEXT,
  status                TEXT NOT NULL CHECK (status IN
                          ('pending','accepted','rejected','conflicted','quarantined')),
  client_timestamp      TEXT NOT NULL,          -- recorded, never trusted for policy
  server_timestamp      TEXT NOT NULL,          -- authoritative (set by appender, UTC)
  accepted_at           TEXT,
  UNIQUE (device_id, device_event_counter)      -- replay protection in the engine too
) STRICT;

CREATE INDEX idx_ledger_object   ON ledger_events (object_type, object_id, server_sequence);
CREATE INDEX idx_ledger_account  ON ledger_events (account_id) WHERE account_id IS NOT NULL;
CREATE INDEX idx_ledger_actor    ON ledger_events (actor_id, server_sequence);
CREATE INDEX idx_ledger_status   ON ledger_events (status) WHERE status <> 'accepted';
```

Rows are inserted **complete** — server fields included — inside the single
append transaction, so the append-only triggers can be absolute. Status
transitions append a new `STATUS_TRANSITION` event; the materialized current
status lives in `object_heads` and projections, never as an UPDATE here.

### 4.2 Conflict working set (mutable)

```sql
CREATE TABLE object_heads (
  object_type   TEXT NOT NULL,
  object_id     TEXT NOT NULL,
  head_sequence INTEGER NOT NULL,   -- last accepted event touching this object
  conflicted    INTEGER NOT NULL DEFAULT 0 CHECK (conflicted IN (0,1)),
  PRIMARY KEY (object_type, object_id)
) STRICT, WITHOUT ROWID;
```

### 4.3 Identity & PKI (materialized state; changes driven by ledger events)

```sql
CREATE TABLE executives (
  id                 TEXT PRIMARY KEY,
  display_name       TEXT NOT NULL,
  role               TEXT NOT NULL,             -- Role enum, COMMON_TYPES.md §3.1
  status             TEXT NOT NULL CHECK (status IN ('active','quarantined','deactivated')),
  signing_public_key TEXT NOT NULL,             -- current key version
  key_version        INTEGER NOT NULL,
  created_at         TEXT NOT NULL
) STRICT;

CREATE TABLE executive_keys (                   -- key history: verify old events
  executive_id         TEXT NOT NULL REFERENCES executives(id),
  key_version          INTEGER NOT NULL,
  signing_public_key   TEXT NOT NULL,
  valid_from_sequence  INTEGER NOT NULL,        -- authority window (forward-only
  valid_until_sequence INTEGER,                 --  revocation, PLAN.md §5.2)
  PRIMARY KEY (executive_id, key_version)
) STRICT, WITHOUT ROWID;

CREATE TABLE devices (
  id                      TEXT PRIMARY KEY,
  executive_id            TEXT NOT NULL REFERENCES executives(id),
  certificate_fingerprint TEXT NOT NULL UNIQUE,
  public_key              TEXT NOT NULL,
  status                  TEXT NOT NULL CHECK (status IN ('enrolled','revoked','quarantined')),
  hardware_backed         INTEGER NOT NULL DEFAULT 0 CHECK (hardware_backed IN (0,1)),
  enrolled_at             TEXT NOT NULL,
  revoked_at              TEXT,
  last_seen_at            TEXT,
  risk_score              INTEGER NOT NULL DEFAULT 0,
  max_event_counter       INTEGER NOT NULL DEFAULT 0   -- replay watermark (hot row)
) STRICT;

CREATE TABLE key_packages (
  id                   TEXT PRIMARY KEY,
  executive_id         TEXT NOT NULL REFERENCES executives(id),
  key_version          INTEGER NOT NULL,
  wrapped_data_key     BLOB NOT NULL,
  recovery_wrapped_key BLOB NOT NULL,
  status               TEXT NOT NULL CHECK (status IN ('active','revoked')),
  created_at           TEXT NOT NULL,
  revoked_at           TEXT
) STRICT;

CREATE TABLE enrollment_tokens (                -- one-time, admin-issued (§8 of server plan)
  token_hash  TEXT PRIMARY KEY,                 -- store the hash, never the token
  executive_id TEXT NOT NULL REFERENCES executives(id),
  issued_by   TEXT NOT NULL,
  expires_at  TEXT NOT NULL,
  consumed_at TEXT
) STRICT;

CREATE TABLE revocation_list_versions (         -- append-only; served signed to clients
  version    INTEGER PRIMARY KEY,
  document   TEXT NOT NULL CHECK (json_valid(document)),  -- RevocationList, COMMON_TYPES.md §3.7
  signature  TEXT NOT NULL,
  issued_at  TEXT NOT NULL
) STRICT;
```

### 4.4 Chain anchors & snapshots (append-only)

```sql
CREATE TABLE checkpoints (
  sequence    INTEGER PRIMARY KEY,
  ledger_hash TEXT NOT NULL,
  issued_at   TEXT NOT NULL,
  key_version INTEGER NOT NULL,                 -- server signing key version
  signature   TEXT NOT NULL
) STRICT, WITHOUT ROWID;

CREATE TABLE snapshots (
  id             TEXT PRIMARY KEY,
  up_to_sequence INTEGER NOT NULL,
  content_hash   TEXT NOT NULL,
  storage_ref    TEXT NOT NULL,                 -- MinIO object (encrypted body)
  signature      TEXT NOT NULL,
  created_at     TEXT NOT NULL
) STRICT;
```

### 4.5 Recovery ceremonies

```sql
CREATE TABLE recovery_ceremonies (
  id                 TEXT PRIMARY KEY,
  executive_id       TEXT NOT NULL REFERENCES executives(id),
  initiated_by       TEXT NOT NULL,
  new_public_key     TEXT NOT NULL,
  status             TEXT NOT NULL CHECK (status IN
                       ('open','threshold_met','executed','aborted')),
  required_approvals INTEGER NOT NULL,
  created_at         TEXT NOT NULL,
  completed_at       TEXT
) STRICT;

CREATE TABLE recovery_approvals (               -- append-only: an approval, once
  ceremony_id        TEXT NOT NULL REFERENCES recovery_ceremonies(id),
  approver_id        TEXT NOT NULL,             --  given, is permanent evidence
  approval_signature TEXT NOT NULL,             -- Ed25519 over JCS({ceremony_id,
  created_at         TEXT NOT NULL,             --  executive_id, new_public_key})
  PRIMARY KEY (ceremony_id, approver_id)
) STRICT, WITHOUT ROWID;
```

### 4.6 Policies & audit (append-only)

```sql
CREATE TABLE policies (
  id                     TEXT PRIMARY KEY,
  version                INTEGER NOT NULL UNIQUE,
  document               TEXT NOT NULL CHECK (json_valid(document)),
  document_hash          TEXT NOT NULL,
  activated_at_sequence  INTEGER               -- set via the POLICY_CHANGED event's
) STRICT;                                       -- append; a new policy = a new row

CREATE TABLE audit_log (
  id            INTEGER PRIMARY KEY AUTOINCREMENT,  -- AUTOINCREMENT: ids never reused
  category      TEXT NOT NULL,                 -- AuditCategory, COMMON_TYPES.md §5.1
  actor         TEXT NOT NULL,
  detail        TEXT NOT NULL CHECK (json_valid(detail)),  -- never payload plaintext
  previous_hash TEXT NOT NULL,                 -- hash-chained like the ledger
  entry_hash    TEXT NOT NULL,
  created_at    TEXT NOT NULL
) STRICT;

CREATE TABLE ai_insights (                      -- advisory outputs; the ONLY table
  id                  TEXT PRIMARY KEY,         --  AI workers may write (via a
  kind                TEXT NOT NULL,            --  dedicated narrow writer process)
  related_object_type TEXT,
  related_object_id   TEXT,
  body                TEXT NOT NULL,
  model_version       TEXT NOT NULL,
  origin              TEXT NOT NULL CHECK (origin IN ('local','vorcaro_server')),
  created_at          TEXT NOT NULL
) STRICT;
```

---

## 5. Read Models — `projections.db`

Rebuildable at any time from `ledger.db`; projections are cache, the ledger is
truth. Reporting APIs read this file only.

```sql
CREATE TABLE proj_meta (                        -- projection watermark
  key TEXT PRIMARY KEY, value TEXT NOT NULL     -- e.g. ('last_applied_sequence', ...)
) STRICT, WITHOUT ROWID;

CREATE TABLE proj_accounts (                    -- one row per bank account (unbounded)
  account_id          TEXT PRIMARY KEY,
  entity_id           TEXT NOT NULL,
  name                TEXT NOT NULL,
  account_type        TEXT NOT NULL,
  institution_name    TEXT NOT NULL,
  account_number_masked TEXT NOT NULL,
  currency            TEXT NOT NULL,
  balance_minor_units INTEGER NOT NULL,
  as_of_sequence      INTEGER NOT NULL,
  status              TEXT NOT NULL,
  conflicted          INTEGER NOT NULL DEFAULT 0
) STRICT;

CREATE TABLE proj_cash_position (               -- aggregated across accounts
  entity_id           TEXT NOT NULL,
  currency            TEXT NOT NULL,
  total_minor_units   INTEGER NOT NULL,
  pending_delta_minor_units INTEGER NOT NULL,   -- pending shown separately (DESIGN.md §2)
  as_of_sequence      INTEGER NOT NULL,
  PRIMARY KEY (entity_id, currency)
) STRICT, WITHOUT ROWID;

CREATE TABLE proj_transactions (
  transaction_id      TEXT PRIMARY KEY,
  account_id          TEXT NOT NULL,
  entity_id           TEXT NOT NULL,
  vendor_id           TEXT,
  direction           TEXT NOT NULL,
  amount_minor_units  INTEGER NOT NULL,
  currency            TEXT NOT NULL,
  occurred_at         TEXT NOT NULL,
  classification      TEXT,
  reconciled          INTEGER NOT NULL DEFAULT 0,
  source_event_id     TEXT NOT NULL
) STRICT;
CREATE INDEX idx_proj_txn_account ON proj_transactions (account_id, occurred_at);

CREATE TABLE proj_budget_lines (
  budget_id TEXT NOT NULL, category TEXT NOT NULL,
  amount_minor_units INTEGER NOT NULL, currency TEXT NOT NULL,
  status TEXT NOT NULL,
  PRIMARY KEY (budget_id, category)
) STRICT, WITHOUT ROWID;

CREATE TABLE proj_approvals_open (
  approval_id     TEXT PRIMARY KEY,
  target_object_type TEXT NOT NULL,
  target_object_id   TEXT NOT NULL,
  account_id      TEXT,
  amount_minor_units INTEGER,
  currency        TEXT,
  required_count  INTEGER NOT NULL,
  signature_count INTEGER NOT NULL,
  requested_by    TEXT NOT NULL,
  created_at      TEXT NOT NULL
) STRICT;

CREATE TABLE proj_conflicts_open (
  conflict_id  TEXT PRIMARY KEY,
  object_type  TEXT NOT NULL,
  object_id    TEXT NOT NULL,
  event_ids    TEXT NOT NULL CHECK (json_valid(event_ids)),
  detected_at_sequence INTEGER NOT NULL
) STRICT;
```

Projection workers are idempotent and keyed on `server_sequence`
(`last_applied_sequence` in `proj_meta`); replaying the same event range twice
must produce identical rows.

---

## 6. Append-Only Triggers

Applied to `ledger_events`, `checkpoints`, `audit_log`, `recovery_approvals`,
`revocation_list_versions`, and `snapshots`:

```sql
CREATE TRIGGER <table>_no_update BEFORE UPDATE ON <table>
BEGIN SELECT RAISE(ABORT, '<table> is append-only'); END;

CREATE TRIGGER <table>_no_delete BEFORE DELETE ON <table>
BEGIN SELECT RAISE(ABORT, '<table> is append-only'); END;
```

There are deliberately **no** conditional escapes in these triggers. Schema
migrations that would require rewriting an append-only table are forbidden by
policy — additive migrations only (§9).

---

## 7. Transactions & Concurrency

* The appender wraps each append in `BEGIN IMMEDIATE … COMMIT`: validate →
  insert complete `ledger_events` row (with `server_sequence`, chain hashes,
  server signature) → upsert `object_heads` → bump `devices.max_event_counter`
  → optionally insert a checkpoint. One transaction, exactly as
  `SERVER_IMPLEMENTATION_PLAN.md` §6 step 9 requires.
* `server_sequence` assignment: the appender is the only writer, so it reads
  `MAX(server_sequence)` inside its own transaction — gapless by construction,
  no sequence object needed.
* Readers use WAL-mode snapshot isolation on `mode=ro` connections; they never
  block the appender and never see a half-applied append.
* If HA is ever added, appender election must be an external mechanism (e.g.
  systemd + shared-nothing failover onto the replicated snapshot); SQLite
  assumes exactly one live server node. Do not shard the sequence.

---

## 8. Backup, Integrity, Retention

* **Nightly backup**: `VACUUM INTO` an encrypted snapshot in `backups/`
  (consistent copy without stopping the appender), then ship to the second
  Vorcaro site. `projections.db` is not backed up — it is rebuildable.
* **Quarterly restore drills**: restore the snapshot on the standby, rebuild
  projections, run full chain verification. A backup that hasn't been restored
  is a rumor (`SERVER_IMPLEMENTATION_PLAN.md` §14).
* **Nightly integrity**: `PRAGMA integrity_check` + full hash-chain
  re-derivation from genesis vs. the latest checkpoint. Any mismatch pages
  security and is never auto-repaired.
* **Retention**: nothing in `ledger.db` is ever deleted — rejected and
  quarantined events are audit evidence (`PLAN.md` §11). WAL checkpointing
  (`wal_checkpoint(TRUNCATE)`) runs after backup to bound file growth.

---

## 9. Migration Discipline

* Schema version tracked in `PRAGMA user_version`; migrations run at startup
  inside a single transaction, before the appender accepts work.
* Migrations are **additive only** for append-only tables (new tables, new
  nullable/generated columns, new indexes). Any migration touching existing
  rows of an append-only table is rejected in code review by policy.
* Every migration file is hashed and its application is recorded in
  `audit_log` (`category = 'admin'`).
