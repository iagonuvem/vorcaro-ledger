PRAGMA user_version = 1;

CREATE TABLE IF NOT EXISTS executives (
  id                 TEXT PRIMARY KEY,
  display_name       TEXT NOT NULL,
  role               TEXT NOT NULL CHECK (role IN (
    'CEO','CFO','COO','TREASURER','GENERAL_COUNSEL',
    'INTERNAL_AUDIT','SECURITY_RECOVERY_OFFICER','FINANCE_CONTROLLER'
  )),
  status             TEXT NOT NULL CHECK (status IN ('active','quarantined','deactivated')),
  signing_public_key TEXT NOT NULL,
  key_version        INTEGER NOT NULL,
  created_at         TEXT NOT NULL
) STRICT;

CREATE TABLE IF NOT EXISTS executive_keys (
  executive_id         TEXT NOT NULL REFERENCES executives(id),
  key_version          INTEGER NOT NULL,
  signing_public_key   TEXT NOT NULL,
  valid_from_sequence  INTEGER NOT NULL,
  valid_until_sequence INTEGER,
  PRIMARY KEY (executive_id, key_version)
) STRICT, WITHOUT ROWID;

CREATE TABLE IF NOT EXISTS devices (
  id                      TEXT PRIMARY KEY,
  executive_id            TEXT NOT NULL REFERENCES executives(id),
  certificate_fingerprint TEXT NOT NULL UNIQUE,
  public_key              TEXT NOT NULL,
  status                  TEXT NOT NULL CHECK (status IN ('enrolled','revoked','quarantined')),
  hardware_backed         INTEGER NOT NULL DEFAULT 0 CHECK (hardware_backed IN (0,1)),
  enrolled_at             TEXT NOT NULL,
  revoked_at              TEXT,
  last_seen_at            TEXT,
  risk_score              INTEGER NOT NULL DEFAULT 0 CHECK (risk_score BETWEEN 0 AND 100),
  max_event_counter       INTEGER NOT NULL DEFAULT 0
) STRICT;

CREATE TABLE IF NOT EXISTS key_packages (
  id                   TEXT PRIMARY KEY,
  executive_id         TEXT NOT NULL REFERENCES executives(id),
  key_version          INTEGER NOT NULL,
  wrapped_data_key     BLOB NOT NULL,
  recovery_wrapped_key BLOB NOT NULL,
  status               TEXT NOT NULL CHECK (status IN ('active','revoked')),
  created_at           TEXT NOT NULL,
  revoked_at           TEXT
) STRICT;

CREATE TABLE IF NOT EXISTS enrollment_tokens (
  token_hash   TEXT PRIMARY KEY,
  executive_id TEXT NOT NULL REFERENCES executives(id),
  issued_by    TEXT NOT NULL,
  expires_at   TEXT NOT NULL,
  consumed_at  TEXT
) STRICT;

CREATE TABLE IF NOT EXISTS enrollment_challenges (
  id           TEXT PRIMARY KEY,
  token_hash   TEXT NOT NULL REFERENCES enrollment_tokens(token_hash),
  executive_id TEXT NOT NULL REFERENCES executives(id),
  device_id    TEXT NOT NULL,
  public_key   TEXT NOT NULL,
  challenge    TEXT NOT NULL,
  expires_at   TEXT NOT NULL,
  consumed_at  TEXT,
  created_at   TEXT NOT NULL
) STRICT;

CREATE TABLE IF NOT EXISTS ledger_events (
  id                    TEXT PRIMARY KEY,
  server_sequence       INTEGER UNIQUE,
  event_type            TEXT NOT NULL,
  actor_id              TEXT NOT NULL REFERENCES executives(id),
  device_id             TEXT NOT NULL REFERENCES devices(id),
  device_event_counter  INTEGER NOT NULL,
  base_server_sequence  INTEGER NOT NULL,
  object_type           TEXT NOT NULL,
  object_id             TEXT NOT NULL,
  policy_metadata       TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(policy_metadata)),
  account_id            TEXT GENERATED ALWAYS AS (json_extract(policy_metadata, '$.account_id')) STORED,
  entity_id             TEXT GENERATED ALWAYS AS (json_extract(policy_metadata, '$.entity_id')) STORED,
  encrypted_payload     BLOB NOT NULL,
  payload_hash          TEXT NOT NULL,
  previous_ledger_hash  TEXT,
  resulting_ledger_hash TEXT,
  client_signature      TEXT NOT NULL,
  server_signature      TEXT,
  status                TEXT NOT NULL CHECK (status IN ('pending','accepted','rejected','conflicted','quarantined')),
  error_code            TEXT CHECK (error_code IN (
    'CERT_REVOKED','CERT_UNKNOWN','EXECUTIVE_INACTIVE',
    'REPLAY_COUNTER','DUPLICATE_EVENT','BAD_SIGNATURE',
    'BAD_PAYLOAD_HASH','SCHEMA_INVALID','STALE_BASE',
    'CONFLICT','POLICY_DENIED','APPROVALS_REQUIRED',
    'UNKNOWN_ACCOUNT','ACCOUNT_CLOSED','POLICY_VERSION_MISMATCH'
  )),
  client_timestamp      TEXT NOT NULL,
  server_timestamp      TEXT NOT NULL,
  accepted_at           TEXT,
  UNIQUE (device_id, device_event_counter)
) STRICT;

CREATE INDEX IF NOT EXISTS idx_ledger_object ON ledger_events (object_type, object_id, server_sequence);
CREATE INDEX IF NOT EXISTS idx_ledger_account ON ledger_events (account_id) WHERE account_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_ledger_actor ON ledger_events (actor_id, server_sequence);
CREATE INDEX IF NOT EXISTS idx_ledger_status ON ledger_events (status) WHERE status <> 'accepted';

CREATE TABLE IF NOT EXISTS object_heads (
  object_type   TEXT NOT NULL,
  object_id     TEXT NOT NULL,
  head_sequence INTEGER NOT NULL,
  conflicted    INTEGER NOT NULL DEFAULT 0 CHECK (conflicted IN (0,1)),
  PRIMARY KEY (object_type, object_id)
) STRICT, WITHOUT ROWID;

CREATE TABLE IF NOT EXISTS revocation_list_versions (
  version   INTEGER PRIMARY KEY,
  document  TEXT NOT NULL CHECK (json_valid(document)),
  signature TEXT NOT NULL,
  issued_at TEXT NOT NULL
) STRICT;

CREATE TABLE IF NOT EXISTS checkpoints (
  sequence    INTEGER PRIMARY KEY,
  ledger_hash TEXT NOT NULL,
  issued_at   TEXT NOT NULL,
  key_version INTEGER NOT NULL,
  signature   TEXT NOT NULL
) STRICT, WITHOUT ROWID;

CREATE TABLE IF NOT EXISTS snapshots (
  id             TEXT PRIMARY KEY,
  up_to_sequence INTEGER NOT NULL,
  content_hash   TEXT NOT NULL,
  storage_ref    TEXT NOT NULL,
  signature      TEXT NOT NULL,
  created_at     TEXT NOT NULL
) STRICT;

CREATE TABLE IF NOT EXISTS recovery_ceremonies (
  id                 TEXT PRIMARY KEY,
  executive_id       TEXT NOT NULL REFERENCES executives(id),
  initiated_by       TEXT NOT NULL,
  new_public_key     TEXT NOT NULL,
  status             TEXT NOT NULL CHECK (status IN ('open','threshold_met','executed','aborted')),
  required_approvals INTEGER NOT NULL,
  created_at         TEXT NOT NULL,
  completed_at       TEXT
) STRICT;

CREATE TABLE IF NOT EXISTS recovery_approvals (
  ceremony_id        TEXT NOT NULL REFERENCES recovery_ceremonies(id),
  approver_id        TEXT NOT NULL,
  approval_signature TEXT NOT NULL,
  created_at         TEXT NOT NULL,
  PRIMARY KEY (ceremony_id, approver_id)
) STRICT, WITHOUT ROWID;

CREATE TABLE IF NOT EXISTS policies (
  id                    TEXT PRIMARY KEY,
  version               INTEGER NOT NULL UNIQUE,
  document              TEXT NOT NULL CHECK (json_valid(document)),
  document_hash         TEXT NOT NULL,
  activated_at_sequence INTEGER
) STRICT;

CREATE TABLE IF NOT EXISTS audit_log (
  id            INTEGER PRIMARY KEY AUTOINCREMENT,
  category      TEXT NOT NULL CHECK (category IN (
    'auth','sync','admin','recovery','revocation',
    'export','ipc_anomaly','chain_verification','ai_access'
  )),
  actor         TEXT NOT NULL,
  detail        TEXT NOT NULL CHECK (json_valid(detail)),
  previous_hash TEXT NOT NULL,
  entry_hash    TEXT NOT NULL,
  created_at    TEXT NOT NULL
) STRICT;

CREATE TABLE IF NOT EXISTS ai_insights (
  id                  TEXT PRIMARY KEY,
  kind                TEXT NOT NULL CHECK (kind IN (
    'cash_flow_summary','burn_rate','anomaly','duplicate_invoice',
    'vendor_risk','variance_explanation','reconciliation_suggestion',
    'conflict_resolution_proposal','board_summary_draft'
  )),
  related_object_type TEXT,
  related_object_id   TEXT,
  body                TEXT NOT NULL,
  model_version       TEXT NOT NULL,
  origin              TEXT NOT NULL CHECK (origin IN ('local','vorcaro_server')),
  created_at          TEXT NOT NULL
) STRICT;

CREATE TRIGGER IF NOT EXISTS ledger_events_no_update BEFORE UPDATE ON ledger_events
BEGIN SELECT RAISE(ABORT, 'ledger_events is append-only'); END;

CREATE TRIGGER IF NOT EXISTS ledger_events_no_delete BEFORE DELETE ON ledger_events
BEGIN SELECT RAISE(ABORT, 'ledger_events is append-only'); END;

CREATE TRIGGER IF NOT EXISTS checkpoints_no_update BEFORE UPDATE ON checkpoints
BEGIN SELECT RAISE(ABORT, 'checkpoints is append-only'); END;

CREATE TRIGGER IF NOT EXISTS checkpoints_no_delete BEFORE DELETE ON checkpoints
BEGIN SELECT RAISE(ABORT, 'checkpoints is append-only'); END;

CREATE TRIGGER IF NOT EXISTS audit_log_no_update BEFORE UPDATE ON audit_log
BEGIN SELECT RAISE(ABORT, 'audit_log is append-only'); END;

CREATE TRIGGER IF NOT EXISTS audit_log_no_delete BEFORE DELETE ON audit_log
BEGIN SELECT RAISE(ABORT, 'audit_log is append-only'); END;

CREATE TRIGGER IF NOT EXISTS recovery_approvals_no_update BEFORE UPDATE ON recovery_approvals
BEGIN SELECT RAISE(ABORT, 'recovery_approvals is append-only'); END;

CREATE TRIGGER IF NOT EXISTS recovery_approvals_no_delete BEFORE DELETE ON recovery_approvals
BEGIN SELECT RAISE(ABORT, 'recovery_approvals is append-only'); END;

CREATE TRIGGER IF NOT EXISTS revocation_list_versions_no_update BEFORE UPDATE ON revocation_list_versions
BEGIN SELECT RAISE(ABORT, 'revocation_list_versions is append-only'); END;

CREATE TRIGGER IF NOT EXISTS revocation_list_versions_no_delete BEFORE DELETE ON revocation_list_versions
BEGIN SELECT RAISE(ABORT, 'revocation_list_versions is append-only'); END;

CREATE TRIGGER IF NOT EXISTS snapshots_no_update BEFORE UPDATE ON snapshots
BEGIN SELECT RAISE(ABORT, 'snapshots is append-only'); END;

CREATE TRIGGER IF NOT EXISTS snapshots_no_delete BEFORE DELETE ON snapshots
BEGIN SELECT RAISE(ABORT, 'snapshots is append-only'); END;
