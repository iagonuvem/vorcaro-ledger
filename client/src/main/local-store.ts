import { createHash } from "node:crypto";
import { mkdirSync } from "node:fs";
import { createRequire } from "node:module";
import path from "node:path";

import { canonicalBytes, type CanonicalJson } from "@vorcaro/protocol";
import type { Checkpoint, ClientEventEnvelope, LedgerEvent, PolicyDocument, ServerAck } from "@vorcaro/protocol";
import { LocalPolicyEngine } from "./local-policy.js";

const require = createRequire(import.meta.url);
const Database = require("better-sqlite3-multiple-ciphers") as typeof import("better-sqlite3-multiple-ciphers");

export type LocalDatabase = import("better-sqlite3-multiple-ciphers").Database;

export type OpenLocalStoreOptions = {
  readonly databasePath: string;
  readonly databaseKey: Buffer;
  readonly readonly?: boolean;
};

export type LocalAuditCategory =
  | "auth"
  | "sync"
  | "export"
  | "ipc_anomaly"
  | "chain_verification"
  | "security_acknowledgement";

export type WriteLocalAuditInput = {
  readonly category: LocalAuditCategory;
  readonly body: CanonicalJson;
  readonly recordedAt: string;
};

export type QueuePendingEventInput = {
  readonly event: import("@vorcaro/protocol").ClientEventEnvelope;
  readonly envelopeBytes: Buffer;
  readonly createdAt: string;
};

export type BuildPendingEventContext = {
  readonly deviceEventCounter: number;
  readonly lastVerifiedSequence: bigint;
};

export type DeviceCredentials = {
  readonly executiveId: string;
  readonly executiveRole: string;
  readonly deviceId: string;
  readonly deviceRiskScore: number;
  readonly serverBaseUrl: string;
  readonly serverCaPem: string;
  readonly clientCertificatePem: string;
  readonly clientPrivateKeyPem: string;
  readonly certificateFingerprint: string;
  readonly certificateExpiresAt: string;
  readonly hardwareBacked: boolean;
};

const schemaVersion = 1;
const genesisAuditHash = "sha256:0000000000000000000000000000000000000000000000000000000000000000";
const genesisLedgerHash = "sha256:0000000000000000000000000000000000000000000000000000000000000000";

export class LocalStore {
  private readonly database: LocalDatabase;

  constructor(database: LocalDatabase) {
    this.database = database;
  }

  static open(options: OpenLocalStoreOptions): LocalStore {
    mkdirSync(path.dirname(options.databasePath), { recursive: true, mode: 0o700 });

    const database = new Database(options.databasePath, {
      readonly: options.readonly ?? false,
      fileMustExist: options.readonly ?? false,
      timeout: 5000
    });

    try {
      database.pragma("cipher = 'sqlcipher'");
      database.pragma("legacy = 4");
      database.key(options.databaseKey);
      configureConnection(database);

      if (options.readonly === true) {
        database.pragma("query_only = ON");
      } else {
        initializeSchema(database);
      }

      return new LocalStore(database);
    } catch (error) {
      database.close();
      throw error;
    }
  }

  close(): void {
    if (this.database.open) {
      this.database.close();
    }
  }

  databaseForInternalUse(): LocalDatabase {
    return this.database;
  }

  readMeta(key: string): string | null {
    const row = this.database.prepare<[string], { value: string }>("SELECT value FROM meta WHERE key = ?").get(key);
    return row?.value ?? null;
  }

  writeMeta(key: string, value: string): void {
    this.database
      .prepare<[string, string]>(
        "INSERT INTO meta (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value"
      )
      .run(key, value);
  }

  readActivePolicy(): PolicyDocument | null {
    const serialized = this.readMeta("active_policy_document");
    return serialized === null ? null : LocalPolicyEngine.parsePolicyDocument(serialized);
  }

  writeActivePolicy(policy: PolicyDocument): void {
    this.writeMeta("active_policy_document", LocalPolicyEngine.serializePolicyDocument(policy));
    this.writeMeta("active_policy_version", policy.version.toString(10));
  }

  requireMeta(key: string): string {
    const value = this.readMeta(key);

    if (value === null) {
      throw new Error(`Missing local metadata: ${key}`);
    }

    return value;
  }

  writeDeviceCredentials(credentials: DeviceCredentials): void {
    assertDeviceCredentials(credentials);
    const transaction = this.database.transaction(() => {
      this.writeMeta("executive_id", credentials.executiveId);
      this.writeMeta("executive_role", credentials.executiveRole);
      this.writeMeta("device_id", credentials.deviceId);
      this.writeMeta("device_risk_score", credentials.deviceRiskScore.toString(10));
      this.writeMeta("sync_server_base_url", credentials.serverBaseUrl);
      this.writeMeta("sync_server_ca_pem", credentials.serverCaPem);
      this.writeMeta("device_certificate_pem", credentials.clientCertificatePem);
      this.writeMeta("device_private_key_pem", credentials.clientPrivateKeyPem);
      this.writeMeta("device_certificate_fingerprint", credentials.certificateFingerprint);
      this.writeMeta("device_certificate_expires_at", credentials.certificateExpiresAt);
      this.writeMeta("device_hardware_backed", credentials.hardwareBacked ? "true" : "false");
    });

    transaction.immediate();
  }

  readDeviceCredentials(): DeviceCredentials | null {
    const executiveId = this.readMeta("executive_id");
    const executiveRole = this.readMeta("executive_role");
    const deviceId = this.readMeta("device_id");
    const deviceRiskScore = this.readMeta("device_risk_score");
    const serverBaseUrl = this.readMeta("sync_server_base_url");
    const serverCaPem = this.readMeta("sync_server_ca_pem");
    const clientCertificatePem = this.readMeta("device_certificate_pem");
    const clientPrivateKeyPem = this.readMeta("device_private_key_pem");
    const certificateFingerprint = this.readMeta("device_certificate_fingerprint");
    const certificateExpiresAt = this.readMeta("device_certificate_expires_at");
    const hardwareBacked = this.readMeta("device_hardware_backed");

    if (
      executiveId === null ||
      executiveRole === null ||
      deviceId === null ||
      deviceRiskScore === null ||
      serverBaseUrl === null ||
      serverCaPem === null ||
      clientCertificatePem === null ||
      clientPrivateKeyPem === null ||
      certificateFingerprint === null ||
      certificateExpiresAt === null ||
      hardwareBacked === null
    ) {
      return null;
    }

    const credentials = {
      executiveId,
      executiveRole,
      deviceId,
      deviceRiskScore: Number.parseInt(deviceRiskScore, 10),
      serverBaseUrl,
      serverCaPem,
      clientCertificatePem,
      clientPrivateKeyPem,
      certificateFingerprint,
      certificateExpiresAt,
      hardwareBacked: hardwareBacked === "true"
    };
    assertDeviceCredentials(credentials);
    return credentials;
  }

  allocateDeviceEventCounter(): number {
    const transaction = this.database.transaction(() => {
      const row = this.database
        .prepare<[], { value: string }>("SELECT value FROM meta WHERE key = 'device_event_counter'")
        .get();
      const current = row ? Number.parseInt(row.value, 10) : 0;
      const next = current + 1;

      if (!Number.isSafeInteger(next) || next <= 0) {
        throw new Error("Device event counter exhausted");
      }

      this.database
        .prepare<[string]>("UPDATE meta SET value = ? WHERE key = 'device_event_counter'")
        .run(String(next));
      return next;
    });

    return transaction.immediate();
  }

  createPendingEvent(
    build: (context: BuildPendingEventContext) => QueuePendingEventInput
  ): import("@vorcaro/protocol").ClientEventEnvelope {
    const transaction = this.database.transaction(() => {
      const counter = this.nextDeviceEventCounter();
      const state = this.database
        .prepare<[], { last_verified_sequence: number }>(
          "SELECT last_verified_sequence FROM sync_state WHERE id = 1"
        )
        .get();

      if (!state) {
        throw new Error("Missing local sync state");
      }

      const input = build({
        deviceEventCounter: counter,
        lastVerifiedSequence: BigInt(state.last_verified_sequence)
      });

      if (input.event.device_event_counter !== BigInt(counter)) {
        throw new Error("Pending event counter mismatch");
      }

      this.database
        .prepare<[string]>("UPDATE meta SET value = ? WHERE key = 'device_event_counter'")
        .run(String(counter));
      this.insertPendingEvent(input);
      return input.event;
    });

    return transaction.immediate();
  }

  writeAudit(input: WriteLocalAuditInput): string {
    const transaction = this.database.transaction(() => {
      const previous = this.database
        .prepare<[], { entry_hash: string }>("SELECT entry_hash FROM local_audit ORDER BY id DESC LIMIT 1")
        .get();
      const previousHash = previous?.entry_hash ?? genesisAuditHash;
      const entryHash = hashAuditEntry({
        category: input.category,
        body: input.body,
        recorded_at: input.recordedAt,
        previous_hash: previousHash
      });

      this.database
        .prepare<[string, string, string, string, string]>(
          `INSERT INTO local_audit (
            category,
            body,
            recorded_at,
            previous_hash,
            entry_hash
          ) VALUES (?, ?, ?, ?, ?)`
        )
        .run(input.category, canonicalBytes(input.body).toString("utf8"), input.recordedAt, previousHash, entryHash);

      return entryHash;
    });

    return transaction.immediate();
  }

  queuePendingEvent(input: QueuePendingEventInput): void {
    const transaction = this.database.transaction(() => {
      this.insertPendingEvent(input);
    });

    transaction.immediate();
  }

  readPendingEventsForPush(limit: number): ClientEventEnvelope[] {
    const rows = this.database
      .prepare<[number], { envelope: Buffer }>(
        `SELECT envelope
        FROM pending_events
        WHERE submit_state = 'queued'
        ORDER BY device_event_counter ASC
        LIMIT ?`
      )
      .all(limit);

    return rows.map((row) => parseStoredClientEvent(row.envelope));
  }

  readVerifiedHead(): { readonly sequence: bigint; readonly ledgerHash: string } {
    const row = this.database
      .prepare<[], { server_sequence: number; resulting_ledger_hash: string }>(
        `SELECT server_sequence, resulting_ledger_hash
        FROM ledger_replica
        ORDER BY server_sequence DESC
        LIMIT 1`
      )
      .get();

    return row === undefined
      ? { sequence: 0n, ledgerHash: genesisLedgerHash }
      : { sequence: BigInt(row.server_sequence), ledgerHash: row.resulting_ledger_hash };
  }

  readLedgerHashAt(sequence: bigint): string | null {
    if (sequence === 0n) {
      return genesisLedgerHash;
    }

    const row = this.database
      .prepare<[number], { resulting_ledger_hash: string }>(
        "SELECT resulting_ledger_hash FROM ledger_replica WHERE server_sequence = ?"
      )
      .get(toSafeInteger(sequence));
    return row?.resulting_ledger_hash ?? null;
  }

  appendVerifiedLedgerEvent(event: LedgerEvent, verifiedAt: string): void {
    if (event.server_sequence === null || event.resulting_ledger_hash === null || event.server_signature === null) {
      throw new Error("Cannot append unsequenced ledger event");
    }
    const serverSequence = event.server_sequence;
    const resultingLedgerHash = event.resulting_ledger_hash;
    const serverSignature = event.server_signature;

    const transaction = this.database.transaction(() => {
      this.database
        .prepare<[number, string, string, string | null, string, string]>(
          `INSERT INTO ledger_replica (
            server_sequence,
            event,
            resulting_ledger_hash,
            previous_ledger_hash,
            server_signature,
            verified_at
          ) VALUES (?, ?, ?, ?, ?, ?)`
        )
        .run(
          toSafeInteger(serverSequence),
          canonicalBytes(event as unknown as CanonicalJson).toString("utf8"),
          resultingLedgerHash,
          event.previous_ledger_hash,
          serverSignature,
          verifiedAt
        );

      this.database
        .prepare<
          [number, number, number, string | null]
        >(
          `UPDATE sync_state
          SET last_verified_sequence = ?,
              revocation_list_version = MAX(revocation_list_version, ?),
              active_policy_version = MAX(active_policy_version, ?),
              last_sync_at = ?
          WHERE id = 1`
        )
        .run(toSafeInteger(serverSequence), 0, 0, verifiedAt);
    });

    transaction.immediate();
  }

  storeVerifiedCheckpoint(checkpoint: Checkpoint, verifiedAt: string): void {
    const transaction = this.database.transaction(() => {
      this.database
        .prepare<[number, string, string, string]>(
          `INSERT INTO checkpoints (
            sequence,
            ledger_hash,
            signature,
            verified_at
          ) VALUES (?, ?, ?, ?)
          ON CONFLICT(sequence) DO NOTHING`
        )
        .run(toSafeInteger(checkpoint.sequence), checkpoint.ledger_hash, checkpoint.signature, verifiedAt);
    });

    transaction.immediate();
  }

  applyVerifiedServerAck(ack: ServerAck): void {
    const state = stateForAck(ack.status);
    const transaction = this.database.transaction(() => {
      this.database
        .prepare<[string, string]>(
          `UPDATE pending_events
          SET submit_state = ?
          WHERE event_id = ?`
        )
        .run(state, ack.event_id);
    });

    transaction.immediate();
  }

  private nextDeviceEventCounter(): number {
    const row = this.database
      .prepare<[], { value: string }>("SELECT value FROM meta WHERE key = 'device_event_counter'")
      .get();
    const current = row ? Number.parseInt(row.value, 10) : 0;
    const next = current + 1;

    if (!Number.isSafeInteger(next) || next <= 0) {
      throw new Error("Device event counter exhausted");
    }

    return next;
  }

  private insertPendingEvent(input: QueuePendingEventInput): void {
    this.database
      .prepare<[string, number, Buffer, string]>(
        `INSERT INTO pending_events (
          event_id,
          device_event_counter,
          envelope,
          created_at,
          submit_state
        ) VALUES (?, ?, ?, ?, 'queued')`
      )
      .run(input.event.event_id, Number(input.event.device_event_counter), input.envelopeBytes, input.createdAt);
  }
}

function configureConnection(database: LocalDatabase): void {
  database.pragma("journal_mode = WAL");
  database.pragma("synchronous = FULL");
  database.pragma("foreign_keys = ON");
  database.pragma("busy_timeout = 5000");
  database.pragma("trusted_schema = OFF");
}

function initializeSchema(database: LocalDatabase): void {
  database.exec(`
    BEGIN IMMEDIATE;

    CREATE TABLE IF NOT EXISTS meta (
      key TEXT PRIMARY KEY,
      value TEXT NOT NULL
    ) STRICT;

    INSERT INTO meta (key, value) VALUES
      ('schema_version', '${schemaVersion}'),
      ('device_event_counter', '0'),
      ('key_version', '1'),
      ('last_verified_sequence', '0'),
      ('revocation_list_version', '0'),
      ('active_policy_version', '0')
    ON CONFLICT(key) DO NOTHING;

    CREATE TABLE IF NOT EXISTS snapshots (
      up_to_sequence INTEGER PRIMARY KEY,
      content_hash TEXT NOT NULL,
      verified_at TEXT NOT NULL,
      body BLOB NOT NULL
    ) STRICT;

    CREATE TABLE IF NOT EXISTS ledger_replica (
      server_sequence INTEGER PRIMARY KEY,
      event TEXT NOT NULL CHECK (json_valid(event)),
      resulting_ledger_hash TEXT NOT NULL,
      previous_ledger_hash TEXT,
      server_signature TEXT NOT NULL,
      verified_at TEXT NOT NULL
    ) STRICT;

    CREATE TABLE IF NOT EXISTS pending_events (
      event_id TEXT PRIMARY KEY,
      device_event_counter INTEGER NOT NULL UNIQUE,
      envelope BLOB NOT NULL,
      created_at TEXT NOT NULL,
      submit_state TEXT NOT NULL CHECK (submit_state IN ('queued','submitted','acked','rejected','conflicted'))
    ) STRICT;

    CREATE TABLE IF NOT EXISTS checkpoints (
      sequence INTEGER PRIMARY KEY,
      ledger_hash TEXT NOT NULL,
      signature TEXT NOT NULL,
      verified_at TEXT NOT NULL
    ) STRICT;

    CREATE TABLE IF NOT EXISTS sync_state (
      id INTEGER PRIMARY KEY CHECK (id = 1),
      last_verified_sequence INTEGER NOT NULL,
      revocation_list_version INTEGER NOT NULL,
      active_policy_version INTEGER NOT NULL,
      last_sync_at TEXT
    ) STRICT;

    INSERT INTO sync_state (
      id,
      last_verified_sequence,
      revocation_list_version,
      active_policy_version,
      last_sync_at
    ) VALUES (1, 0, 0, 0, NULL)
    ON CONFLICT(id) DO NOTHING;

    CREATE TABLE IF NOT EXISTS object_cache (
      object_type TEXT NOT NULL,
      object_id TEXT NOT NULL,
      current_state TEXT NOT NULL CHECK (json_valid(current_state)),
      conflicted INTEGER NOT NULL DEFAULT 0 CHECK (conflicted IN (0,1)),
      PRIMARY KEY (object_type, object_id)
    ) STRICT, WITHOUT ROWID;

    CREATE TABLE IF NOT EXISTS local_audit (
      id INTEGER PRIMARY KEY,
      category TEXT NOT NULL CHECK (category IN (
        'auth',
        'sync',
        'export',
        'ipc_anomaly',
        'chain_verification',
        'security_acknowledgement'
      )),
      body TEXT NOT NULL CHECK (json_valid(body)),
      recorded_at TEXT NOT NULL,
      previous_hash TEXT NOT NULL,
      entry_hash TEXT NOT NULL UNIQUE
    ) STRICT;

    CREATE TABLE IF NOT EXISTS ai_insights_cache (
      id TEXT PRIMARY KEY,
      kind TEXT NOT NULL,
      body TEXT NOT NULL CHECK (json_valid(body)),
      model_version TEXT NOT NULL,
      created_at TEXT NOT NULL
    ) STRICT;

    CREATE TRIGGER IF NOT EXISTS snapshots_no_update
      BEFORE UPDATE ON snapshots
      BEGIN
        SELECT RAISE(ABORT, 'snapshots is append-only');
      END;

    CREATE TRIGGER IF NOT EXISTS snapshots_no_delete
      BEFORE DELETE ON snapshots
      BEGIN
        SELECT RAISE(ABORT, 'snapshots is append-only');
      END;

    CREATE TRIGGER IF NOT EXISTS ledger_replica_no_update
      BEFORE UPDATE ON ledger_replica
      BEGIN
        SELECT RAISE(ABORT, 'ledger_replica is append-only');
      END;

    CREATE TRIGGER IF NOT EXISTS ledger_replica_no_delete
      BEFORE DELETE ON ledger_replica
      BEGIN
        SELECT RAISE(ABORT, 'ledger_replica is append-only');
      END;

    CREATE TRIGGER IF NOT EXISTS checkpoints_no_update
      BEFORE UPDATE ON checkpoints
      BEGIN
        SELECT RAISE(ABORT, 'checkpoints is append-only');
      END;

    CREATE TRIGGER IF NOT EXISTS checkpoints_no_delete
      BEFORE DELETE ON checkpoints
      BEGIN
        SELECT RAISE(ABORT, 'checkpoints is append-only');
      END;

    CREATE TRIGGER IF NOT EXISTS local_audit_no_update
      BEFORE UPDATE ON local_audit
      BEGIN
        SELECT RAISE(ABORT, 'local_audit is append-only');
      END;

    CREATE TRIGGER IF NOT EXISTS local_audit_no_delete
      BEFORE DELETE ON local_audit
      BEGIN
        SELECT RAISE(ABORT, 'local_audit is append-only');
      END;

    COMMIT;
  `);
}

function hashAuditEntry(entry: CanonicalJson): string {
  return `sha256:${createHash("sha256").update(canonicalBytes(entry)).digest("hex")}`;
}

function toSafeInteger(value: bigint): number {
  const asNumber = Number(value);

  if (!Number.isSafeInteger(asNumber)) {
    throw new Error("Integer exceeds SQLite safe range");
  }

  return asNumber;
}

function stateForAck(status: ServerAck["status"]): "acked" | "rejected" | "conflicted" {
  if (status === "accepted" || status === "pending") {
    return "acked";
  }

  if (status === "conflicted") {
    return "conflicted";
  }

  return "rejected";
}

function parseStoredClientEvent(envelope: Buffer): ClientEventEnvelope {
  const parsed = JSON.parse(envelope.toString("utf8")) as Record<string, unknown>;
  return {
    ...parsed,
    base_server_sequence: BigInt(String(parsed.base_server_sequence)),
    device_event_counter: BigInt(String(parsed.device_event_counter)),
    policy_metadata: parseStoredPolicyMetadata(parsed.policy_metadata)
  } as ClientEventEnvelope;
}

function parseStoredPolicyMetadata(value: unknown): ClientEventEnvelope["policy_metadata"] {
  const metadata = typeof value === "object" && value !== null && !Array.isArray(value) ? value as Record<string, unknown> : {};
  return {
    ...metadata,
    amount_minor_units:
      metadata.amount_minor_units === undefined ? undefined : BigInt(String(metadata.amount_minor_units)),
    local_rate: metadata.local_rate === undefined ? undefined : BigInt(String(metadata.local_rate))
  } as ClientEventEnvelope["policy_metadata"];
}

function assertDeviceCredentials(credentials: DeviceCredentials): void {
  if (
    credentials.executiveId.length === 0 ||
    credentials.executiveRole.length === 0 ||
    credentials.deviceId.length === 0 ||
    credentials.serverBaseUrl.length === 0 ||
    credentials.serverCaPem.length === 0 ||
    credentials.clientCertificatePem.length === 0 ||
    credentials.clientPrivateKeyPem.length === 0 ||
    credentials.certificateFingerprint.length === 0 ||
    Number.isNaN(Date.parse(credentials.certificateExpiresAt)) ||
    !Number.isInteger(credentials.deviceRiskScore) ||
    credentials.deviceRiskScore < 0 ||
    credentials.deviceRiskScore > 100
  ) {
    throw new Error("Invalid device credentials");
  }

  if (new URL(credentials.serverBaseUrl).protocol !== "https:") {
    throw new Error("Device credentials require HTTPS sync URL");
  }
}
