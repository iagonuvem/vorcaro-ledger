import { createCipheriv, randomBytes } from "node:crypto";
import type { DatabaseSync } from "node:sqlite";

import {
  canonicalBytes,
  ledgerSnapshotSchema,
  sha256Digest,
  sha256Hex,
  signBytes,
  type CanonicalJson,
  type LedgerSnapshot
} from "@vorcaro/protocol";

import { GENESIS_LEDGER_HASH } from "../ledger/appender.js";

export type SnapshotObjectStore = {
  putObject(input: {
    readonly key: string;
    readonly body: Buffer;
    readonly contentHash: string;
  }): string;
};

export class MemorySnapshotObjectStore implements SnapshotObjectStore {
  readonly objects = new Map<string, Buffer>();

  putObject(input: { readonly key: string; readonly body: Buffer; readonly contentHash: string }): string {
    this.objects.set(input.key, Buffer.from(input.body));
    return `memory://snapshots/${input.key}`;
  }
}

export type SnapshotWorkerOptions = {
  readonly ledgerDatabase: DatabaseSync;
  readonly projectionsDatabase: DatabaseSync;
  readonly objectStore: SnapshotObjectStore;
  readonly serverSigningSecretKey: string;
  readonly snapshotEncryptionKey: Buffer;
  readonly now?: () => string;
};

type LedgerHeadRow = {
  readonly server_sequence: number;
  readonly resulting_ledger_hash: string;
};

type ProjectionMetaRow = {
  readonly value: string;
};

type AccountRow = {
  readonly account_id: string;
  readonly entity_id: string;
  readonly currency: string;
  readonly balance_minor_units: number;
  readonly as_of_sequence: number;
  readonly status: string;
  readonly conflicted: number;
};

type CashRow = {
  readonly entity_id: string;
  readonly currency: string;
  readonly total_minor_units: number;
  readonly pending_delta_minor_units: number;
  readonly as_of_sequence: number;
};

type ConflictRow = {
  readonly conflict_id: string;
  readonly object_type: string;
  readonly object_id: string;
  readonly event_ids: string;
  readonly detected_at_sequence: number;
};

export class SnapshotWorker {
  private readonly ledgerDatabase: DatabaseSync;
  private readonly projectionsDatabase: DatabaseSync;
  private readonly objectStore: SnapshotObjectStore;
  private readonly serverSigningSecretKey: string;
  private readonly snapshotEncryptionKey: Buffer;
  private readonly now: () => string;

  constructor(options: SnapshotWorkerOptions) {
    if (options.snapshotEncryptionKey.length !== 32) {
      throw new TypeError("Snapshot encryption key must be 32 bytes");
    }

    this.ledgerDatabase = options.ledgerDatabase;
    this.projectionsDatabase = options.projectionsDatabase;
    this.objectStore = options.objectStore;
    this.serverSigningSecretKey = options.serverSigningSecretKey;
    this.snapshotEncryptionKey = Buffer.from(options.snapshotEncryptionKey);
    this.now = options.now ?? (() => new Date().toISOString());
  }

  createSnapshot(): LedgerSnapshot {
    const body = this.buildSnapshotBody();
    const encrypted = encryptSnapshotBody(
      canonicalBytes(body),
      this.snapshotEncryptionKey
    );
    const contentHash = sha256Digest(encrypted);
    const id = `snap_${body.up_to_sequence.toString().padStart(20, "0")}_${sha256Hex(encrypted).slice(0, 12)}`;
    const storageRef = this.objectStore.putObject({
      key: `${id}.bin`,
      body: encrypted,
      contentHash
    });
    const createdAt = this.now();
    const unsigned = {
      id,
      up_to_sequence: BigInt(body.up_to_sequence),
      content_hash: contentHash,
      storage_ref: storageRef,
      created_at: createdAt
    };
    const snapshot = ledgerSnapshotSchema.parse({
      ...unsigned,
      signature: signBytes(canonicalBytes(unsigned), this.serverSigningSecretKey)
    });

    this.ledgerDatabase
      .prepare(
        `INSERT INTO snapshots (
          id, up_to_sequence, content_hash, storage_ref, signature, created_at
        ) VALUES (?, ?, ?, ?, ?, ?)`
      )
      .run(
        snapshot.id,
        toSqlInteger(snapshot.up_to_sequence),
        snapshot.content_hash,
        snapshot.storage_ref,
        snapshot.signature,
        snapshot.created_at
      );

    return snapshot;
  }

  private buildSnapshotBody(): {
    readonly kind: "vorcaro-ledger-snapshot";
    readonly version: 1;
    readonly up_to_sequence: number;
    readonly ledger_hash: string;
    readonly projection_watermark: number;
    readonly accounts: readonly CanonicalJson[];
    readonly cash_position: readonly CanonicalJson[];
    readonly open_conflicts: readonly CanonicalJson[];
  } {
    const head = this.ledgerDatabase
      .prepare(
        `SELECT server_sequence, resulting_ledger_hash
        FROM ledger_events
        WHERE server_sequence IS NOT NULL
        ORDER BY server_sequence DESC
        LIMIT 1`
      )
      .get() as LedgerHeadRow | undefined;
    const watermark = this.projectionsDatabase
      .prepare("SELECT value FROM proj_meta WHERE key = 'last_applied_sequence'")
      .get() as ProjectionMetaRow | undefined;

    return {
      kind: "vorcaro-ledger-snapshot",
      version: 1,
      up_to_sequence: head?.server_sequence ?? 0,
      ledger_hash: head?.resulting_ledger_hash ?? GENESIS_LEDGER_HASH,
      projection_watermark: watermark === undefined ? 0 : Number(watermark.value),
      accounts: this.readAccounts(),
      cash_position: this.readCashPosition(),
      open_conflicts: this.readOpenConflicts()
    };
  }

  private readAccounts(): readonly CanonicalJson[] {
    return (
      this.projectionsDatabase
        .prepare(
          `SELECT
            account_id, entity_id, currency, balance_minor_units,
            as_of_sequence, status, conflicted
          FROM proj_accounts
          ORDER BY account_id ASC`
        )
        .all() as AccountRow[]
    ).map((row) => ({
      account_id: row.account_id,
      entity_id: row.entity_id,
      currency: row.currency,
      balance_minor_units: row.balance_minor_units,
      as_of_sequence: row.as_of_sequence,
      status: row.status,
      conflicted: row.conflicted === 1
    }));
  }

  private readCashPosition(): readonly CanonicalJson[] {
    return (
      this.projectionsDatabase
        .prepare(
          `SELECT
            entity_id, currency, total_minor_units,
            pending_delta_minor_units, as_of_sequence
          FROM proj_cash_position
          ORDER BY entity_id ASC, currency ASC`
        )
        .all() as CashRow[]
    ).map((row) => ({
      entity_id: row.entity_id,
      currency: row.currency,
      total_minor_units: row.total_minor_units,
      pending_delta_minor_units: row.pending_delta_minor_units,
      as_of_sequence: row.as_of_sequence
    }));
  }

  private readOpenConflicts(): readonly CanonicalJson[] {
    return (
      this.projectionsDatabase
        .prepare(
          `SELECT
            conflict_id, object_type, object_id,
            event_ids, detected_at_sequence
          FROM proj_conflicts_open
          ORDER BY detected_at_sequence ASC`
        )
        .all() as ConflictRow[]
    ).map((row) => ({
      conflict_id: row.conflict_id,
      object_type: row.object_type,
      object_id: row.object_id,
      event_ids: JSON.parse(row.event_ids) as string[],
      detected_at_sequence: row.detected_at_sequence
    }));
  }
}

export function createSnapshotWorker(options: SnapshotWorkerOptions): SnapshotWorker {
  return new SnapshotWorker(options);
}

function encryptSnapshotBody(plaintext: Buffer, key: Buffer): Buffer {
  const iv = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", key, iv);
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const authTag = cipher.getAuthTag();
  const envelope = {
    algorithm: "AES-256-GCM",
    iv: iv.toString("base64"),
    auth_tag: authTag.toString("base64"),
    ciphertext: ciphertext.toString("base64")
  };

  return canonicalBytes(envelope);
}

function toSqlInteger(value: bigint): number {
  const asNumber = Number(value);

  if (!Number.isSafeInteger(asNumber)) {
    throw new RangeError("SQLite integer value exceeds JavaScript safe integer range");
  }

  return asNumber;
}
