import type { DatabaseSync } from "node:sqlite";

import {
  clientEventEnvelopeSchema,
  computeLedgerHash,
  constantTimeEqual,
  payloadHash,
  sha256Hex,
  signServerAck,
  verifyClientEventSignature,
  type ClientEventEnvelope,
  type ErrorCode,
  type EventStatus,
  type ServerAck,
} from "@vorcaro/protocol";

export const GENESIS_LEDGER_HASH = "sha256:0000000000000000000000000000000000000000000000000000000000000000";

export type AppendEventRequest = {
  readonly event: ClientEventEnvelope;
  readonly certificateFingerprint: string;
};

export type LedgerAppenderOptions = {
  readonly database: DatabaseSync;
  readonly serverSigningSecretKey: string;
  readonly now?: () => string;
};

type DeviceExecutiveRow = {
  readonly device_status: string;
  readonly certificate_fingerprint: string;
  readonly executive_id: string;
  readonly executive_status: string;
  readonly max_event_counter: number;
};

type ExistingEventRow = {
  readonly id: string;
  readonly status: EventStatus;
  readonly server_sequence: number | null;
  readonly resulting_ledger_hash: string | null;
  readonly server_timestamp: string;
  readonly error_code: ErrorCode | null;
  readonly server_signature: string;
};

type ExecutiveKeyRow = {
  readonly signing_public_key: string;
};

type ObjectHeadRow = {
  readonly head_sequence: number;
  readonly conflicted: number;
};

type ChainHeadRow = {
  readonly server_sequence: number;
  readonly resulting_ledger_hash: string;
};

type HeadEventRow = {
  readonly id: string;
};

type ConflictRow = {
  readonly id: string;
  readonly event_ids: string;
  readonly status: "open" | "resolved";
};

export class LedgerAppender {
  private readonly database: DatabaseSync;
  private readonly serverSigningSecretKey: string;
  private readonly now: () => string;
  private tail: Promise<void> = Promise.resolve();

  constructor(options: LedgerAppenderOptions) {
    this.database = options.database;
    this.serverSigningSecretKey = options.serverSigningSecretKey;
    this.now = options.now ?? (() => new Date().toISOString());
  }

  append(request: AppendEventRequest): Promise<ServerAck> {
    const work = this.tail.then(() => this.appendNow(request));
    this.tail = work.then(
      () => undefined,
      () => undefined
    );
    return work;
  }

  async appendBatch(requests: readonly AppendEventRequest[]): Promise<ServerAck[]> {
    const ordered = [...requests].sort((left, right) => {
      const deviceOrder = left.event.device_id.localeCompare(right.event.device_id);
      if (deviceOrder !== 0) {
        return deviceOrder;
      }

      return compareBigInt(left.event.device_event_counter, right.event.device_event_counter);
    });
    const acknowledgements: ServerAck[] = [];

    for (const request of ordered) {
      acknowledgements.push(await this.append(request));
    }

    return acknowledgements;
  }

  private appendNow(request: AppendEventRequest): ServerAck {
    const event = clientEventEnvelopeSchema.parse(request.event);
    const existing = this.findExistingEvent(event.event_id);

    if (existing !== undefined) {
      return rowToAck(existing);
    }

    const device = this.findDeviceExecutive(event.device_id);

    if (device === undefined) {
      return this.signNonAppendedAck(event.event_id, "CERT_UNKNOWN");
    }

    if (
      device.certificate_fingerprint !== request.certificateFingerprint ||
      device.device_status !== "enrolled"
    ) {
      return this.appendRejectedEvent(event, "CERT_REVOKED");
    }

    if (device.executive_id !== event.actor_id || device.executive_status !== "active") {
      return this.appendRejectedEvent(event, "EXECUTIVE_INACTIVE");
    }

    if (event.device_event_counter <= BigInt(device.max_event_counter)) {
      return this.signNonAppendedAck(event.event_id, "REPLAY_COUNTER");
    }

    const signingKey = this.findExecutiveKey(event.actor_id, event.base_server_sequence);

    if (
      signingKey === undefined ||
      !verifyClientEventSignature(event, signingKey.signing_public_key)
    ) {
      return this.appendRejectedEvent(event, "BAD_SIGNATURE");
    }

    if (!constantTimeEqual(payloadHash(event.encrypted_payload), event.payload_hash)) {
      return this.appendRejectedEvent(event, "BAD_PAYLOAD_HASH");
    }

    const objectHead = this.findObjectHead(event.object_type, event.object_id);

    if (event.event_type === "CONFLICT_RESOLVED") {
      if (objectHead === undefined || objectHead.conflicted !== 1 || this.findOpenConflict(event.object_type, event.object_id) === undefined) {
        return this.appendRejectedEvent(event, "CONFLICT");
      }

      return this.appendValidatedEvent(event, "accepted", null);
    }

    if (objectHead?.conflicted === 1) {
      return this.appendRejectedEvent(event, "POLICY_DENIED");
    }

    const isConflict =
      objectHead !== undefined && event.base_server_sequence < BigInt(objectHead.head_sequence);

    return this.appendValidatedEvent(event, isConflict ? "conflicted" : "accepted", isConflict ? "CONFLICT" : null);
  }

  private appendRejectedEvent(event: ClientEventEnvelope, errorCode: ErrorCode): ServerAck {
    return this.appendValidatedEvent(event, "rejected", errorCode);
  }

  private appendValidatedEvent(event: ClientEventEnvelope, status: EventStatus, errorCode: ErrorCode | null): ServerAck {
    this.database.exec("BEGIN IMMEDIATE");

    try {
      const serverSequence = this.nextServerSequence();
      const previousLedgerHash = this.previousLedgerHash();
      const resultingLedgerHash = computeLedgerHash(previousLedgerHash, BigInt(serverSequence), event);
      const serverTimestamp = this.now();
      const ack = signServerAck(
        {
          event_id: event.event_id,
          status,
          server_sequence: BigInt(serverSequence),
          resulting_ledger_hash: resultingLedgerHash,
          server_timestamp: serverTimestamp,
          error_code: errorCode
        },
        this.serverSigningSecretKey
      );

      this.insertLedgerEvent({
        event,
        serverSequence,
        previousLedgerHash,
        resultingLedgerHash,
        serverSignature: ack.server_signature,
        status,
        errorCode,
        serverTimestamp
      });
      this.updateDeviceWatermark(event.device_id, event.device_event_counter, serverTimestamp);
      this.updateConflictState(event, serverSequence, status, serverTimestamp);
      this.updateObjectHead(event, serverSequence, status);

      this.database.exec("COMMIT");
      return ack;
    } catch (error) {
      this.database.exec("ROLLBACK");
      throw error;
    }
  }

  private signNonAppendedAck(eventId: string, errorCode: ErrorCode): ServerAck {
    return signServerAck(
      {
        event_id: eventId,
        status: "rejected",
        server_sequence: null,
        resulting_ledger_hash: null,
        server_timestamp: this.now(),
        error_code: errorCode
      },
      this.serverSigningSecretKey
    );
  }

  private findExistingEvent(eventId: string): ExistingEventRow | undefined {
    return this.database
      .prepare(
        `SELECT
          id, status, server_sequence, resulting_ledger_hash,
          server_timestamp, error_code, server_signature
        FROM ledger_events
        WHERE id = ?`
      )
      .get(eventId) as ExistingEventRow | undefined;
  }

  private findDeviceExecutive(deviceId: string): DeviceExecutiveRow | undefined {
    return this.database
      .prepare(
        `SELECT
          devices.status AS device_status,
          devices.certificate_fingerprint,
          devices.executive_id,
          devices.max_event_counter,
          executives.status AS executive_status
        FROM devices
        JOIN executives ON executives.id = devices.executive_id
        WHERE devices.id = ?`
      )
      .get(deviceId) as DeviceExecutiveRow | undefined;
  }

  private findExecutiveKey(executiveId: string, baseServerSequence: bigint): ExecutiveKeyRow | undefined {
    return this.database
      .prepare(
        `SELECT signing_public_key
        FROM executive_keys
        WHERE executive_id = ?
          AND valid_from_sequence <= ?
          AND (valid_until_sequence IS NULL OR valid_until_sequence >= ?)
        ORDER BY key_version DESC
        LIMIT 1`
      )
      .get(executiveId, toSqlInteger(baseServerSequence), toSqlInteger(baseServerSequence)) as
      | ExecutiveKeyRow
      | undefined;
  }

  private findObjectHead(objectType: string, objectId: string): ObjectHeadRow | undefined {
    return this.database
      .prepare("SELECT head_sequence, conflicted FROM object_heads WHERE object_type = ? AND object_id = ?")
      .get(objectType, objectId) as ObjectHeadRow | undefined;
  }

  private findOpenConflict(objectType: string, objectId: string): ConflictRow | undefined {
    return this.database
      .prepare(
        `SELECT id, event_ids, status
        FROM conflicts
        WHERE object_type = ?
          AND object_id = ?
          AND status = 'open'
        LIMIT 1`
      )
      .get(objectType, objectId) as ConflictRow | undefined;
  }

  private findHeadEventId(serverSequence: number): string | undefined {
    const row = this.database
      .prepare("SELECT id FROM ledger_events WHERE server_sequence = ?")
      .get(serverSequence) as HeadEventRow | undefined;
    return row?.id;
  }

  private nextServerSequence(): number {
    const row = this.database.prepare("SELECT COALESCE(MAX(server_sequence), 0) + 1 AS next_sequence FROM ledger_events").get() as {
      readonly next_sequence: number;
    };
    return row.next_sequence;
  }

  private previousLedgerHash(): string {
    const row = this.database
      .prepare(
        `SELECT server_sequence, resulting_ledger_hash
        FROM ledger_events
        WHERE server_sequence IS NOT NULL
        ORDER BY server_sequence DESC
        LIMIT 1`
      )
      .get() as ChainHeadRow | undefined;

    return row?.resulting_ledger_hash ?? GENESIS_LEDGER_HASH;
  }

  private insertLedgerEvent(input: {
    readonly event: ClientEventEnvelope;
    readonly serverSequence: number;
    readonly previousLedgerHash: string;
    readonly resultingLedgerHash: string;
    readonly serverSignature: string;
    readonly status: EventStatus;
    readonly errorCode: ErrorCode | null;
    readonly serverTimestamp: string;
  }): void {
    const acceptedAt = input.status === "accepted" ? input.serverTimestamp : null;

    this.database
      .prepare(
        `INSERT INTO ledger_events (
          id, server_sequence, event_type, actor_id, device_id, device_event_counter,
          base_server_sequence, object_type, object_id, policy_metadata,
          encrypted_payload, payload_hash, previous_ledger_hash, resulting_ledger_hash,
          client_signature, server_signature, status, error_code,
          client_timestamp, server_timestamp, accepted_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
      )
      .run(
        input.event.event_id,
        input.serverSequence,
        input.event.event_type,
        input.event.actor_id,
        input.event.device_id,
        toSqlInteger(input.event.device_event_counter),
        toSqlInteger(input.event.base_server_sequence),
        input.event.object_type,
        input.event.object_id,
        stringifyPolicyMetadata(input.event.policy_metadata),
        Buffer.from(input.event.encrypted_payload, "base64"),
        input.event.payload_hash,
        input.previousLedgerHash,
        input.resultingLedgerHash,
        input.event.client_signature,
        input.serverSignature,
        input.status,
        input.errorCode,
        input.event.client_timestamp,
        input.serverTimestamp,
        acceptedAt
      );
  }

  private updateDeviceWatermark(deviceId: string, deviceEventCounter: bigint, lastSeenAt: string): void {
    this.database
      .prepare(
        `UPDATE devices
        SET max_event_counter = ?, last_seen_at = ?
        WHERE id = ?`
      )
      .run(toSqlInteger(deviceEventCounter), lastSeenAt, deviceId);
  }

  private updateObjectHead(event: ClientEventEnvelope, serverSequence: number, status: EventStatus): void {
    if (status === "accepted") {
      if (event.event_type === "CONFLICT_RESOLVED") {
        this.database
          .prepare(
            `UPDATE object_heads
            SET head_sequence = ?, conflicted = 0
            WHERE object_type = ? AND object_id = ?`
          )
          .run(serverSequence, event.object_type, event.object_id);
        return;
      }

      this.database
        .prepare(
          `INSERT INTO object_heads (object_type, object_id, head_sequence, conflicted)
          VALUES (?, ?, ?, 0)
          ON CONFLICT(object_type, object_id) DO UPDATE SET
            head_sequence = excluded.head_sequence,
            conflicted = 0`
        )
        .run(event.object_type, event.object_id, serverSequence);
      return;
    }

    if (status === "conflicted") {
      this.database
        .prepare(
          `INSERT INTO object_heads (object_type, object_id, head_sequence, conflicted)
          VALUES (?, ?, 0, 1)
          ON CONFLICT(object_type, object_id) DO UPDATE SET conflicted = 1`
        )
        .run(event.object_type, event.object_id);
    }
  }

  private updateConflictState(
    event: ClientEventEnvelope,
    serverSequence: number,
    status: EventStatus,
    serverTimestamp: string
  ): void {
    if (status === "conflicted") {
      this.openConflict(event, serverSequence, serverTimestamp);
      return;
    }

    if (status === "accepted" && event.event_type === "CONFLICT_RESOLVED") {
      this.resolveConflict(event, serverTimestamp);
    }
  }

  private openConflict(event: ClientEventEnvelope, serverSequence: number, serverTimestamp: string): void {
    const objectHead = this.findObjectHead(event.object_type, event.object_id);
    const existingConflict = this.findOpenConflict(event.object_type, event.object_id);
    const eventIds = existingConflict === undefined ? [] : parseConflictEventIds(existingConflict.event_ids);
    const headEventId = objectHead === undefined ? undefined : this.findHeadEventId(objectHead.head_sequence);

    if (headEventId !== undefined && !eventIds.includes(headEventId)) {
      eventIds.push(headEventId);
    }

    if (!eventIds.includes(event.event_id)) {
      eventIds.push(event.event_id);
    }

    if (existingConflict !== undefined) {
      this.database
        .prepare("UPDATE conflicts SET event_ids = ? WHERE id = ?")
        .run(JSON.stringify(eventIds), existingConflict.id);
      return;
    }

    this.database
      .prepare(
        `INSERT INTO conflicts (
          id, object_type, object_id, event_ids, detected_at_sequence,
          status, resolution_event_id, ai_proposal_id, created_at, resolved_at
        ) VALUES (?, ?, ?, ?, ?, 'open', NULL, NULL, ?, NULL)`
      )
      .run(
        conflictId(event.object_type, event.object_id, serverSequence),
        event.object_type,
        event.object_id,
        JSON.stringify(eventIds),
        serverSequence,
        serverTimestamp
      );
  }

  private resolveConflict(event: ClientEventEnvelope, serverTimestamp: string): void {
    const existingConflict = this.findOpenConflict(event.object_type, event.object_id);

    if (existingConflict === undefined) {
      throw new Error("No open conflict exists for accepted resolution event");
    }

    this.database
      .prepare(
        `UPDATE conflicts
        SET status = 'resolved',
          resolution_event_id = ?,
          resolved_at = ?
        WHERE id = ?`
      )
      .run(event.event_id, serverTimestamp, existingConflict.id);
  }
}

export function createLedgerAppender(options: LedgerAppenderOptions): LedgerAppender {
  return new LedgerAppender(options);
}

function rowToAck(row: ExistingEventRow): ServerAck {
  return {
    event_id: row.id,
    status: row.status,
    server_sequence: row.server_sequence === null ? null : BigInt(row.server_sequence),
    resulting_ledger_hash: row.resulting_ledger_hash,
    server_timestamp: row.server_timestamp,
    error_code: row.error_code,
    server_signature: row.server_signature
  };
}

function compareBigInt(left: bigint, right: bigint): number {
  if (left < right) {
    return -1;
  }

  if (left > right) {
    return 1;
  }

  return 0;
}

function stringifyPolicyMetadata(policyMetadata: ClientEventEnvelope["policy_metadata"]): string {
  return JSON.stringify(policyMetadata, (_key, value: unknown) =>
    typeof value === "bigint" ? value.toString(10) : value
  );
}

function parseConflictEventIds(raw: string): string[] {
  const parsed = JSON.parse(raw) as unknown;
  return Array.isArray(parsed) ? parsed.filter((value): value is string => typeof value === "string") : [];
}

function conflictId(objectType: string, objectId: string, detectedAtSequence: number): string {
  return `cfl_${sha256Hex(`${objectType}:${objectId}:${detectedAtSequence}`).slice(0, 26)}`;
}

function toSqlInteger(value: bigint): number {
  const asNumber = Number(value);

  if (!Number.isSafeInteger(asNumber)) {
    throw new RangeError("SQLite integer value exceeds JavaScript safe integer range");
  }

  return asNumber;
}
