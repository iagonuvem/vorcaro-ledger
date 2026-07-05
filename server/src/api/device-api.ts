import type { DatabaseSync } from "node:sqlite";
import express, { type ErrorRequestHandler, type Request, type RequestHandler } from "express";
import { z, ZodError } from "zod";

import {
  clientEventEnvelopeSchema,
  type Checkpoint,
  type ClientEventEnvelope,
  type LedgerEvent,
  type LedgerSnapshot,
  type PolicyDocument,
  type RevocationList
} from "@vorcaro/protocol";

import type { LedgerAppender } from "../ledger/appender.js";
import { GENESIS_LEDGER_HASH } from "../ledger/appender.js";
import { ApiError } from "./errors.js";
import { PkiError, type PkiService } from "../pki/enrollment.js";
import { PolicyError } from "../policy/engine.js";
import {
  createIdentityMiddleware,
  requireIdentity,
  type CertificateFingerprintResolver,
  type IdentityRequest
} from "./identity.js";
import { sendJson } from "./json.js";
import { createTokenBucketMiddleware } from "./rate-limit.js";
import { signListResponse, signStateResponse } from "./signing.js";

export type DeviceApiOptions = {
  readonly database: DatabaseSync;
  readonly appender: LedgerAppender;
  readonly serverSigningSecretKey: string;
  readonly pkiService?: PkiService;
  readonly now?: () => string;
  readonly certificateFingerprintResolver?: CertificateFingerprintResolver;
};

const eventBatchSchema = z
  .object({
    events: z.array(clientEventEnvelopeSchema).min(1)
  })
  .strict();

const nonNegativeIntegerParam = z.coerce.bigint().nonnegative();
const beginEnrollmentBodySchema = z
  .object({
    token: z.string().min(1),
    device_id: z.string().min(1),
    public_key: z.string().min(1)
  })
  .strict();
const completeEnrollmentBodySchema = z
  .object({
    token: z.string().min(1),
    challenge_id: z.string().min(1),
    proof_signature: z.string().min(1),
    hardware_backed: z.boolean(),
    enrollment_event: z.unknown()
  })
  .strict();

export function createDeviceApiApp(options: DeviceApiOptions): express.Express {
  const now = options.now ?? (() => new Date().toISOString());
  const app = express();
  app.disable("x-powered-by");

  app.use(requireJsonContentType);
  app.use((request, response, next) => {
    const parser = express.json({
      limit: request.path === "/v1/events" ? "10mb" : "1mb",
      strict: true
    });
    parser(request, response, next);
  });
  app.use(
    createIdentityMiddleware({
      database: options.database,
      now,
      ...(options.certificateFingerprintResolver === undefined
        ? {}
        : { certificateFingerprintResolver: options.certificateFingerprintResolver }),
      optionalPaths: ["/v1/enroll/begin", "/v1/enroll/complete"]
    })
  );
  app.use(
    createTokenBucketMiddleware({
      capacity: 120,
      refillPerSecond: 10,
      key: (request) => (request as IdentityRequest).identity?.device.id ?? request.ip ?? "unknown"
    })
  );

  app.post("/v1/enroll/begin", (request, response) => {
    if (options.pkiService === undefined) {
      sendJson(response, 501, { error_code: "POLICY_DENIED" });
      return;
    }

    const body = beginEnrollmentBodySchema.parse(request.body);
    sendJson(
      response,
      200,
      signListResponse(
        options.pkiService.beginEnrollment({
          token: body.token,
          deviceId: body.device_id,
          publicKey: body.public_key
        }),
        options.serverSigningSecretKey
      )
    );
  });

  app.post("/v1/enroll/complete", (request, response) => {
    if (options.pkiService === undefined) {
      sendJson(response, 501, { error_code: "POLICY_DENIED" });
      return;
    }

    const body = completeEnrollmentBodySchema.parse(request.body);
    const result = options.pkiService.completeEnrollment({
      token: body.token,
      challengeId: body.challenge_id,
      proofSignature: body.proof_signature,
      hardwareBacked: body.hardware_backed,
      enrollmentEvent: parseEnrollmentEvent(body.enrollment_event)
    });

    sendJson(
      response,
      200,
      signListResponse(
        {
          certificate: result.certificate,
          acknowledgement: result.acknowledgement
        },
        options.serverSigningSecretKey
      )
    );
  });

  app.get("/v1/state", (request, response) => {
    requireIdentity(request);
    sendJson(
      response,
      200,
      signStateResponse(
        {
          ...readState(options.database),
          server_timestamp: now()
        },
        options.serverSigningSecretKey
      )
    );
  });

  app.get("/v1/checkpoints", (request, response) => {
    requireIdentity(request);
    const after = parseQueryBigInt(request, "after", 0n);
    const checkpoints = readCheckpoints(options.database, after);
    sendJson(
      response,
      200,
      signListResponse(
        {
          after,
          checkpoints,
          server_timestamp: now()
        },
        options.serverSigningSecretKey
      )
    );
  });

  app.get("/v1/events", (request, response) => {
    requireIdentity(request);
    const afterSeq = parseQueryBigInt(request, "after_seq", 0n);
    const events = readEvents(options.database, afterSeq);
    sendJson(
      response,
      200,
      signListResponse(
        {
          after_seq: afterSeq,
          events,
          server_timestamp: now()
        },
        options.serverSigningSecretKey
      )
    );
  });

  app.get("/v1/snapshots/latest", (request, response) => {
    requireIdentity(request);
    sendJson(
      response,
      200,
      signListResponse(
        {
          snapshot: readLatestSnapshot(options.database),
          server_timestamp: now()
        },
        options.serverSigningSecretKey
      )
    );
  });

  app.post("/v1/events", async (request, response) => {
    const identity = requireIdentity(request);
    const body = parseEventSubmission(request.body);
    const acknowledgements =
      body.length === 1
        ? [await options.appender.append({ event: body[0] as ClientEventEnvelope, certificateFingerprint: identity.certificateFingerprint })]
        : await options.appender.appendBatch(
            body.map((event) => ({
              event,
              certificateFingerprint: identity.certificateFingerprint
            }))
          );

    sendJson(response, 200, body.length === 1 ? acknowledgements[0] : { acknowledgements });
  });

  app.get("/v1/revocations", (request, response) => {
    requireIdentity(request);
    sendJson(
      response,
      200,
      signListResponse(
        {
          revocation_list: readLatestRevocationList(options.database),
          server_timestamp: now()
        },
        options.serverSigningSecretKey
      )
    );
  });

  app.get("/v1/policies/active", (request, response) => {
    requireIdentity(request);
    sendJson(
      response,
      200,
      signListResponse(
        {
          policy: readActivePolicy(options.database),
          server_timestamp: now()
        },
        options.serverSigningSecretKey
      )
    );
  });

  app.post("/v1/recovery/ceremonies", (_request, response) => {
    sendJson(response, 501, { error_code: "POLICY_DENIED" });
  });

  app.post("/v1/recovery/ceremonies/:id/approve", (_request, response) => {
    sendJson(response, 501, { error_code: "POLICY_DENIED" });
  });

  app.post("/v1/recovery/ceremonies/:id/execute", (_request, response) => {
    sendJson(response, 501, { error_code: "POLICY_DENIED" });
  });

  app.use(createErrorHandler());
  return app;
}

export function createErrorHandler(): ErrorRequestHandler {
  return (error: unknown, _request: Request, response, _next): void => {
    if (response.headersSent) {
      return;
    }

    if (error instanceof ApiError) {
      sendJson(response, error.statusCode, { error_code: error.errorCode });
      return;
    }

    if (error instanceof PkiError) {
      sendJson(response, ApiError.errorStatus(error.errorCode), { error_code: error.errorCode });
      return;
    }

    if (error instanceof PolicyError) {
      sendJson(response, ApiError.errorStatus(error.errorCode), { error_code: error.errorCode });
      return;
    }

    if (error instanceof ZodError || isJsonParseError(error)) {
      sendJson(response, ApiError.errorStatus("SCHEMA_INVALID"), { error_code: "SCHEMA_INVALID" });
      return;
    }

    sendJson(response, 500, { error_code: "POLICY_DENIED" });
  };
}

function parseEnrollmentEvent(value: unknown): ClientEventEnvelope {
  const events = parseEventSubmission(value);
  const event = events[0];
  if (events.length !== 1 || event === undefined) {
    throw new ApiError(400, "SCHEMA_INVALID");
  }

  return event;
}

function requireJsonContentType(request: Request, _response: Parameters<RequestHandler>[1], next: Parameters<RequestHandler>[2]): void {
  if (
    request.method !== "GET" &&
    request.method !== "HEAD" &&
    request.method !== "DELETE" &&
    !request.is("application/json")
  ) {
    throw new ApiError(400, "SCHEMA_INVALID");
  }

  next();
}

export function parseEventSubmission(body: unknown): ClientEventEnvelope[] {
  const normalized = normalizeEventSubmission(body);
  const single = clientEventEnvelopeSchema.safeParse(normalized);
  if (single.success) {
    return [single.data];
  }

  return eventBatchSchema.parse(normalized).events;
}

function normalizeEventSubmission(body: unknown): unknown {
  if (Array.isArray(body)) {
    return body.map((event) => normalizeEvent(event));
  }

  if (isRecord(body) && Array.isArray(body.events)) {
    return {
      ...body,
      events: body.events.map((event) => normalizeEvent(event))
    };
  }

  return normalizeEvent(body);
}

function normalizeEvent(event: unknown): unknown {
  if (!isRecord(event)) {
    return event;
  }

  return {
    ...event,
    base_server_sequence: normalizeBigIntField(event.base_server_sequence),
    device_event_counter: normalizeBigIntField(event.device_event_counter),
    policy_metadata: isRecord(event.policy_metadata)
      ? {
          ...event.policy_metadata,
          amount_minor_units: normalizeOptionalBigIntField(event.policy_metadata.amount_minor_units),
          local_rate: normalizeOptionalBigIntField(event.policy_metadata.local_rate)
        }
      : event.policy_metadata
  };
}

function normalizeBigIntField(value: unknown): unknown {
  if (typeof value === "string" && /^\d+$/.test(value)) {
    return BigInt(value);
  }

  return value;
}

function normalizeOptionalBigIntField(value: unknown): unknown {
  if (value === undefined) {
    return undefined;
  }

  return normalizeBigIntField(value);
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function parseQueryBigInt(request: Request, name: string, defaultValue: bigint): bigint {
  const raw = request.query[name];
  if (raw === undefined) {
    return defaultValue;
  }

  if (Array.isArray(raw) || typeof raw === "object") {
    throw new ApiError(400, "SCHEMA_INVALID");
  }

  return nonNegativeIntegerParam.parse(raw);
}

type StateRow = {
  readonly server_sequence: number;
  readonly resulting_ledger_hash: string;
};

type CheckpointRow = {
  readonly sequence: number;
  readonly ledger_hash: string;
  readonly issued_at: string;
  readonly key_version: number;
  readonly signature: string;
};

type VersionRow = {
  readonly version: number | null;
};

function readState(database: DatabaseSync): {
  latest_sequence: bigint;
  latest_ledger_hash: string;
  latest_checkpoint: Checkpoint | null;
  revocation_list_version: number;
  active_policy_version: number;
} {
  const head = database
    .prepare(
      `SELECT server_sequence, resulting_ledger_hash
      FROM ledger_events
      WHERE server_sequence IS NOT NULL
      ORDER BY server_sequence DESC
      LIMIT 1`
    )
    .get() as StateRow | undefined;
  const revocation = database
    .prepare("SELECT MAX(version) AS version FROM revocation_list_versions")
    .get() as VersionRow;
  const policy = database.prepare("SELECT MAX(version) AS version FROM policies").get() as VersionRow;

  return {
    latest_sequence: BigInt(head?.server_sequence ?? 0),
    latest_ledger_hash: head?.resulting_ledger_hash ?? GENESIS_LEDGER_HASH,
    latest_checkpoint: readLatestCheckpoint(database),
    revocation_list_version: revocation.version ?? 0,
    active_policy_version: policy.version ?? 0
  };
}

function readLatestCheckpoint(database: DatabaseSync): Checkpoint | null {
  const row = database
    .prepare("SELECT sequence, ledger_hash, issued_at, key_version, signature FROM checkpoints ORDER BY sequence DESC LIMIT 1")
    .get() as CheckpointRow | undefined;

  if (row === undefined) {
    return null;
  }

  return checkpointFromRow(row);
}

function readCheckpoints(database: DatabaseSync, after: bigint): Checkpoint[] {
  return database
    .prepare(
      `SELECT sequence, ledger_hash, issued_at, key_version, signature
      FROM checkpoints
      WHERE sequence > ?
      ORDER BY sequence ASC`
    )
    .all(toSqlInteger(after))
    .map((row) => checkpointFromRow(row as CheckpointRow));
}

type EventRow = {
  readonly id: string;
  readonly server_sequence: number | null;
  readonly event_type: LedgerEvent["event_type"];
  readonly actor_id: string;
  readonly device_id: string;
  readonly device_event_counter: number;
  readonly base_server_sequence: number;
  readonly object_type: LedgerEvent["object_type"];
  readonly object_id: string;
  readonly policy_metadata: string;
  readonly encrypted_payload: Buffer;
  readonly payload_hash: string;
  readonly previous_ledger_hash: string | null;
  readonly resulting_ledger_hash: string | null;
  readonly client_signature: string;
  readonly server_signature: string | null;
  readonly status: LedgerEvent["status"];
  readonly error_code: LedgerEvent["error_code"];
  readonly client_timestamp: string;
  readonly server_timestamp: string;
  readonly accepted_at: string | null;
};

function readEvents(database: DatabaseSync, afterSeq: bigint): LedgerEvent[] {
  return database
    .prepare(
      `SELECT
        id, server_sequence, event_type, actor_id, device_id,
        device_event_counter, base_server_sequence, object_type, object_id,
        policy_metadata, encrypted_payload, payload_hash, previous_ledger_hash,
        resulting_ledger_hash, client_signature, server_signature, status,
        error_code, client_timestamp, server_timestamp, accepted_at
      FROM ledger_events
      WHERE server_sequence > ?
      ORDER BY server_sequence ASC`
    )
    .all(toSqlInteger(afterSeq))
    .map((row) => eventFromRow(row as EventRow));
}

function eventFromRow(row: EventRow): LedgerEvent {
  return {
    event_id: row.id,
    event_type: row.event_type,
    actor_id: row.actor_id,
    device_id: row.device_id,
    client_timestamp: row.client_timestamp,
    base_server_sequence: BigInt(row.base_server_sequence),
    device_event_counter: BigInt(row.device_event_counter),
    object_type: row.object_type,
    object_id: row.object_id,
    policy_metadata: parsePolicyMetadata(row.policy_metadata),
    payload_hash: row.payload_hash,
    encrypted_payload: row.encrypted_payload.toString("base64"),
    client_signature: row.client_signature,
    server_sequence: row.server_sequence === null ? null : BigInt(row.server_sequence),
    previous_ledger_hash: row.previous_ledger_hash,
    resulting_ledger_hash: row.resulting_ledger_hash,
    server_signature: row.server_signature,
    status: row.status,
    error_code: row.error_code,
    server_timestamp: row.server_timestamp,
    accepted_at: row.accepted_at
  };
}

function parsePolicyMetadata(raw: string): LedgerEvent["policy_metadata"] {
  const parsed = JSON.parse(raw) as Record<string, unknown>;

  return {
    account_id: typeof parsed.account_id === "string" ? parsed.account_id : undefined,
    counterparty_account_id:
      typeof parsed.counterparty_account_id === "string" ? parsed.counterparty_account_id : undefined,
    entity_id: typeof parsed.entity_id === "string" ? parsed.entity_id : undefined,
    amount_minor_units:
      typeof parsed.amount_minor_units === "string" || typeof parsed.amount_minor_units === "number"
        ? BigInt(parsed.amount_minor_units)
        : undefined,
    currency: typeof parsed.currency === "string" ? parsed.currency : undefined,
    transaction_currency: typeof parsed.transaction_currency === "string" ? parsed.transaction_currency : undefined,
    exchange_rate: typeof parsed.exchange_rate === "string" ? parsed.exchange_rate : undefined,
    default_currency_snapshot_id:
      typeof parsed.default_currency_snapshot_id === "string" ? parsed.default_currency_snapshot_id : undefined,
    local_rate:
      typeof parsed.local_rate === "string" || typeof parsed.local_rate === "number"
        ? BigInt(parsed.local_rate)
        : undefined
  };
}

function checkpointFromRow(row: CheckpointRow): Checkpoint {
  return {
    sequence: BigInt(row.sequence),
    ledger_hash: row.ledger_hash,
    issued_at: row.issued_at,
    key_version: row.key_version,
    signature: row.signature
  };
}

type SnapshotRow = {
  readonly id: string;
  readonly up_to_sequence: number;
  readonly content_hash: string;
  readonly storage_ref: string;
  readonly signature: string;
  readonly created_at: string;
};

function readLatestSnapshot(database: DatabaseSync): LedgerSnapshot | null {
  const row = database
    .prepare(
      `SELECT id, up_to_sequence, content_hash, storage_ref, signature, created_at
      FROM snapshots
      ORDER BY up_to_sequence DESC
      LIMIT 1`
    )
    .get() as SnapshotRow | undefined;

  if (row === undefined) {
    return null;
  }

  return {
    id: row.id,
    up_to_sequence: BigInt(row.up_to_sequence),
    content_hash: row.content_hash,
    storage_ref: row.storage_ref,
    signature: row.signature,
    created_at: row.created_at
  };
}

type DocumentRow = {
  readonly document: string;
};

function readLatestRevocationList(database: DatabaseSync): RevocationList | null {
  const row = database
    .prepare("SELECT document FROM revocation_list_versions ORDER BY version DESC LIMIT 1")
    .get() as DocumentRow | undefined;

  return row === undefined ? null : (JSON.parse(row.document) as RevocationList);
}

function readActivePolicy(database: DatabaseSync): PolicyDocument | null {
  const row = database
    .prepare("SELECT document FROM policies ORDER BY version DESC LIMIT 1")
    .get() as DocumentRow | undefined;

  return row === undefined ? null : (JSON.parse(row.document) as PolicyDocument);
}

function isJsonParseError(error: unknown): boolean {
  return (
    typeof error === "object" &&
    error !== null &&
    "type" in error &&
    ((error as { type?: unknown }).type === "entity.parse.failed" ||
      (error as { type?: unknown }).type === "entity.too.large")
  );
}

function toSqlInteger(value: bigint): number {
  const asNumber = Number(value);

  if (!Number.isSafeInteger(asNumber)) {
    throw new ApiError(400, "SCHEMA_INVALID");
  }

  return asNumber;
}
