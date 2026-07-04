import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import {
  canonicalBytes,
  deriveSigningKeyPair,
  payloadHash,
  signClientEvent,
  verifyBytes
} from "@vorcaro/protocol";

import {
  buildMtlsServerOptions,
  createAdminApiApp,
  createDeviceApiApp,
  createLedgerAppender,
  openLedgerDatabase
} from "../dist/index.js";
import { ApiError } from "../dist/api/errors.js";
import { createIdentityMiddleware } from "../dist/api/identity.js";
import { parseEventSubmission } from "../dist/api/device-api.js";
import { signStateResponse } from "../dist/api/signing.js";

const clientKeys = deriveSigningKeyPair(Buffer.alloc(32, 31));
const serverKeys = deriveSigningKeyPair(Buffer.alloc(32, 32));

test("identity middleware binds identity from the certificate fingerprint and audits ignored identity headers", () => {
  const { database, cleanup } = createDatabaseFixture();

  try {
    const middleware = createIdentityMiddleware({
      database,
      now: () => "2026-07-01T15:00:00.000Z",
      certificateFingerprintResolver: () => "fingerprint-1"
    });
    const request = {
      path: "/v1/state",
      headers: {
        "x-device-id": "attacker-controlled"
      }
    };
    let nextCalled = false;

    middleware(request, {}, () => {
      nextCalled = true;
    });

    const audit = database.prepare("SELECT category, detail FROM audit_log ORDER BY id DESC LIMIT 1").get();

    assert.equal(nextCalled, true);
    assert.equal(request.identity.device.id, "dev_1");
    assert.equal(request.identity.executive.id, "exec_1");
    assert.equal(audit.category, "auth");
    assert.deepEqual(JSON.parse(audit.detail), {
      event: "ignored_identity_headers",
      header_names: ["x-device-id"]
    });
  } finally {
    database.close();
    cleanup();
  }
});

test("identity middleware rejects missing and revoked certificates with closed error codes", () => {
  const { database, cleanup } = createDatabaseFixture();

  try {
    const missing = createIdentityMiddleware({
      database,
      now: () => "2026-07-01T15:00:00.000Z",
      certificateFingerprintResolver: () => undefined
    });
    assert.throws(
      () => missing({ path: "/v1/state", headers: {} }, {}, () => undefined),
      (error) => error instanceof ApiError && error.errorCode === "CERT_UNKNOWN"
    );

    database.prepare("UPDATE devices SET status = ? WHERE id = ?").run("revoked", "dev_1");
    const revoked = createIdentityMiddleware({
      database,
      now: () => "2026-07-01T15:00:00.000Z",
      certificateFingerprintResolver: () => "fingerprint-1"
    });
    assert.throws(
      () => revoked({ path: "/v1/state", headers: {} }, {}, () => undefined),
      (error) => error instanceof ApiError && error.errorCode === "CERT_REVOKED"
    );
  } finally {
    database.close();
    cleanup();
  }
});

test("event submission validation accepts JSON string integers only at known bigint fields", () => {
  const event = makeEvent({ eventId: "evt_api_parse", counter: 1n });
  const jsonBody = JSON.parse(stringifyJson(event));
  const [parsed] = parseEventSubmission(jsonBody);

  assert.equal(typeof parsed.base_server_sequence, "bigint");
  assert.equal(typeof parsed.device_event_counter, "bigint");
  assert.equal(typeof parsed.policy_metadata.amount_minor_units, "bigint");
  assert.equal(parsed.event_id, "evt_api_parse");

  assert.throws(
    () =>
      parseEventSubmission({
        ...jsonBody,
        unexpected: true
      }),
    /Unrecognized key/
  );
});

test("state-bearing API responses are signed over canonical bytes", () => {
  const signed = signStateResponse(
    {
      latest_sequence: 7n,
      latest_ledger_hash: "sha256:1111111111111111111111111111111111111111111111111111111111111111",
      latest_checkpoint: null,
      revocation_list_version: 2,
      active_policy_version: 3,
      server_timestamp: "2026-07-01T15:00:00.000Z"
    },
    serverKeys.secretKey
  );
  const { signature, ...body } = signed;

  assert.equal(verifyBytes(canonicalBytes(body), signature, serverKeys.publicKey), true);
});

test("device and admin apps are hardened Express apps without version banners", () => {
  const { database, cleanup } = createDatabaseFixture();

  try {
    const appender = createLedgerAppender({
      database,
      serverSigningSecretKey: serverKeys.secretKey,
      now: () => "2026-07-01T15:00:00.000Z"
    });
    const deviceApp = createDeviceApiApp({
      database,
      appender,
      serverSigningSecretKey: serverKeys.secretKey,
      certificateFingerprintResolver: () => "fingerprint-1"
    });
    const adminApp = createAdminApiApp();

    assert.equal(deviceApp.enabled("x-powered-by"), false);
    assert.equal(adminApp.enabled("x-powered-by"), false);
  } finally {
    database.close();
    cleanup();
  }
});

test("TLS listener options enforce mandatory TLS 1.3 mTLS", () => {
  const options = buildMtlsServerOptions({
    key: "key",
    cert: "cert",
    ca: "ca",
    minVersion: "TLSv1.2",
    requestCert: false,
    rejectUnauthorized: false
  });

  assert.equal(options.minVersion, "TLSv1.3");
  assert.equal(options.requestCert, true);
  assert.equal(options.rejectUnauthorized, true);
});

function createDatabaseFixture() {
  const directory = mkdtempSync(join(tmpdir(), "vorcaro-api-"));
  const database = openLedgerDatabase({ path: join(directory, "ledger.db") });
  seedIdentity(database);

  return {
    database,
    cleanup: () => rmSync(directory, { recursive: true, force: true })
  };
}

function seedIdentity(database) {
  database
    .prepare(
      `INSERT INTO executives (
        id, display_name, role, status, signing_public_key, key_version, created_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?)`
    )
    .run("exec_1", "Vorcaro CFO", "CFO", "active", clientKeys.publicKey, 1, "2026-07-01T14:00:00Z");

  database
    .prepare(
      `INSERT INTO executive_keys (
        executive_id, key_version, signing_public_key, valid_from_sequence, valid_until_sequence
      ) VALUES (?, ?, ?, ?, ?)`
    )
    .run("exec_1", 1, clientKeys.publicKey, 0, null);

  database
    .prepare(
      `INSERT INTO devices (
        id, executive_id, certificate_fingerprint, public_key, status,
        hardware_backed, enrolled_at, risk_score, max_event_counter
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`
    )
    .run(
      "dev_1",
      "exec_1",
      "fingerprint-1",
      "device-public-key",
      "enrolled",
      1,
      "2026-07-01T14:00:00Z",
      0,
      0
    );
}

function makeEvent(options) {
  const payload = Buffer.from(`payload:${options.eventId}`).toString("base64");

  return signClientEvent(
    {
      event_id: options.eventId,
      event_type: "ACCOUNT_CREATED",
      actor_id: "exec_1",
      device_id: "dev_1",
      client_timestamp: "2026-07-01T14:23:11Z",
      base_server_sequence: options.baseServerSequence ?? 0n,
      device_event_counter: options.counter,
      object_type: "account",
      object_id: options.objectId ?? "acct_default",
      policy_metadata: {
        account_id: options.objectId ?? "acct_default",
        entity_id: "ent_1",
        amount_minor_units: 1000n,
        currency: "USD"
      },
      payload_hash: payloadHash(payload),
      encrypted_payload: payload
    },
    clientKeys.secretKey
  );
}

function stringifyJson(value) {
  return JSON.stringify(value, (_key, field) => (typeof field === "bigint" ? field.toString(10) : field));
}
