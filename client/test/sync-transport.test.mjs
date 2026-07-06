import assert from "node:assert/strict";
import { mkdtemp, rm } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { test } from "node:test";

import { LocalStore } from "../dist/main/main/local-store.js";
import {
  MtlsSyncTransport,
  createMtlsSyncTransportFromStore,
  jsonReplacer,
  normalizeProtocolJson
} from "../dist/main/main/sync-transport.js";

const caPem = "-----BEGIN CERTIFICATE-----\nca\n-----END CERTIFICATE-----";
const certPem = "-----BEGIN CERTIFICATE-----\nclient\n-----END CERTIFICATE-----";
const keyPem = "-----BEGIN PRIVATE KEY-----\nclient\n-----END PRIVATE KEY-----";

test("mTLS sync transport requires HTTPS", () => {
  assert.throws(
    () =>
      new MtlsSyncTransport({
        baseUrl: "http://ledger.vorcaro.test",
        caPem,
        clientCertificatePem: certPem,
        clientPrivateKeyPem: keyPem
      }),
    /requires HTTPS/
  );
});

test("mTLS sync transport builds pinned TLS request options", () => {
  const transport = new MtlsSyncTransport({
    baseUrl: "https://ledger.vorcaro.test:9443/base",
    caPem,
    clientCertificatePem: certPem,
    clientPrivateKeyPem: keyPem,
    timeoutMs: 1234,
    requestJson: async () => ({})
  });

  const options = transport.buildRequestOptions({ method: "GET", path: "/v1/state" });
  assert.equal(options.protocol, "https:");
  assert.equal(options.hostname, "ledger.vorcaro.test");
  assert.equal(options.port, "9443");
  assert.equal(options.path, "/v1/state");
  assert.equal(options.method, "GET");
  assert.equal(options.ca, caPem);
  assert.equal(options.cert, certPem);
  assert.equal(options.key, keyPem);
  assert.equal(options.rejectUnauthorized, true);
  assert.equal(options.minVersion, "TLSv1.3");
  assert.equal(options.timeout, 1234);
});

test("mTLS sync transport calls the expected device API paths", async () => {
  const calls = [];
  const transport = new MtlsSyncTransport({
    baseUrl: "https://ledger.vorcaro.test",
    caPem,
    clientCertificatePem: certPem,
    clientPrivateKeyPem: keyPem,
    requestJson: async (request) => {
      calls.push(request);
      return {};
    }
  });

  await transport.getState();
  await transport.getCheckpoints(7n);
  await transport.getEvents(9n);
  await transport.getActivePolicy();
  await transport.pushEvents([
    {
      event_id: "evt_1",
      event_type: "ACCOUNT_CREATED",
      actor_id: "exec_1",
      device_id: "dev_1",
      client_timestamp: "2026-07-05T00:00:00.000Z",
      base_server_sequence: 0n,
      device_event_counter: 1n,
      object_type: "account",
      object_id: "acct_1",
      policy_metadata: {},
      payload_hash: "sha256:0000000000000000000000000000000000000000000000000000000000000000",
      encrypted_payload: "AA==",
      client_signature: "AA=="
    }
  ]);

  assert.deepEqual(
    calls.map((call) => [call.method, call.path]),
    [
      ["GET", "/v1/state"],
      ["GET", "/v1/checkpoints?after=7"],
      ["GET", "/v1/events?after_seq=9"],
      ["GET", "/v1/policies/active"],
      ["POST", "/v1/events"]
    ]
  );
  assert.equal(calls[4].body.event_id, "evt_1");
});

test("protocol JSON normalization restores only known bigint fields", () => {
  const normalized = normalizeProtocolJson({
    latest_sequence: "9",
    event_id: "123",
    policy: {
      activated_at_sequence: "0n"
    },
    events: [
      {
        server_sequence: "2",
        policy_metadata: {
          amount_minor_units: "500",
          local_rate: "500",
          exchange_rate: "1"
        }
      }
    ]
  });

  assert.equal(normalized.latest_sequence, 9n);
  assert.equal(normalized.event_id, "123");
  assert.equal(normalized.policy.activated_at_sequence, 0n);
  assert.equal(normalized.events[0].server_sequence, 2n);
  assert.equal(normalized.events[0].policy_metadata.amount_minor_units, 500n);
  assert.equal(normalized.events[0].policy_metadata.local_rate, 500n);
  assert.equal(normalized.events[0].policy_metadata.exchange_rate, "1");
});

test("sync transport JSON replacer serializes bigint for POST bodies", () => {
  assert.equal(JSON.stringify({ counter: 3n }, jsonReplacer), '{"counter":"3"}');
});

test("mTLS sync transport can be constructed from stored device credentials", async () => {
  const tempRoot = await mkdtemp(path.join(os.tmpdir(), "vorcaro-sync-transport-"));
  const databaseKey = Buffer.alloc(32, 13);

  try {
    const store = LocalStore.open({
      databasePath: path.join(tempRoot, "local.db"),
      databaseKey
    });
    store.writeDeviceCredentials({
      executiveId: "exec_cfo",
      executiveRole: "CFO",
      deviceId: "dev_macbook",
      deviceRiskScore: 5,
      serverBaseUrl: "https://ledger.vorcaro.test",
      serverCaPem: caPem,
      clientCertificatePem: certPem,
      clientPrivateKeyPem: keyPem,
      certificateFingerprint: "fingerprint-device",
      certificateExpiresAt: "2026-07-12T00:00:00.000Z",
      hardwareBacked: false
    });

    const transport = createMtlsSyncTransportFromStore(store, 999);
    const options = transport.buildRequestOptions({ method: "GET", path: "/v1/state" });

    assert.equal(options.ca, caPem);
    assert.equal(options.cert, certPem);
    assert.equal(options.key, keyPem);
    assert.equal(options.timeout, 999);
    store.close();
  } finally {
    databaseKey.fill(0);
    await rm(tempRoot, { recursive: true, force: true });
  }
});
