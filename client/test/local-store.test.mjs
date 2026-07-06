import assert from "node:assert/strict";
import { createRequire } from "node:module";
import { mkdtemp, rm } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { test } from "node:test";

import { LocalStore } from "../dist/main/main/local-store.js";

const require = createRequire(import.meta.url);
const Database = require("better-sqlite3-multiple-ciphers");

test("local store opens an encrypted SQLCipher-compatible database", async () => {
  const tempRoot = await mkdtemp(path.join(os.tmpdir(), "vorcaro-local-store-"));
  const databasePath = path.join(tempRoot, "profile", "local.db");
  const databaseKey = Buffer.alloc(32, 7);

  try {
    LocalStore.open({ databasePath, databaseKey }).close();

    const plain = new Database(databasePath, { readonly: true, fileMustExist: true });
    assert.throws(() => plain.prepare("SELECT value FROM meta WHERE key = 'schema_version'").get(), /file is not a database|not a database/);
    plain.close();

    const reopened = LocalStore.open({ databasePath, databaseKey: Buffer.alloc(32, 7), readonly: true });
    assert.equal(reopened.readMeta("schema_version"), "1");
    reopened.close();
  } finally {
    databaseKey.fill(0);
    await rm(tempRoot, { recursive: true, force: true });
  }
});

test("local store enforces append-only verification memory", async () => {
  const tempRoot = await mkdtemp(path.join(os.tmpdir(), "vorcaro-local-store-"));
  const databasePath = path.join(tempRoot, "profile", "local.db");
  const databaseKey = Buffer.alloc(32, 8);

  try {
    const store = LocalStore.open({ databasePath, databaseKey });
    const db = store.databaseForInternalUse();

    db.prepare(
      "INSERT INTO checkpoints (sequence, ledger_hash, signature, verified_at) VALUES (?, ?, ?, ?)"
    ).run(1, "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "sig", "2026-07-05T00:00:00.000Z");

    assert.throws(
      () => db.prepare("UPDATE checkpoints SET ledger_hash = ? WHERE sequence = 1").run("sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"),
      /checkpoints is append-only/
    );
    assert.throws(() => db.prepare("DELETE FROM checkpoints WHERE sequence = 1").run(), /checkpoints is append-only/);
    store.close();
  } finally {
    databaseKey.fill(0);
    await rm(tempRoot, { recursive: true, force: true });
  }
});

test("local store allocates monotonic device event counters", async () => {
  const tempRoot = await mkdtemp(path.join(os.tmpdir(), "vorcaro-local-store-"));
  const databasePath = path.join(tempRoot, "profile", "local.db");
  const databaseKey = Buffer.alloc(32, 9);

  try {
    const store = LocalStore.open({ databasePath, databaseKey });
    assert.equal(store.allocateDeviceEventCounter(), 1);
    assert.equal(store.allocateDeviceEventCounter(), 2);
    store.close();

    const reopened = LocalStore.open({ databasePath, databaseKey: Buffer.alloc(32, 9) });
    assert.equal(reopened.allocateDeviceEventCounter(), 3);
    reopened.close();
  } finally {
    databaseKey.fill(0);
    await rm(tempRoot, { recursive: true, force: true });
  }
});

test("local store writes hash-chained audit entries", async () => {
  const tempRoot = await mkdtemp(path.join(os.tmpdir(), "vorcaro-local-store-"));
  const databasePath = path.join(tempRoot, "profile", "local.db");
  const databaseKey = Buffer.alloc(32, 10);

  try {
    const store = LocalStore.open({ databasePath, databaseKey });
    const firstHash = store.writeAudit({
      category: "ipc_anomaly",
      body: { message: "Rejected invalid payload" },
      recordedAt: "2026-07-05T00:00:00.000Z"
    });
    const secondHash = store.writeAudit({
      category: "security_acknowledgement",
      body: { kind: "checkpoint_tripwire", acknowledged_at: "2026-07-05T00:00:01.000Z" },
      recordedAt: "2026-07-05T00:00:01.000Z"
    });

    const rows = store
      .databaseForInternalUse()
      .prepare("SELECT previous_hash, entry_hash FROM local_audit ORDER BY id")
      .all();
    assert.equal(rows.length, 2);
    assert.equal(rows[0].entry_hash, firstHash);
    assert.equal(rows[1].previous_hash, firstHash);
    assert.equal(rows[1].entry_hash, secondHash);
    store.close();
  } finally {
    databaseKey.fill(0);
    await rm(tempRoot, { recursive: true, force: true });
  }
});

test("local store persists enrolled device credentials inside the encrypted database", async () => {
  const tempRoot = await mkdtemp(path.join(os.tmpdir(), "vorcaro-local-store-"));
  const databasePath = path.join(tempRoot, "profile", "local.db");
  const databaseKey = Buffer.alloc(32, 11);

  try {
    const store = LocalStore.open({ databasePath, databaseKey });
    const credentials = makeDeviceCredentials();
    store.writeDeviceCredentials(credentials);
    assert.deepEqual(store.readDeviceCredentials(), credentials);
    store.close();

    const reopened = LocalStore.open({ databasePath, databaseKey: Buffer.alloc(32, 11) });
    assert.deepEqual(reopened.readDeviceCredentials(), credentials);
    assert.equal(reopened.requireMeta("executive_id"), "exec_cfo");
    assert.equal(reopened.requireMeta("device_id"), "dev_macbook");
    reopened.close();
  } finally {
    databaseKey.fill(0);
    await rm(tempRoot, { recursive: true, force: true });
  }
});

test("local store rejects device credentials without HTTPS sync URL", async () => {
  const tempRoot = await mkdtemp(path.join(os.tmpdir(), "vorcaro-local-store-"));
  const databasePath = path.join(tempRoot, "profile", "local.db");
  const databaseKey = Buffer.alloc(32, 12);

  try {
    const store = LocalStore.open({ databasePath, databaseKey });
    assert.throws(
      () =>
        store.writeDeviceCredentials({
          ...makeDeviceCredentials(),
          serverBaseUrl: "http://ledger.vorcaro.test"
        }),
      /require HTTPS/
    );
    assert.equal(store.readDeviceCredentials(), null);
    store.close();
  } finally {
    databaseKey.fill(0);
    await rm(tempRoot, { recursive: true, force: true });
  }
});

function makeDeviceCredentials() {
  return {
    executiveId: "exec_cfo",
    executiveRole: "CFO",
    deviceId: "dev_macbook",
    deviceRiskScore: 7,
    serverBaseUrl: "https://ledger.vorcaro.test",
    serverCaPem: "-----BEGIN CERTIFICATE-----\nca\n-----END CERTIFICATE-----",
    clientCertificatePem: "-----BEGIN CERTIFICATE-----\nclient\n-----END CERTIFICATE-----",
    clientPrivateKeyPem: "-----BEGIN PRIVATE KEY-----\nclient\n-----END PRIVATE KEY-----",
    certificateFingerprint: "fingerprint-device",
    certificateExpiresAt: "2026-07-12T00:00:00.000Z",
    hardwareBacked: true
  };
}
