import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import {
  canonicalBytes,
  deriveSigningKeyPair,
  payloadHash,
  sha256Digest,
  signClientEvent,
  verifyBytes
} from "@vorcaro/protocol";

import {
  LedgerAppender,
  MemorySnapshotObjectStore,
  ProjectionWorker,
  SnapshotWorker,
  openLedgerDatabase,
  openProjectionsDatabase
} from "../dist/index.js";

const clientKeys = deriveSigningKeyPair(Buffer.alloc(32, 31));
const serverKeys = deriveSigningKeyPair(Buffer.alloc(32, 32));

test("projection worker applies ledger events idempotently and mirrors open conflicts", async () => {
  const { ledgerDatabase, projectionsDatabase, appender, cleanup } = createFixture();

  try {
    await appender.append({
      event: makeEvent({ eventId: "evt_projection_head", counter: 1n, objectId: "acct_projection" }),
      certificateFingerprint: "fingerprint-1"
    });
    await appender.append({
      event: makeEvent({
        eventId: "evt_projection_conflict",
        counter: 1n,
        deviceId: "dev_2",
        objectId: "acct_projection",
        baseServerSequence: 0n
      }),
      certificateFingerprint: "fingerprint-2"
    });

    const worker = ProjectionWorker.create({ ledgerDatabase, projectionsDatabase });
    const firstRun = worker.applyNextBatch();
    const repeatedRun = worker.applyNextBatch();
    const account = projectionsDatabase
      .prepare("SELECT entity_id, currency, as_of_sequence, status, conflicted FROM proj_accounts WHERE account_id = ?")
      .get("acct_projection");
    const cash = projectionsDatabase
      .prepare("SELECT entity_id, currency, total_minor_units, as_of_sequence FROM proj_cash_position")
      .get();
    const conflict = projectionsDatabase
      .prepare("SELECT object_type, object_id, event_ids, detected_at_sequence FROM proj_conflicts_open")
      .get();

    assert.deepEqual(firstRun, { fromSequence: 0n, toSequence: 2n, appliedEvents: 2 });
    assert.deepEqual(repeatedRun, { fromSequence: 2n, toSequence: 2n, appliedEvents: 0 });
    assert.deepEqual({ ...account }, {
      entity_id: "ent_1",
      currency: "USD",
      as_of_sequence: 1,
      status: "active",
      conflicted: 1
    });
    assert.deepEqual({ ...cash }, {
      entity_id: "ent_1",
      currency: "USD",
      total_minor_units: 0,
      as_of_sequence: 1
    });
    assert.deepEqual(JSON.parse(conflict.event_ids), ["evt_projection_head", "evt_projection_conflict"]);
    assert.equal(conflict.object_type, "account");
    assert.equal(conflict.object_id, "acct_projection");
    assert.equal(conflict.detected_at_sequence, 2);

    await appender.append({
      event: makeEvent({
        eventId: "evt_projection_resolution",
        eventType: "CONFLICT_RESOLVED",
        counter: 2n,
        objectId: "acct_projection",
        baseServerSequence: 2n
      }),
      certificateFingerprint: "fingerprint-1"
    });
    const resolutionRun = worker.applyNextBatch();
    const resolvedAccount = projectionsDatabase
      .prepare("SELECT as_of_sequence, conflicted FROM proj_accounts WHERE account_id = ?")
      .get("acct_projection");
    const openConflictCount = projectionsDatabase
      .prepare("SELECT COUNT(*) AS count FROM proj_conflicts_open")
      .get();

    assert.deepEqual(resolutionRun, { fromSequence: 2n, toSequence: 3n, appliedEvents: 1 });
    assert.deepEqual({ ...resolvedAccount }, { as_of_sequence: 1, conflicted: 0 });
    assert.equal(openConflictCount.count, 0);
  } finally {
    ledgerDatabase.close();
    projectionsDatabase.close();
    cleanup();
  }
});

test("snapshot worker stores encrypted compact state and writes a signed manifest", async () => {
  const { ledgerDatabase, projectionsDatabase, appender, cleanup } = createFixture();

  try {
    await appender.append({
      event: makeEvent({ eventId: "evt_snapshot_account", counter: 1n, objectId: "acct_snapshot" }),
      certificateFingerprint: "fingerprint-1"
    });
    ProjectionWorker.create({ ledgerDatabase, projectionsDatabase }).applyNextBatch();

    const objectStore = new MemorySnapshotObjectStore();
    const snapshotWorker = SnapshotWorker.create({
      ledgerDatabase,
      projectionsDatabase,
      objectStore,
      serverSigningSecretKey: serverKeys.secretKey,
      snapshotEncryptionKey: Buffer.alloc(32, 7),
      now: () => "2026-07-01T14:30:00.000Z"
    });
    const snapshot = snapshotWorker.createSnapshot();
    const storedKey = `${snapshot.id}.bin`;
    const storedBody = objectStore.objects.get(storedKey);
    const row = ledgerDatabase.prepare("SELECT * FROM snapshots WHERE id = ?").get(snapshot.id);
    const unsignedSnapshot = {
      id: snapshot.id,
      up_to_sequence: snapshot.up_to_sequence,
      content_hash: snapshot.content_hash,
      storage_ref: snapshot.storage_ref,
      created_at: snapshot.created_at
    };

    assert.ok(storedBody instanceof Buffer);
    assert.equal(snapshot.up_to_sequence, 1n);
    assert.equal(snapshot.content_hash, sha256Digest(storedBody));
    assert.equal(snapshot.storage_ref, `memory://snapshots/${storedKey}`);
    assert.equal(row.up_to_sequence, 1);
    assert.equal(row.content_hash, snapshot.content_hash);
    assert.equal(row.signature, snapshot.signature);
    assert.equal(verifyBytes(canonicalBytes(unsignedSnapshot), snapshot.signature, serverKeys.publicKey), true);
    assert.equal(storedBody.toString("utf8").includes("acct_snapshot"), false);

    const secondSnapshot = snapshotWorker.createSnapshot();
    assert.notEqual(secondSnapshot.id, snapshot.id);
  } finally {
    ledgerDatabase.close();
    projectionsDatabase.close();
    cleanup();
  }
});

function createFixture() {
  const directory = mkdtempSync(join(tmpdir(), "vorcaro-projections-"));
  const ledgerDatabase = openLedgerDatabase({ path: join(directory, "ledger.db") });
  const projectionsDatabase = openProjectionsDatabase({ path: join(directory, "projections.db") });
  seedIdentity(ledgerDatabase);
  const appender = LedgerAppender.create({
    database: ledgerDatabase,
    serverSigningSecretKey: serverKeys.secretKey,
    now: sequentialClock("2026-07-01T14:23:12.000Z")
  });

  return {
    ledgerDatabase,
    projectionsDatabase,
    appender,
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

  for (const [deviceId, fingerprint] of [
    ["dev_1", "fingerprint-1"],
    ["dev_2", "fingerprint-2"]
  ]) {
    database
      .prepare(
        `INSERT INTO devices (
          id, executive_id, certificate_fingerprint, public_key, status,
          hardware_backed, enrolled_at, risk_score, max_event_counter
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`
      )
      .run(
        deviceId,
        "exec_1",
        fingerprint,
        "device-public-key",
        "enrolled",
        1,
        "2026-07-01T14:00:00Z",
        0,
        0
      );
  }
}

function makeEvent(options) {
  const payload = Buffer.from(`payload:${options.eventId}`).toString("base64");
  const objectId = options.objectId ?? "acct_default";

  return signClientEvent(
    {
      event_id: options.eventId,
      event_type: options.eventType ?? "ACCOUNT_CREATED",
      actor_id: "exec_1",
      device_id: options.deviceId ?? "dev_1",
      client_timestamp: "2026-07-01T14:23:11Z",
      base_server_sequence: options.baseServerSequence ?? 0n,
      device_event_counter: options.counter,
      object_type: "account",
      object_id: objectId,
      policy_metadata: {
        account_id: objectId,
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

function sequentialClock(startIso) {
  let nextTime = Date.parse(startIso);

  return () => {
    const current = new Date(nextTime).toISOString();
    nextTime += 1000;
    return current;
  };
}
