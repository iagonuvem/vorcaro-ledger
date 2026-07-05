import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import {
  deriveSigningKeyPair,
  payloadHash,
  signClientEvent,
  verifyServerAckSignature
} from "@vorcaro/protocol";

import {
  GENESIS_LEDGER_HASH,
  LedgerAppender,
  openLedgerDatabase
} from "../dist/index.js";

const clientKeys = deriveSigningKeyPair(Buffer.alloc(32, 21));
const otherClientKeys = deriveSigningKeyPair(Buffer.alloc(32, 22));
const serverKeys = deriveSigningKeyPair(Buffer.alloc(32, 23));

test("append accepts a valid event, advances the hash chain, and returns a signed acknowledgement", async () => {
  const { database, appender, cleanup } = createFixture();

  try {
    const event = makeEvent({ eventId: "evt_accept_001", counter: 1n });
    const ack = await appender.append({ event, certificateFingerprint: "fingerprint-1" });
    const row = database.prepare("SELECT * FROM ledger_events WHERE id = ?").get("evt_accept_001");
    const head = database.prepare("SELECT head_sequence, conflicted FROM object_heads WHERE object_id = ?").get(event.object_id);
    const device = database.prepare("SELECT max_event_counter FROM devices WHERE id = ?").get(event.device_id);

    assert.equal(ack.status, "accepted");
    assert.equal(ack.error_code, null);
    assert.equal(ack.server_sequence, 1n);
    assert.equal(verifyServerAckSignature(ack, serverKeys.publicKey), true);
    assert.equal(row.previous_ledger_hash, GENESIS_LEDGER_HASH);
    assert.equal(row.resulting_ledger_hash, ack.resulting_ledger_hash);
    assert.equal(row.error_code, null);
    assert.equal(head.head_sequence, 1);
    assert.equal(head.conflicted, 0);
    assert.equal(device.max_event_counter, 1);
  } finally {
    database.close();
    cleanup();
  }
});

test("duplicate event id returns the original signed outcome verbatim", async () => {
  const { database, appender, cleanup } = createFixture();

  try {
    const event = makeEvent({ eventId: "evt_duplicate_001", counter: 1n });
    const firstAck = await appender.append({ event, certificateFingerprint: "fingerprint-1" });
    const secondAck = await appender.append({ event, certificateFingerprint: "fingerprint-1" });
    const eventCount = database.prepare("SELECT COUNT(*) AS count FROM ledger_events").get();

    assert.deepEqual(secondAck, firstAck);
    assert.equal(eventCount.count, 1);
  } finally {
    database.close();
    cleanup();
  }
});

test("captured counter replay is rejected before append", async () => {
  const { database, appender, cleanup } = createFixture();

  try {
    await appender.append({
      event: makeEvent({ eventId: "evt_replay_original", counter: 1n }),
      certificateFingerprint: "fingerprint-1"
    });
    const replayAck = await appender.append({
      event: makeEvent({ eventId: "evt_replay_changed", counter: 1n, objectId: "acct_replay_changed" }),
      certificateFingerprint: "fingerprint-1"
    });
    const eventCount = database.prepare("SELECT COUNT(*) AS count FROM ledger_events").get();

    assert.equal(replayAck.status, "rejected");
    assert.equal(replayAck.error_code, "REPLAY_COUNTER");
    assert.equal(replayAck.server_sequence, null);
    assert.equal(verifyServerAckSignature(replayAck, serverKeys.publicKey), true);
    assert.equal(eventCount.count, 1);
  } finally {
    database.close();
    cleanup();
  }
});

test("bad signatures and payload hashes append rejected audit evidence", async () => {
  const { database, appender, cleanup } = createFixture();

  try {
    const badSignature = makeEvent({
      eventId: "evt_bad_signature",
      counter: 1n,
      signingSecretKey: otherClientKeys.secretKey
    });
    const badSignatureAck = await appender.append({
      event: badSignature,
      certificateFingerprint: "fingerprint-1"
    });
    const badHash = makeEvent({
      eventId: "evt_bad_hash",
      counter: 2n,
      payloadHashOverride: "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
    });
    const badHashAck = await appender.append({
      event: badHash,
      certificateFingerprint: "fingerprint-1"
    });
    const rows = database
      .prepare("SELECT id, status, error_code, server_sequence FROM ledger_events ORDER BY server_sequence")
      .all();
    const device = database.prepare("SELECT max_event_counter FROM devices WHERE id = ?").get("dev_1");

    assert.equal(badSignatureAck.status, "rejected");
    assert.equal(badSignatureAck.error_code, "BAD_SIGNATURE");
    assert.equal(badHashAck.status, "rejected");
    assert.equal(badHashAck.error_code, "BAD_PAYLOAD_HASH");
    assert.deepEqual(
      rows.map((row) => [row.id, row.status, row.error_code, row.server_sequence]),
      [
        ["evt_bad_signature", "rejected", "BAD_SIGNATURE", 1],
        ["evt_bad_hash", "rejected", "BAD_PAYLOAD_HASH", 2]
      ]
    );
    assert.equal(device.max_event_counter, 2);
  } finally {
    database.close();
    cleanup();
  }
});

test("offline clients converge to one chain while stale-object writes are explicitly conflicted", async () => {
  const { database, appender, cleanup } = createFixture();

  try {
    const first = await appender.append({
      event: makeEvent({
        eventId: "evt_client_one",
        counter: 1n,
        deviceId: "dev_1",
        objectId: "acct_shared",
        baseServerSequence: 0n
      }),
      certificateFingerprint: "fingerprint-1"
    });
    const conflicted = await appender.append({
      event: makeEvent({
        eventId: "evt_client_two_conflict",
        counter: 1n,
        deviceId: "dev_2",
        objectId: "acct_shared",
        baseServerSequence: 0n
      }),
      certificateFingerprint: "fingerprint-2"
    });
    const independent = await appender.append({
      event: makeEvent({
        eventId: "evt_client_two_independent",
        counter: 2n,
        deviceId: "dev_2",
        objectId: "acct_independent",
        baseServerSequence: 0n
      }),
      certificateFingerprint: "fingerprint-2"
    });
    const chainHead = database
      .prepare("SELECT server_sequence, resulting_ledger_hash FROM ledger_events ORDER BY server_sequence DESC LIMIT 1")
      .get();
    const sharedHead = database
      .prepare("SELECT head_sequence, conflicted FROM object_heads WHERE object_id = ?")
      .get("acct_shared");
    const independentHead = database
      .prepare("SELECT head_sequence, conflicted FROM object_heads WHERE object_id = ?")
      .get("acct_independent");
    const conflict = database
      .prepare("SELECT object_type, object_id, event_ids, detected_at_sequence, status FROM conflicts WHERE object_id = ?")
      .get("acct_shared");

    assert.equal(first.status, "accepted");
    assert.equal(conflicted.status, "conflicted");
    assert.equal(conflicted.error_code, "CONFLICT");
    assert.equal(independent.status, "accepted");
    assert.equal(chainHead.server_sequence, 3);
    assert.equal(chainHead.resulting_ledger_hash, independent.resulting_ledger_hash);
    assert.equal(sharedHead.head_sequence, 1);
    assert.equal(sharedHead.conflicted, 1);
    assert.equal(independentHead.head_sequence, 3);
    assert.equal(independentHead.conflicted, 0);
    assert.equal(conflict.object_type, "account");
    assert.equal(conflict.object_id, "acct_shared");
    assert.equal(conflict.detected_at_sequence, 2);
    assert.equal(conflict.status, "open");
    assert.deepEqual(JSON.parse(conflict.event_ids), ["evt_client_one", "evt_client_two_conflict"]);
  } finally {
    database.close();
    cleanup();
  }
});

test("conflicted objects reject new writes until a signed CONFLICT_RESOLVED event lands", async () => {
  const { database, appender, cleanup } = createFixture();

  try {
    await appender.append({
      event: makeEvent({
        eventId: "evt_conflict_head",
        counter: 1n,
        deviceId: "dev_1",
        objectId: "acct_resolution",
        baseServerSequence: 0n
      }),
      certificateFingerprint: "fingerprint-1"
    });
    const conflictAck = await appender.append({
      event: makeEvent({
        eventId: "evt_conflict_stale",
        counter: 1n,
        deviceId: "dev_2",
        objectId: "acct_resolution",
        baseServerSequence: 0n
      }),
      certificateFingerprint: "fingerprint-2"
    });
    const blockedAck = await appender.append({
      event: makeEvent({
        eventId: "evt_blocked_during_conflict",
        counter: 2n,
        deviceId: "dev_1",
        objectId: "acct_resolution",
        baseServerSequence: 2n
      }),
      certificateFingerprint: "fingerprint-1"
    });
    const resolutionAck = await appender.append({
      event: makeEvent({
        eventId: "evt_conflict_resolved",
        eventType: "CONFLICT_RESOLVED",
        counter: 3n,
        deviceId: "dev_1",
        objectId: "acct_resolution",
        baseServerSequence: 2n
      }),
      certificateFingerprint: "fingerprint-1"
    });
    const head = database
      .prepare("SELECT head_sequence, conflicted FROM object_heads WHERE object_id = ?")
      .get("acct_resolution");
    const conflict = database
      .prepare("SELECT status, resolution_event_id, resolved_at FROM conflicts WHERE object_id = ?")
      .get("acct_resolution");
    const statuses = database
      .prepare("SELECT id, status, error_code, server_sequence FROM ledger_events ORDER BY server_sequence")
      .all();

    assert.equal(conflictAck.status, "conflicted");
    assert.equal(blockedAck.status, "rejected");
    assert.equal(blockedAck.error_code, "POLICY_DENIED");
    assert.equal(resolutionAck.status, "accepted");
    assert.equal(head.head_sequence, 4);
    assert.equal(head.conflicted, 0);
    assert.equal(conflict.status, "resolved");
    assert.equal(conflict.resolution_event_id, "evt_conflict_resolved");
    assert.equal(conflict.resolved_at, "2026-07-01T14:23:15.000Z");
    assert.deepEqual(
      statuses.map((row) => [row.id, row.status, row.error_code, row.server_sequence]),
      [
        ["evt_conflict_head", "accepted", null, 1],
        ["evt_conflict_stale", "conflicted", "CONFLICT", 2],
        ["evt_blocked_during_conflict", "rejected", "POLICY_DENIED", 3],
        ["evt_conflict_resolved", "accepted", null, 4]
      ]
    );
  } finally {
    database.close();
    cleanup();
  }
});

test("CONFLICT_RESOLVED without an open conflict appends a closed-code rejection", async () => {
  const { database, appender, cleanup } = createFixture();

  try {
    await appender.append({
      event: makeEvent({
        eventId: "evt_resolution_head",
        counter: 1n,
        objectId: "acct_no_conflict"
      }),
      certificateFingerprint: "fingerprint-1"
    });
    const ack = await appender.append({
      event: makeEvent({
        eventId: "evt_resolution_without_conflict",
        eventType: "CONFLICT_RESOLVED",
        counter: 2n,
        objectId: "acct_no_conflict",
        baseServerSequence: 1n
      }),
      certificateFingerprint: "fingerprint-1"
    });
    const head = database
      .prepare("SELECT head_sequence, conflicted FROM object_heads WHERE object_id = ?")
      .get("acct_no_conflict");

    assert.equal(ack.status, "rejected");
    assert.equal(ack.error_code, "CONFLICT");
    assert.equal(ack.server_sequence, 2n);
    assert.equal(head.head_sequence, 1);
    assert.equal(head.conflicted, 0);
  } finally {
    database.close();
    cleanup();
  }
});

test("batch append processes events in device counter order", async () => {
  const { database, appender, cleanup } = createFixture();

  try {
    const second = makeEvent({ eventId: "evt_batch_second", counter: 2n, objectId: "acct_batch_2" });
    const first = makeEvent({ eventId: "evt_batch_first", counter: 1n, objectId: "acct_batch_1" });
    const acknowledgements = await appender.appendBatch([
      { event: second, certificateFingerprint: "fingerprint-1" },
      { event: first, certificateFingerprint: "fingerprint-1" }
    ]);
    const rows = database
      .prepare("SELECT id, server_sequence FROM ledger_events ORDER BY server_sequence")
      .all();

    assert.equal(acknowledgements[0].event_id, "evt_batch_first");
    assert.equal(acknowledgements[1].event_id, "evt_batch_second");
    assert.deepEqual(
      rows.map((row) => [row.id, row.server_sequence]),
      [
        ["evt_batch_first", 1],
        ["evt_batch_second", 2]
      ]
    );
  } finally {
    database.close();
    cleanup();
  }
});

function createFixture() {
  const directory = mkdtempSync(join(tmpdir(), "vorcaro-appender-"));
  const database = openLedgerDatabase({ path: join(directory, "ledger.db") });
  seedIdentity(database);
  const appender = LedgerAppender.create({
    database,
    serverSigningSecretKey: serverKeys.secretKey,
    now: sequentialClock("2026-07-01T14:23:12.000Z")
  });

  return {
    database,
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
      object_id: options.objectId ?? "acct_default",
      policy_metadata: {
        account_id: options.objectId ?? "acct_default",
        entity_id: "ent_1",
        amount_minor_units: 1000n,
        currency: "USD",
        default_currency_snapshot_id: "ccysnap_test_usd",
        exchange_rate: "1",
        local_rate: 1000n,
        transaction_currency: "USD"
      },
      payload_hash: options.payloadHashOverride ?? payloadHash(payload),
      encrypted_payload: payload
    },
    options.signingSecretKey ?? clientKeys.secretKey
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
