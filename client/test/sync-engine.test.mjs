import assert from "node:assert/strict";
import { mkdtemp, rm } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { test } from "node:test";

import {
  computeLedgerHash,
  deriveSigningKeyPair,
  payloadHash,
  signCheckpoint,
  signClientEvent,
  signServerAck
} from "@vorcaro/protocol";

import { LocalStore } from "../dist/main/main/local-store.js";
import { SyncEngine, SyncVerificationError } from "../dist/main/main/sync-engine.js";

const clientKeys = deriveSigningKeyPair(Buffer.alloc(32, 41));
const serverKeys = deriveSigningKeyPair(Buffer.alloc(32, 42));
const checkpointKeys = deriveSigningKeyPair(Buffer.alloc(32, 43));
const genesisLedgerHash = "sha256:0000000000000000000000000000000000000000000000000000000000000000";

test("sync engine verifies and applies pulled ledger events", async () => {
  const fixture = await createStoreFixture();

  try {
    const engine = createEngine(fixture.store);
    const event = makeSequencedEvent({ eventId: "evt_sync_1", sequence: 1n, previousHash: genesisLedgerHash });

    engine.applyPulledEvents([event]);

    assert.deepEqual(fixture.store.readVerifiedHead(), {
      sequence: 1n,
      ledgerHash: event.resulting_ledger_hash
    });
    assert.equal(
      fixture.store
        .databaseForInternalUse()
        .prepare("SELECT COUNT(*) AS count FROM ledger_replica")
        .get().count,
      1
    );
  } finally {
    await fixture.cleanup();
  }
});

test("sync engine rejects bad ledger hashes before applying data", async () => {
  const fixture = await createStoreFixture();

  try {
    const engine = createEngine(fixture.store);
    const event = {
      ...makeSequencedEvent({ eventId: "evt_bad_hash", sequence: 1n, previousHash: genesisLedgerHash }),
      resulting_ledger_hash: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    };

    assert.throws(() => engine.applyPulledEvents([event]), (error) => {
      assert.equal(error instanceof SyncVerificationError, true);
      assert.equal(error.code, "BAD_LEDGER_HASH");
      return true;
    });
    assert.deepEqual(fixture.store.readVerifiedHead(), {
      sequence: 0n,
      ledgerHash: genesisLedgerHash
    });
  } finally {
    await fixture.cleanup();
  }
});

test("sync engine trips rollback audit on previous-hash mismatch", async () => {
  const fixture = await createStoreFixture();

  try {
    const engine = createEngine(fixture.store);
    engine.applyPulledEvents([
      makeSequencedEvent({ eventId: "evt_sync_head", sequence: 1n, previousHash: genesisLedgerHash })
    ]);

    assert.throws(
      () =>
        engine.applyPulledEvents([
          makeSequencedEvent({
            eventId: "evt_sync_rollback",
            sequence: 2n,
            previousHash: "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
          })
        ]),
      (error) => error instanceof SyncVerificationError && error.code === "ROLLBACK_DETECTED"
    );

    const audit = fixture.store
      .databaseForInternalUse()
      .prepare("SELECT category, body FROM local_audit ORDER BY id DESC LIMIT 1")
      .get();
    assert.equal(audit.category, "chain_verification");
    assert.match(audit.body, /previous hash/);
  } finally {
    await fixture.cleanup();
  }
});

test("sync engine verifies checkpoints against signatures and local ledger memory", async () => {
  const fixture = await createStoreFixture();

  try {
    const engine = createEngine(fixture.store);
    const event = makeSequencedEvent({ eventId: "evt_checkpoint", sequence: 1n, previousHash: genesisLedgerHash });
    engine.applyPulledEvents([event]);

    const checkpoint = signCheckpoint(
      {
        sequence: 1n,
        ledger_hash: event.resulting_ledger_hash,
        issued_at: "2026-07-05T00:00:05.000Z",
        key_version: 1
      },
      checkpointKeys.secretKey
    );
    engine.verifyAndStoreCheckpoint(checkpoint);

    assert.equal(fixture.store.readLedgerHashAt(1n), checkpoint.ledger_hash);
    assert.equal(
      fixture.store.databaseForInternalUse().prepare("SELECT COUNT(*) AS count FROM checkpoints").get().count,
      1
    );

    assert.throws(
      () =>
        engine.verifyAndStoreCheckpoint({
          ...checkpoint,
          signature: serverKeys.publicKey
        }),
      (error) => error instanceof SyncVerificationError && error.code === "BAD_CHECKPOINT_SIGNATURE"
    );
  } finally {
    await fixture.cleanup();
  }
});

test("sync engine applies only verified server acknowledgements to pending rows", async () => {
  const fixture = await createStoreFixture();

  try {
    const event = makeClientEvent({ eventId: "evt_pending_ack", counter: 1n });
    fixture.store.queuePendingEvent({
      event,
      envelopeBytes: Buffer.from("{}"),
      createdAt: "2026-07-05T00:00:00.000Z"
    });

    const engine = createEngine(fixture.store);
    const ack = signServerAck(
      {
        event_id: event.event_id,
        status: "accepted",
        server_sequence: 1n,
        resulting_ledger_hash: computeLedgerHash(genesisLedgerHash, 1n, event),
        server_timestamp: "2026-07-05T00:00:01.000Z",
        error_code: null
      },
      serverKeys.secretKey
    );
    engine.applyServerAck(ack);

    assert.equal(
      fixture.store
        .databaseForInternalUse()
        .prepare("SELECT submit_state FROM pending_events WHERE event_id = ?")
        .get(event.event_id).submit_state,
      "acked"
    );

    assert.throws(
      () => engine.applyServerAck({ ...ack, server_signature: checkpointKeys.publicKey }),
      (error) => error instanceof SyncVerificationError && error.code === "BAD_SERVER_SIGNATURE"
    );
  } finally {
    await fixture.cleanup();
  }
});

async function createStoreFixture() {
  const tempRoot = await mkdtemp(path.join(os.tmpdir(), "vorcaro-sync-"));
  const databaseKey = Buffer.alloc(32, 31);
  const store = LocalStore.open({
    databasePath: path.join(tempRoot, "local.db"),
    databaseKey
  });
  databaseKey.fill(0);

  return {
    store,
    async cleanup() {
      store.close();
      await rm(tempRoot, { recursive: true, force: true });
    }
  };
}

function createEngine(store) {
  return new SyncEngine({
    store,
    serverSigningPublicKey: serverKeys.publicKey,
    checkpointPublicKey: checkpointKeys.publicKey,
    now: () => "2026-07-05T00:00:10.000Z"
  });
}

function makeSequencedEvent({ eventId, sequence, previousHash }) {
  const event = makeClientEvent({ eventId, counter: sequence });
  const resultingLedgerHash = computeLedgerHash(previousHash, sequence, event);
  const ack = signServerAck(
    {
      event_id: event.event_id,
      status: "accepted",
      server_sequence: sequence,
      resulting_ledger_hash: resultingLedgerHash,
      server_timestamp: "2026-07-05T00:00:01.000Z",
      error_code: null
    },
    serverKeys.secretKey
  );

  return {
    ...event,
    server_sequence: sequence,
    previous_ledger_hash: previousHash,
    resulting_ledger_hash: resultingLedgerHash,
    server_signature: ack.server_signature,
    status: "accepted",
    error_code: null,
    server_timestamp: ack.server_timestamp,
    accepted_at: ack.server_timestamp
  };
}

function makeClientEvent({ eventId, counter }) {
  const payload = Buffer.from(`payload:${eventId}`).toString("base64");

  return signClientEvent(
    {
      event_id: eventId,
      event_type: "ACCOUNT_CREATED",
      actor_id: "exec_cfo",
      device_id: "dev_cfo",
      client_timestamp: "2026-07-05T00:00:00.000Z",
      base_server_sequence: counter - 1n,
      device_event_counter: counter,
      object_type: "account",
      object_id: `acct_${eventId}`,
      policy_metadata: {},
      payload_hash: payloadHash(payload),
      encrypted_payload: payload
    },
    clientKeys.secretKey
  );
}
