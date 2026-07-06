import assert from "node:assert/strict";
import { mkdtemp, rm } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { test } from "node:test";

import {
  canonicalBytes,
  computeLedgerHash,
  deriveSigningKeyPair,
  payloadHash,
  policyDocumentSchema,
  signBytes,
  signCheckpoint,
  signClientEvent,
  signServerAck
} from "@vorcaro/protocol";

import { LocalPolicyEngine } from "../dist/main/main/local-policy.js";
import { LocalStore } from "../dist/main/main/local-store.js";
import { SyncEngine } from "../dist/main/main/sync-engine.js";
import { SyncSession, SyncSessionError } from "../dist/main/main/sync-session.js";

const clientKeys = deriveSigningKeyPair(Buffer.alloc(32, 51));
const serverKeys = deriveSigningKeyPair(Buffer.alloc(32, 52));
const checkpointKeys = deriveSigningKeyPair(Buffer.alloc(32, 53));
const genesisLedgerHash = "sha256:0000000000000000000000000000000000000000000000000000000000000000";

test("sync session verifies state, pulls data, stores policy, and pushes pending events", async () => {
  const fixture = await createStoreFixture();

  try {
    const pending = makeClientEvent({ eventId: "evt_push_pending", counter: 1n });
    fixture.store.queuePendingEvent({
      event: pending,
      envelopeBytes: canonicalBytes(pending),
      createdAt: "2026-07-05T00:00:00.000Z"
    });

    const pulled = makeSequencedEvent({
      eventId: "evt_pulled",
      sequence: 1n,
      previousHash: genesisLedgerHash
    });
    const checkpoint = signCheckpoint(
      {
        sequence: 1n,
        ledger_hash: pulled.resulting_ledger_hash,
        issued_at: "2026-07-05T00:00:02.000Z",
        key_version: 1
      },
      checkpointKeys.secretKey
    );
    const policy = makeActivePolicy();
    const calls = [];
    const transport = {
      async getState() {
        calls.push("state");
        return signResponse({
          latest_sequence: 1n,
          latest_ledger_hash: pulled.resulting_ledger_hash,
          latest_checkpoint: null,
          revocation_list_version: 0,
          active_policy_version: 1,
          server_timestamp: "2026-07-05T00:00:03.000Z"
        });
      },
      async getCheckpoints(after) {
        calls.push(`checkpoints:${after.toString(10)}`);
        return signResponse({
          after,
          checkpoints: [checkpoint],
          server_timestamp: "2026-07-05T00:00:04.000Z"
        });
      },
      async getEvents(afterSequence) {
        calls.push(`events:${afterSequence.toString(10)}`);
        return signResponse({
          after_seq: afterSequence,
          events: [pulled],
          server_timestamp: "2026-07-05T00:00:05.000Z"
        });
      },
      async getActivePolicy() {
        calls.push("policy");
        return signResponse({
          policy,
          server_timestamp: "2026-07-05T00:00:06.000Z"
        });
      },
      async pushEvents(events) {
        calls.push(`push:${events.length}`);
        assert.equal(events[0].event_id, pending.event_id);
        return signServerAck(
          {
            event_id: pending.event_id,
            status: "accepted",
            server_sequence: 2n,
            resulting_ledger_hash: computeLedgerHash(pulled.resulting_ledger_hash, 2n, pending),
            server_timestamp: "2026-07-05T00:00:07.000Z",
            error_code: null
          },
          serverKeys.secretKey
        );
      }
    };

    const result = await createSession(fixture.store, transport).runOnce();

    assert.deepEqual(result.states, ["connecting", "verifying", "pulling", "pushing", "idle"]);
    assert.deepEqual(calls, ["state", "checkpoints:0", "policy", "events:0", "push:1"]);
    assert.equal(result.pulledEvents, 1);
    assert.equal(result.pushedEvents, 1);
    assert.deepEqual(fixture.store.readVerifiedHead(), {
      sequence: 1n,
      ledgerHash: pulled.resulting_ledger_hash
    });
    assert.equal(fixture.store.readMeta("active_policy_version"), "1");
    assert.equal(
      fixture.store
        .databaseForInternalUse()
        .prepare("SELECT submit_state FROM pending_events WHERE event_id = ?")
        .get(pending.event_id).submit_state,
      "acked"
    );
  } finally {
    await fixture.cleanup();
  }
});

test("sync session rejects unsigned state before pulling or pushing", async () => {
  const fixture = await createStoreFixture();

  try {
    let pulled = false;
    const transport = {
      async getState() {
        return {
          ...signResponse({
            latest_sequence: 0n,
            latest_ledger_hash: genesisLedgerHash,
            latest_checkpoint: null,
            revocation_list_version: 0,
            active_policy_version: 0,
            server_timestamp: "2026-07-05T00:00:03.000Z"
          }),
          signature: checkpointKeys.publicKey
        };
      },
      async getCheckpoints() {
        pulled = true;
        throw new Error("should not fetch checkpoints");
      },
      async getEvents() {
        pulled = true;
        throw new Error("should not pull events");
      },
      async getActivePolicy() {
        pulled = true;
        throw new Error("should not fetch policy");
      },
      async pushEvents() {
        pulled = true;
        throw new Error("should not push events");
      }
    };

    await assert.rejects(
      () => createSession(fixture.store, transport).runOnce(),
      (error) => error instanceof SyncSessionError && error.code === "BAD_RESPONSE_SIGNATURE"
    );
    assert.equal(pulled, false);
    assert.deepEqual(fixture.store.readVerifiedHead(), {
      sequence: 0n,
      ledgerHash: genesisLedgerHash
    });
  } finally {
    await fixture.cleanup();
  }
});

async function createStoreFixture() {
  const tempRoot = await mkdtemp(path.join(os.tmpdir(), "vorcaro-sync-session-"));
  const databaseKey = Buffer.alloc(32, 33);
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

function createSession(store, transport) {
  return new SyncSession({
    store,
    engine: new SyncEngine({
      store,
      serverSigningPublicKey: serverKeys.publicKey,
      checkpointPublicKey: checkpointKeys.publicKey,
      now: () => "2026-07-05T00:00:10.000Z"
    }),
    transport,
    serverSigningPublicKey: serverKeys.publicKey
  });
}

function signResponse(body) {
  return {
    ...body,
    signature: signBytes(canonicalBytes(body), serverKeys.secretKey)
  };
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

function makeActivePolicy() {
  const unsigned = {
    id: "policy_sync_session",
    version: 1,
    default_currency: "USD",
    permissions: [
      {
        role: "CFO",
        object_type: "account",
        actions: ["create"]
      }
    ],
    approval_rules: [],
    activated_at_sequence: 0n
  };

  return policyDocumentSchema.parse({
    ...unsigned,
    document_hash: LocalPolicyEngine.documentHash(unsigned),
    signature: "AA=="
  });
}
