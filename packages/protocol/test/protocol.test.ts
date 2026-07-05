import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import test from "node:test";

import {
  canonicalEventBytes,
  computeLedgerHash,
  deriveSigningKeyPair,
  payloadHash,
  signCheckpoint,
  signClientEvent,
  signServerAck,
  verifyCheckpointSignature,
  verifyClientEventSignature,
  verifyServerAckSignature,
  type UnsignedClientEventEnvelope
} from "../src/index.js";

const fixtureEvent: UnsignedClientEventEnvelope = {
  event_id: "evt_01J00000000000000000000000",
  event_type: "PAYMENT_REQUESTED",
  actor_id: "exec_01J00000000000000000000000",
  device_id: "dev_01J00000000000000000000000",
  client_timestamp: "2026-07-01T14:23:11Z",
  base_server_sequence: 912388n,
  device_event_counter: 4471n,
  object_type: "approval",
  object_id: "apr_01J00000000000000000000000",
  policy_metadata: {
    account_id: "acct_01J0000000000000000000000",
    amount_minor_units: 125000n,
    currency: "USD",
    default_currency_snapshot_id: "ccysnap_01J000000000000000000",
    entity_id: "ent_01J00000000000000000000000",
    exchange_rate: "1",
    local_rate: 125000n,
    transaction_currency: "USD"
  },
  payload_hash: "sha256:9a5df3729917cba86db1a823bdedea240ac08fd1cdacb93ac8d987c09b49bb08",
  encrypted_payload: "Zml4dHVyZS1wYXlsb2Fk"
};

test("canonical event bytes match the pinned golden fixture", () => {
  const expected = readFileSync(
    join(import.meta.dirname, "../../test/fixtures/client-event-canonical.txt"),
    "utf8"
  ).trimEnd();

  assert.equal(canonicalEventBytes(fixtureEvent).toString("utf8"), expected);
});

test("client events, server acknowledgements, and checkpoints sign and verify", () => {
  const clientKeys = deriveSigningKeyPair(Buffer.alloc(32, 7));
  const serverKeys = deriveSigningKeyPair(Buffer.alloc(32, 9));
  const signedEvent = signClientEvent(fixtureEvent, clientKeys.secretKey);
  const ledgerHash = computeLedgerHash(
    "sha256:0000000000000000000000000000000000000000000000000000000000000000",
    912389n,
    signedEvent
  );
  const ack = signServerAck(
    {
      event_id: signedEvent.event_id,
      status: "accepted",
      server_sequence: 912389n,
      resulting_ledger_hash: ledgerHash,
      server_timestamp: "2026-07-01T14:23:12Z",
      error_code: null
    },
    serverKeys.secretKey
  );
  const checkpoint = signCheckpoint(
    {
      sequence: 912389n,
      ledger_hash: ledgerHash,
      issued_at: "2026-07-01T14:24:00Z",
      key_version: 1
    },
    serverKeys.secretKey
  );

  assert.equal(verifyClientEventSignature(signedEvent, clientKeys.publicKey), true);
  assert.equal(verifyServerAckSignature(ack, serverKeys.publicKey), true);
  assert.equal(verifyCheckpointSignature(checkpoint, serverKeys.publicKey), true);
});

test("payload hash is over encrypted payload bytes", () => {
  assert.equal(payloadHash(fixtureEvent.encrypted_payload), fixtureEvent.payload_hash);
});

test("monetary policy metadata requires exchange-rate audit fields", () => {
  const keys = deriveSigningKeyPair(Buffer.alloc(32, 13));

  assert.throws(() =>
    signClientEvent(
      {
        ...fixtureEvent,
        event_id: "evt_01J00000000000000000000001",
        policy_metadata: {
          account_id: "acct_01J0000000000000000000000",
          amount_minor_units: 125000n,
          currency: "USD"
        }
      },
      keys.secretKey
    )
  );
});

test("10k generated schema-valid events round-trip through serialize, sign, and verify", () => {
  const keys = deriveSigningKeyPair(Buffer.alloc(32, 11));

  for (let index = 1; index <= 10_000; index += 1) {
    const payload = Buffer.from(`encrypted-payload-${index}`).toString("base64");
    const event: UnsignedClientEventEnvelope = {
      event_id: `evt_${index.toString().padStart(26, "0")}`,
      event_type: index % 2 === 0 ? "TRANSACTION_RECORDED" : "PAYMENT_REQUESTED",
      actor_id: "exec_01J00000000000000000000000",
      device_id: "dev_01J00000000000000000000000",
      client_timestamp: "2026-07-01T14:23:11Z",
      base_server_sequence: BigInt(index - 1),
      device_event_counter: BigInt(index),
      object_type: index % 2 === 0 ? "transaction" : "approval",
      object_id: `${index % 2 === 0 ? "txn" : "apr"}_${index.toString().padStart(26, "0")}`,
      policy_metadata: {
        account_id: "acct_01J0000000000000000000000",
        amount_minor_units: BigInt(index * 100),
        currency: "USD",
        default_currency_snapshot_id: "ccysnap_01J000000000000000000",
        exchange_rate: "1",
        local_rate: BigInt(index * 100),
        transaction_currency: "USD"
      },
      payload_hash: payloadHash(payload),
      encrypted_payload: payload
    };

    const signed = signClientEvent(event, keys.secretKey);
    assert.equal(verifyClientEventSignature(signed, keys.publicKey), true);
  }
});
