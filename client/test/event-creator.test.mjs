import assert from "node:assert/strict";
import { mkdtemp, rm } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { test } from "node:test";

import {
  deriveSigningKeyPair,
  policyDocumentSchema,
  payloadHash,
  verifyClientEventSignature
} from "@vorcaro/protocol";

import { createEventRequestSchema } from "../dist/main/ipc/contract.js";
import { EventCreator } from "../dist/main/main/event-creator.js";
import { LocalPolicyEngine } from "../dist/main/main/local-policy.js";
import { LocalStore } from "../dist/main/main/local-store.js";
import { VaultService } from "../dist/main/main/vault.js";

const passphrase = "correct horse battery staple";

test("event creator signs and queues a pending protocol envelope atomically", async () => {
  const fixture = await createUnlockedFixture();

  try {
    const signingSeed = fixture.vault.signingKeySeedForInternalUse();
    const publicKey = deriveSigningKeyPair(signingSeed).publicKey;
    signingSeed.fill(0);

    fixture.store.writeMeta("executive_id", "exec_ceo");
    fixture.store.writeMeta("device_id", "dev_macbook");
    fixture.store.writeMeta("executive_role", "CFO");

    const result = new EventCreator({
      store: fixture.store,
      vault: fixture.vault,
      now: () => "2026-07-05T00:00:00.000Z"
    }).createEvent({
      eventType: "TRANSACTION_RECORDED",
      objectType: "transaction",
      objectId: "txn_001",
      policyMetadata: {
        account_id: "acct_ops",
        entity_id: "ent_vorcaro",
        amount_minor_units: 125000n,
        currency: "USD",
        transaction_currency: "USD",
        exchange_rate: "1",
        default_currency_snapshot_id: "fx_2026_07_05",
        local_rate: 1n
      },
      payload: {
        account_id: "acct_ops",
        amount_minor_units: 125000,
        description: "Vendor invoice"
      }
    });

    assert.match(result.eventId, /^evt_/);
    assert.equal(result.deviceEventCounter, "1");
    assert.equal(result.baseServerSequence, "0");
    assert.equal(result.submitState, "queued");
    assert.deepEqual(result.localPolicy, { outcome: "not_configured" });

    const row = fixture.store
      .databaseForInternalUse()
      .prepare("SELECT event_id, device_event_counter, envelope, submit_state FROM pending_events")
      .get();
    assert.equal(row.event_id, result.eventId);
    assert.equal(row.device_event_counter, 1);
    assert.equal(row.submit_state, "queued");

    const event = parseQueuedEnvelope(row.envelope);
    assert.equal(event.actor_id, "exec_ceo");
    assert.equal(event.device_id, "dev_macbook");
    assert.equal(event.device_event_counter, 1n);
    assert.equal(event.base_server_sequence, 0n);
    assert.equal(event.payload_hash, payloadHash(event.encrypted_payload));
    assert.equal(verifyClientEventSignature(event, publicKey), true);
    assert.equal(fixture.store.readMeta("device_event_counter"), "1");
  } finally {
    await fixture.cleanup();
  }
});

test("event creator refuses to sign without enrollment identity metadata", async () => {
  const fixture = await createUnlockedFixture();

  try {
    assert.throws(
      () =>
        new EventCreator({ store: fixture.store, vault: fixture.vault }).createEvent({
          eventType: "ACCOUNT_CREATED",
          objectType: "account",
          objectId: "acct_missing_identity",
          policyMetadata: {},
          payload: { name: "Operating" }
        }),
      /Missing local metadata: executive_id/
    );
    assert.equal(fixture.store.readMeta("device_event_counter"), "0");
  } finally {
    await fixture.cleanup();
  }
});

test("event creator refuses to sign after the vault locks", async () => {
  const fixture = await createUnlockedFixture();

  try {
    fixture.store.writeMeta("executive_id", "exec_ceo");
    fixture.store.writeMeta("device_id", "dev_macbook");
    fixture.store.writeMeta("executive_role", "CFO");
    fixture.vault.lock();

    assert.throws(
      () =>
        new EventCreator({ store: fixture.store, vault: fixture.vault }).createEvent({
          eventType: "ACCOUNT_CREATED",
          objectType: "account",
          objectId: "acct_locked",
          policyMetadata: {},
          payload: { name: "Operating" }
        }),
      /Vault is locked/
    );
  } finally {
    await fixture.cleanup();
  }
});

test("event creator previews allow, deny, and approval-required policy outcomes", async () => {
  const fixture = await createUnlockedFixture();

  try {
    fixture.store.writeMeta("executive_id", "exec_cfo");
    fixture.store.writeMeta("device_id", "dev_cfo");
    fixture.store.writeMeta("executive_role", "CFO");
    const policy = makeActivePolicy({
      permissions: [
        {
          role: "CFO",
          object_type: "account",
          actions: ["create"],
          conditions: { currency: "USD", max_amount_minor_units: "100000" }
        }
      ],
      approval_rules: [
        {
          event_types: ["PAYMENT_REQUESTED"],
          threshold: { amount_minor_units: 50000n, currency: "USD" },
          required_roles: ["CEO", "CFO"],
          required_count: 2
        }
      ]
    });
    fixture.store.writeActivePolicy(policy);

    const allowed = createAccountEvent(fixture, "acct_allowed", 1000n);
    const denied = createAccountEvent(fixture, "acct_denied", 150000n);
    const approval = createPaymentEvent(fixture, "approval_payment", 75000n);

    assert.deepEqual(allowed.localPolicy, { outcome: "allow" });
    assert.deepEqual(denied.localPolicy, { outcome: "deny", errorCode: "POLICY_DENIED" });
    assert.deepEqual(approval.localPolicy, {
      outcome: "require_approvals",
      requiredRoles: ["CEO", "CFO"],
      requiredCount: 2,
      errorCode: "APPROVALS_REQUIRED"
    });
    assert.equal(fixture.store.readMeta("active_policy_version"), "1");
    assert.equal(fixture.store.readMeta("device_event_counter"), "3");
  } finally {
    await fixture.cleanup();
  }
});

test("event creator previews policy hash mismatch as a denial", async () => {
  const fixture = await createUnlockedFixture();

  try {
    fixture.store.writeMeta("executive_id", "exec_cfo");
    fixture.store.writeMeta("device_id", "dev_cfo");
    fixture.store.writeMeta("executive_role", "CFO");
    fixture.store.writeActivePolicy({
      ...makeActivePolicy({
        permissions: [
          {
            role: "CFO",
            object_type: "account",
            actions: ["create"]
          }
        ],
        approval_rules: []
      }),
      document_hash: "sha256:0000000000000000000000000000000000000000000000000000000000000000"
    });

    assert.deepEqual(createAccountEvent(fixture, "acct_bad_hash", 1000n).localPolicy, {
      outcome: "deny",
      errorCode: "POLICY_VERSION_MISMATCH"
    });
  } finally {
    await fixture.cleanup();
  }
});

test("create-event IPC schema accepts string integer policy metadata", () => {
  const parsed = createEventRequestSchema.parse({
    eventType: "TRANSACTION_RECORDED",
    objectType: "transaction",
    objectId: "txn_ipc",
    policyMetadata: {
      amount_minor_units: "900",
      transaction_currency: "USD",
      exchange_rate: "1",
      default_currency_snapshot_id: "fx_1",
      local_rate: "1"
    },
    payload: { amount_minor_units: 900 }
  });

  assert.equal(parsed.policyMetadata.amount_minor_units, "900");
});

async function createUnlockedFixture() {
  const tempRoot = await mkdtemp(path.join(os.tmpdir(), "vorcaro-event-creator-"));
  const vault = new VaultService({ headerPath: path.join(tempRoot, "profile", "header.json") });
  await vault.create(passphrase);

  const databaseKey = vault.localDatabaseKeyForInternalUse();
  const store = LocalStore.open({
    databasePath: path.join(tempRoot, "profile", "local.db"),
    databaseKey
  });
  databaseKey.fill(0);

  return {
    store,
    vault,
    async cleanup() {
      store.close();
      vault.lock();
      await rm(tempRoot, { recursive: true, force: true });
    }
  };
}

function parseQueuedEnvelope(envelope) {
  const parsed = JSON.parse(Buffer.from(envelope).toString("utf8"));
  return {
    ...parsed,
    base_server_sequence: BigInt(parsed.base_server_sequence),
    device_event_counter: BigInt(parsed.device_event_counter),
    policy_metadata: {
      ...parsed.policy_metadata,
      amount_minor_units:
        parsed.policy_metadata.amount_minor_units === undefined
          ? undefined
          : BigInt(parsed.policy_metadata.amount_minor_units),
      local_rate:
        parsed.policy_metadata.local_rate === undefined ? undefined : BigInt(parsed.policy_metadata.local_rate)
    }
  };
}

function createAccountEvent(fixture, objectId, amount) {
  return new EventCreator({
    store: fixture.store,
    vault: fixture.vault,
    now: () => "2026-07-05T00:00:00.000Z"
  }).createEvent({
    eventType: "ACCOUNT_CREATED",
    objectType: "account",
    objectId,
    policyMetadata: policyMetadata(objectId, amount),
    payload: { object_id: objectId, amount_minor_units: Number(amount) }
  });
}

function createPaymentEvent(fixture, objectId, amount) {
  return new EventCreator({
    store: fixture.store,
    vault: fixture.vault,
    now: () => "2026-07-05T00:00:00.000Z"
  }).createEvent({
    eventType: "PAYMENT_REQUESTED",
    objectType: "account",
    objectId,
    policyMetadata: policyMetadata(objectId, amount),
    payload: { object_id: objectId, amount_minor_units: Number(amount) }
  });
}

function policyMetadata(objectId, amount) {
  return {
    account_id: objectId,
    entity_id: "ent_vorcaro",
    amount_minor_units: amount,
    currency: "USD",
    transaction_currency: "USD",
    exchange_rate: "1",
    default_currency_snapshot_id: makeActivePolicy.defaultCurrencySnapshotId,
    local_rate: amount
  };
}

function makeActivePolicy(input) {
  const unsigned = {
    id: "policy_local",
    version: 1,
    default_currency: "USD",
    permissions: input.permissions,
    approval_rules: input.approval_rules,
    activated_at_sequence: 0n
  };
  const policy = policyDocumentSchema.parse({
    ...unsigned,
    document_hash: LocalPolicyEngine.documentHash(unsigned),
    signature: "AA=="
  });
  makeActivePolicy.defaultCurrencySnapshotId = LocalPolicyEngine.defaultCurrencySnapshot(policy).id;
  return policy;
}
