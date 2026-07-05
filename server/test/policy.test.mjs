import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import {
  deriveSigningKeyPair,
  payloadHash,
  signClientEvent
} from "@vorcaro/protocol";

import {
  LedgerAppender,
  PolicyEngine,
  PolicyError,
  PolicyService,
  openLedgerDatabase
} from "../dist/index.js";

const cfoKeys = deriveSigningKeyPair(Buffer.alloc(32, 61));
const cooKeys = deriveSigningKeyPair(Buffer.alloc(32, 62));
const serverKeys = deriveSigningKeyPair(Buffer.alloc(32, 63));

test("policy engine allows, denies, and requires approvals from a versioned document", () => {
  const policy = makePolicy({
    id: "policy_eval",
    version: 1,
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

  assert.deepEqual(
    PolicyEngine.evaluate(
      policy,
      makeEvent({ eventId: "evt_policy_allow", counter: 1n, actorId: "exec_cfo", deviceId: "dev_cfo" }),
      { actorRole: "CFO", riskScore: 10 }
    ),
    { outcome: "allow" }
  );
  assert.deepEqual(
    PolicyEngine.evaluate(
      policy,
      makeEvent({ eventId: "evt_policy_deny", counter: 1n, actorId: "exec_coo", deviceId: "dev_coo" }),
      { actorRole: "COO", riskScore: 10 }
    ),
    { outcome: "deny", errorCode: "POLICY_DENIED" }
  );
  assert.deepEqual(
    PolicyEngine.evaluate(
      policy,
      makeEvent({
        eventId: "evt_policy_approval",
        eventType: "PAYMENT_REQUESTED",
        objectType: "account",
        objectId: "acct_policy",
        counter: 2n,
        actorId: "exec_cfo",
        deviceId: "dev_cfo",
        amount: 75000n
      }),
      { actorRole: "CFO", riskScore: 10 }
    ),
    {
      outcome: "require_approvals",
      requiredRoles: ["CEO", "CFO"],
      requiredCount: 2,
      errorCode: "APPROVALS_REQUIRED"
    }
  );
});

test("policy service activates only after a signed POLICY_CHANGED event is accepted", async () => {
  const { database, appender, cleanup } = createPolicyFixture();

  try {
    const policy = makePolicy({
      id: "policy_activation",
      version: 1,
      permissions: [
        {
          role: "CFO",
          object_type: "policy",
          actions: ["create"]
        },
        {
          role: "CFO",
          object_type: "account",
          actions: ["create"]
        }
      ],
      approval_rules: []
    });
    const service = new PolicyService({
      database,
      appender,
      now: () => "2026-07-01T16:00:00.000Z"
    });
    const result = await service.activatePolicy({
      policy,
      activationEvent: makeEvent({
        eventId: "evt_policy_changed",
        eventType: "POLICY_CHANGED",
        objectType: "policy",
        objectId: "policy_activation",
        counter: 1n,
        actorId: "exec_cfo",
        deviceId: "dev_cfo"
      }),
      certificateFingerprint: "fingerprint-cfo",
      activatedBy: "exec_cfo"
    });
    const row = database.prepare("SELECT version, activated_at_sequence FROM policies WHERE id = ?").get("policy_activation");
    const audit = database.prepare("SELECT category, detail FROM audit_log ORDER BY id DESC LIMIT 1").get();

    assert.equal(result.acknowledgement.status, "accepted");
    assert.equal(result.policy.activated_at_sequence, 1n);
    assert.deepEqual({ ...row }, { version: 1, activated_at_sequence: 1 });
    assert.equal(audit.category, "admin");
    assert.equal(JSON.parse(audit.detail).event, "policy_activated");
    assert.equal(service.activePolicy().id, "policy_activation");

    await assert.rejects(
      () =>
        service.activatePolicy({
          policy: {
            ...policy,
            version: 2,
            document_hash: "sha256:0000000000000000000000000000000000000000000000000000000000000000"
          },
          activationEvent: makeEvent({
            eventId: "evt_policy_bad_hash",
            eventType: "POLICY_CHANGED",
            objectType: "policy",
            objectId: "policy_activation",
            counter: 2n,
            actorId: "exec_cfo",
            deviceId: "dev_cfo",
            baseServerSequence: 1n
          }),
          certificateFingerprint: "fingerprint-cfo",
          activatedBy: "exec_cfo"
        }),
      (error) => error instanceof PolicyError && error.errorCode === "POLICY_VERSION_MISMATCH"
    );
  } finally {
    database.close();
    cleanup();
  }
});

test("ledger appender consults active policy before conflict handling", async () => {
  const { database, appender, cleanup } = createPolicyFixture();

  try {
    const policy = makePolicy({
      id: "policy_appender",
      version: 1,
      permissions: [
        {
          role: "CFO",
          object_type: "account",
          actions: ["create"]
        }
      ],
      approval_rules: [
        {
          event_types: ["ACCOUNT_CREATED"],
          threshold: { amount_minor_units: 5000n, currency: "USD" },
          required_roles: ["CEO", "CFO"],
          required_count: 2
        }
      ]
    });
    insertActivePolicy(database, policy);

    const pending = await appender.append({
      event: makeEvent({
        eventId: "evt_policy_pending",
        counter: 1n,
        actorId: "exec_cfo",
        deviceId: "dev_cfo",
        amount: 7000n
      }),
      certificateFingerprint: "fingerprint-cfo"
    });
    const denied = await appender.append({
      event: makeEvent({
        eventId: "evt_policy_denied",
        counter: 1n,
        actorId: "exec_coo",
        deviceId: "dev_coo"
      }),
      certificateFingerprint: "fingerprint-coo"
    });
    const rows = database
      .prepare("SELECT id, status, error_code FROM ledger_events ORDER BY server_sequence")
      .all();

    assert.equal(pending.status, "pending");
    assert.equal(pending.error_code, "APPROVALS_REQUIRED");
    assert.equal(denied.status, "rejected");
    assert.equal(denied.error_code, "POLICY_DENIED");
    assert.deepEqual(
      rows.map((row) => [row.id, row.status, row.error_code]),
      [
        ["evt_policy_pending", "pending", "APPROVALS_REQUIRED"],
        ["evt_policy_denied", "rejected", "POLICY_DENIED"]
      ]
    );
  } finally {
    database.close();
    cleanup();
  }
});

function createPolicyFixture() {
  const directory = mkdtempSync(join(tmpdir(), "vorcaro-policy-"));
  const database = openLedgerDatabase({ path: join(directory, "ledger.db") });
  seedExecutive(database, "exec_cfo", "Vorcaro CFO", "CFO", cfoKeys.publicKey);
  seedExecutive(database, "exec_coo", "Vorcaro COO", "COO", cooKeys.publicKey);
  seedDevice(database, "dev_cfo", "exec_cfo", "fingerprint-cfo");
  seedDevice(database, "dev_coo", "exec_coo", "fingerprint-coo");

  return {
    database,
    appender: LedgerAppender.create({
      database,
      serverSigningSecretKey: serverKeys.secretKey,
      now: sequentialClock("2026-07-01T15:00:00.000Z")
    }),
    cleanup: () => rmSync(directory, { recursive: true, force: true })
  };
}

function seedExecutive(database, id, displayName, role, publicKey) {
  database
    .prepare(
      `INSERT INTO executives (
        id, display_name, role, status, signing_public_key, key_version, created_at
      ) VALUES (?, ?, ?, 'active', ?, 1, ?)`
    )
    .run(id, displayName, role, publicKey, "2026-07-01T14:00:00.000Z");
  database
    .prepare(
      `INSERT INTO executive_keys (
        executive_id, key_version, signing_public_key, valid_from_sequence, valid_until_sequence
      ) VALUES (?, 1, ?, 0, NULL)`
    )
    .run(id, publicKey);
}

function seedDevice(database, id, executiveId, fingerprint) {
  database
    .prepare(
      `INSERT INTO devices (
        id, executive_id, certificate_fingerprint, public_key, status,
        hardware_backed, enrolled_at, risk_score, max_event_counter
      ) VALUES (?, ?, ?, ?, 'enrolled', 1, ?, 0, 0)`
    )
    .run(id, executiveId, fingerprint, "device-public-key", "2026-07-01T14:00:00.000Z");
}

function makePolicy(input) {
  const unsigned = {
    id: input.id,
    version: input.version,
    permissions: input.permissions,
    approval_rules: input.approval_rules,
    activated_at_sequence: null
  };

  return {
    ...unsigned,
    document_hash: PolicyEngine.documentHash(unsigned),
    signature: "AA=="
  };
}

function insertActivePolicy(database, policy) {
  database
    .prepare(
      `INSERT INTO policies (
        id, version, document, document_hash, activated_at_sequence
      ) VALUES (?, ?, ?, ?, ?)`
    )
    .run(
      policy.id,
      policy.version,
      PolicyEngine.serializePolicyDocument({
        ...policy,
        activated_at_sequence: 0n
      }),
      policy.document_hash,
      0
    );
}

function makeEvent(options) {
  const payload = Buffer.from(`payload:${options.eventId}`).toString("base64");
  const actorId = options.actorId ?? "exec_cfo";
  const secretKey = actorId === "exec_coo" ? cooKeys.secretKey : cfoKeys.secretKey;

  return signClientEvent(
    {
      event_id: options.eventId,
      event_type: options.eventType ?? "ACCOUNT_CREATED",
      actor_id: actorId,
      device_id: options.deviceId ?? "dev_cfo",
      client_timestamp: "2026-07-01T15:00:00.000Z",
      base_server_sequence: options.baseServerSequence ?? 0n,
      device_event_counter: options.counter,
      object_type: options.objectType ?? "account",
      object_id: options.objectId ?? `acct_${options.eventId}`,
      policy_metadata:
        options.objectType === "policy"
          ? {}
          : {
              account_id: options.objectId ?? `acct_${options.eventId}`,
              entity_id: "ent_1",
              amount_minor_units: options.amount ?? 1000n,
              currency: "USD"
            },
      payload_hash: payloadHash(payload),
      encrypted_payload: payload
    },
    secretKey
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
