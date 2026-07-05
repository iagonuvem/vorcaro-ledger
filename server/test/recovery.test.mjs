import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import {
  deriveSigningKeyPair,
  payloadHash,
  signBytes,
  signClientEvent,
  verifyServerAckSignature
} from "@vorcaro/protocol";

import {
  LocalKeyManagementService,
  RecoveryError,
  RecoveryService,
  openLedgerDatabase
} from "../dist/index.js";

const targetKeysV1 = deriveSigningKeyPair(Buffer.alloc(32, 51));
const targetKeysV2 = deriveSigningKeyPair(Buffer.alloc(32, 52));
const custodianOneKeys = deriveSigningKeyPair(Buffer.alloc(32, 53));
const custodianTwoKeys = deriveSigningKeyPair(Buffer.alloc(32, 54));
const custodianThreeKeys = deriveSigningKeyPair(Buffer.alloc(32, 55));
const executorKeys = deriveSigningKeyPair(Buffer.alloc(32, 56));
const serverKeys = deriveSigningKeyPair(Buffer.alloc(32, 57));

test("local KMS wraps, unwraps, rewraps, and signs by handle", () => {
  const kms = new LocalKeyManagementService({
    wrappingKeys: new Map([
      ["old", Buffer.alloc(32, 1)],
      ["new", Buffer.alloc(32, 2)]
    ]),
    signingKeys: new Map([["server", serverKeys.secretKey]])
  });
  const dataKey = Buffer.from("0123456789abcdef0123456789abcdef", "utf8");
  const wrapped = kms.wrapKey({ keyHandle: "old", plaintextKey: dataKey });
  const rewrapped = kms.rewrapKey({ unwrapKeyHandle: "old", wrapKeyHandle: "new", wrappedKey: wrapped });

  assert.notDeepEqual(wrapped, dataKey);
  assert.deepEqual(kms.unwrapKey({ keyHandle: "old", wrappedKey: wrapped }), dataKey);
  assert.deepEqual(kms.unwrapKey({ keyHandle: "new", wrappedKey: rewrapped }), dataKey);
  assert.equal(
    verifyServerAckSignature(
      {
        event_id: "evt_kms_sign",
        status: "accepted",
        server_sequence: 1n,
        resulting_ledger_hash: "sha256:1111111111111111111111111111111111111111111111111111111111111111",
        server_timestamp: "2026-07-01T14:00:00.000Z",
        error_code: null,
        server_signature: kms.signWithKey({
          keyHandle: "server",
          bytes: Buffer.from(
            '{"error_code":null,"event_id":"evt_kms_sign","resulting_ledger_hash":"sha256:1111111111111111111111111111111111111111111111111111111111111111","server_sequence":1,"server_timestamp":"2026-07-01T14:00:00.000Z","status":"accepted"}',
            "utf8"
          )
        })
      },
      serverKeys.publicKey
    ),
    true
  );
});

test("recovery ceremony verifies threshold approvals, rewraps keys, rotates executive key, and appends evidence", () => {
  const { database, recovery, kms, cleanup } = createRecoveryFixture();

  try {
    const ceremony = recovery.initiateCeremony({
      ceremonyId: "ceremony_1",
      executiveId: "exec_target",
      initiatedBy: "custodian_1",
      newPublicKey: targetKeysV2.publicKey
    });
    const targetAfterInitiate = database
      .prepare("SELECT status FROM executives WHERE id = ?")
      .get("exec_target");
    const targetDeviceAfterInitiate = database
      .prepare("SELECT status FROM devices WHERE id = ?")
      .get("dev_target");

    assert.equal(ceremony.status, "open");
    assert.equal(targetAfterInitiate.status, "quarantined");
    assert.equal(targetDeviceAfterInitiate.status, "quarantined");

    assert.throws(
      () =>
        recovery.approveCeremony({
          ceremonyId: "ceremony_1",
          approverId: "custodian_2",
          approvalSignature: signApproval("ceremony_1", "exec_target", targetKeysV2.publicKey, custodianThreeKeys.secretKey)
        }),
      (error) => error instanceof RecoveryError && error.errorCode === "BAD_SIGNATURE"
    );

    const firstApproval = recovery.approveCeremony({
      ceremonyId: "ceremony_1",
      approverId: "custodian_1",
      approvalSignature: signApproval("ceremony_1", "exec_target", targetKeysV2.publicKey, custodianOneKeys.secretKey)
    });
    const threshold = recovery.approveCeremony({
      ceremonyId: "ceremony_1",
      approverId: "custodian_2",
      approvalSignature: signApproval("ceremony_1", "exec_target", targetKeysV2.publicKey, custodianTwoKeys.secretKey)
    });

    assert.equal(firstApproval.status, "open");
    assert.equal(threshold.status, "threshold_met");
    assert.equal(threshold.approvals.length, 2);

    const result = recovery.executeCeremony({
      ceremonyId: "ceremony_1",
      executedBy: "exec_recovery",
      executorDeviceId: "dev_recovery",
      recoveryPerformedEvent: makeRecoveryEvent({
        eventId: "evt_recovery_performed",
        eventType: "RECOVERY_PERFORMED",
        objectId: "ceremony_1",
        counter: 1n
      }),
      keyRotatedEvent: makeRecoveryEvent({
        eventId: "evt_key_rotated",
        eventType: "KEY_ROTATED",
        objectId: RecoveryService.rotatedKeyObjectId("exec_target", 2),
        counter: 2n,
        baseServerSequence: 1n
      })
    });
    const oldKey = database
      .prepare("SELECT valid_until_sequence FROM executive_keys WHERE executive_id = ? AND key_version = ?")
      .get("exec_target", 1);
    const newKey = database
      .prepare("SELECT signing_public_key, valid_from_sequence FROM executive_keys WHERE executive_id = ? AND key_version = ?")
      .get("exec_target", 2);
    const targetAfterExecute = database
      .prepare("SELECT status, signing_public_key, key_version FROM executives WHERE id = ?")
      .get("exec_target");
    const packages = database
      .prepare("SELECT id, key_version, wrapped_data_key, recovery_wrapped_key, status FROM key_packages WHERE executive_id = ? ORDER BY key_version")
      .all("exec_target");
    const events = database
      .prepare("SELECT id, event_type, status, server_sequence FROM ledger_events ORDER BY server_sequence")
      .all();
    const auditCount = database
      .prepare("SELECT COUNT(*) AS count FROM audit_log WHERE category = 'recovery'")
      .get();
    const rewrappedPackage = packages.find((row) => row.key_version === 2);

    assert.equal(result.ceremony.status, "executed");
    assert.equal(result.newKeyVersion, 2);
    assert.deepEqual(result.rewrappedKeyPackageIds, [RecoveryService.rewrappedKeyPackageId("kp_original", 2)]);
    assert.equal(result.acknowledgements.length, 2);
    assert.equal(verifyServerAckSignature(result.acknowledgements[0], serverKeys.publicKey), true);
    assert.equal(verifyServerAckSignature(result.acknowledgements[1], serverKeys.publicKey), true);
    assert.equal(oldKey.valid_until_sequence, 0);
    assert.equal(newKey.signing_public_key, targetKeysV2.publicKey);
    assert.equal(newKey.valid_from_sequence, 0);
    assert.deepEqual({ ...targetAfterExecute }, {
      status: "active",
      signing_public_key: targetKeysV2.publicKey,
      key_version: 2
    });
    assert.equal(packages[0].status, "revoked");
    assert.equal(rewrappedPackage.status, "active");
    assert.deepEqual(
      kms.unwrapKey({
        keyHandle: RecoveryService.executiveWrapKeyHandle("exec_target", 2),
        wrappedKey: rewrappedPackage.wrapped_data_key
      }),
      Buffer.from("0123456789abcdef0123456789abcdef", "utf8")
    );
    assert.deepEqual(
      events.map((row) => [row.id, row.event_type, row.status, row.server_sequence]),
      [
        ["evt_recovery_performed", "RECOVERY_PERFORMED", "accepted", 1],
        ["evt_key_rotated", "KEY_ROTATED", "accepted", 2]
      ]
    );
    assert.ok(auditCount.count >= 4);
  } finally {
    database.close();
    cleanup();
  }
});

function createRecoveryFixture() {
  const directory = mkdtempSync(join(tmpdir(), "vorcaro-recovery-"));
  const database = openLedgerDatabase({ path: join(directory, "ledger.db") });
  const kms = new LocalKeyManagementService({
    wrappingKeys: new Map([
      ["recovery-master", Buffer.alloc(32, 9)],
      [RecoveryService.executiveWrapKeyHandle("exec_target", 1), Buffer.alloc(32, 10)],
      [RecoveryService.executiveWrapKeyHandle("exec_target", 2), Buffer.alloc(32, 11)]
    ]),
    signingKeys: new Map([["server-ledger", serverKeys.secretKey]])
  });
  const dataKey = Buffer.from("0123456789abcdef0123456789abcdef", "utf8");
  seedExecutive(database, {
    id: "exec_target",
    displayName: "Target CFO",
    role: "CFO",
    status: "active",
    keyVersion: 1,
    publicKey: targetKeysV1.publicKey
  });
  seedExecutive(database, {
    id: "custodian_1",
    displayName: "Custodian One",
    role: "SECURITY_RECOVERY_OFFICER",
    status: "active",
    keyVersion: 1,
    publicKey: custodianOneKeys.publicKey
  });
  seedExecutive(database, {
    id: "custodian_2",
    displayName: "Custodian Two",
    role: "SECURITY_RECOVERY_OFFICER",
    status: "active",
    keyVersion: 1,
    publicKey: custodianTwoKeys.publicKey
  });
  seedExecutive(database, {
    id: "custodian_3",
    displayName: "Custodian Three",
    role: "SECURITY_RECOVERY_OFFICER",
    status: "active",
    keyVersion: 1,
    publicKey: custodianThreeKeys.publicKey
  });
  seedExecutive(database, {
    id: "exec_recovery",
    displayName: "Recovery Officer",
    role: "SECURITY_RECOVERY_OFFICER",
    status: "active",
    keyVersion: 1,
    publicKey: executorKeys.publicKey
  });
  seedDevice(database, "dev_target", "exec_target");
  seedDevice(database, "dev_recovery", "exec_recovery");
  database
    .prepare(
      `INSERT INTO key_packages (
        id, executive_id, key_version, wrapped_data_key,
        recovery_wrapped_key, status, created_at, revoked_at
      ) VALUES (?, ?, ?, ?, ?, 'active', ?, NULL)`
    )
    .run(
      "kp_original",
      "exec_target",
      1,
      kms.wrapKey({
        keyHandle: RecoveryService.executiveWrapKeyHandle("exec_target", 1),
        plaintextKey: dataKey
      }),
      kms.wrapKey({
        keyHandle: "recovery-master",
        plaintextKey: dataKey
      }),
      "2026-07-01T14:00:00.000Z"
    );
  const recovery = new RecoveryService({
    database,
    kms,
    serverSigningKeyHandle: "server-ledger",
    recoveryMasterKeyHandle: "recovery-master",
    policy: {
      requiredApprovals: 2,
      custodianIds: ["custodian_1", "custodian_2", "custodian_3"]
    },
    now: sequentialClock("2026-07-01T14:23:12.000Z")
  });

  return {
    database,
    recovery,
    kms,
    cleanup: () => rmSync(directory, { recursive: true, force: true })
  };
}

function seedExecutive(database, input) {
  database
    .prepare(
      `INSERT INTO executives (
        id, display_name, role, status, signing_public_key, key_version, created_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?)`
    )
    .run(input.id, input.displayName, input.role, input.status, input.publicKey, input.keyVersion, "2026-07-01T14:00:00.000Z");
  database
    .prepare(
      `INSERT INTO executive_keys (
        executive_id, key_version, signing_public_key,
        valid_from_sequence, valid_until_sequence
      ) VALUES (?, ?, ?, 0, NULL)`
    )
    .run(input.id, input.keyVersion, input.publicKey);
}

function seedDevice(database, deviceId, executiveId) {
  database
    .prepare(
      `INSERT INTO devices (
        id, executive_id, certificate_fingerprint, public_key, status,
        hardware_backed, enrolled_at, risk_score, max_event_counter
      ) VALUES (?, ?, ?, ?, 'enrolled', 1, ?, 0, 0)`
    )
    .run(deviceId, executiveId, `fingerprint-${deviceId}`, "device-public-key", "2026-07-01T14:00:00.000Z");
}

function signApproval(ceremonyId, executiveId, newPublicKey, secretKey) {
  return signBytes(
    RecoveryService.approvalBytes(ceremonyId, executiveId, newPublicKey),
    secretKey
  );
}

function makeRecoveryEvent(options) {
  const payload = Buffer.from(`payload:${options.eventId}`).toString("base64");

  return signClientEvent(
    {
      event_id: options.eventId,
      event_type: options.eventType,
      actor_id: "exec_recovery",
      device_id: "dev_recovery",
      client_timestamp: "2026-07-01T14:23:11.000Z",
      base_server_sequence: options.baseServerSequence ?? 0n,
      device_event_counter: options.counter,
      object_type: "executive_key",
      object_id: options.objectId,
      policy_metadata: {},
      payload_hash: payloadHash(payload),
      encrypted_payload: payload
    },
    executorKeys.secretKey
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
