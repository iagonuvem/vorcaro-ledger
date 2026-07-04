import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import {
  canonicalBytes,
  deriveSigningKeyPair,
  payloadHash,
  signBytes,
  signClientEvent,
  verifyBytes,
  verifyServerAckSignature
} from "@vorcaro/protocol";

import {
  LocalCertificateAuthority,
  PkiError,
  PkiService,
  hashEnrollmentToken,
  openLedgerDatabase
} from "../dist/index.js";

const executiveKeys = deriveSigningKeyPair(Buffer.alloc(32, 41));
const deviceKeys = deriveSigningKeyPair(Buffer.alloc(32, 42));
const serverKeys = deriveSigningKeyPair(Buffer.alloc(32, 43));

test("enrollment stores only token hash, verifies device proof, issues cert, and appends DEVICE_ENROLLED", () => {
  const { database, pki, cleanup } = createPkiFixture();

  try {
    const token = pki.issueEnrollmentToken({
      executiveId: "exec_1",
      issuedBy: "admin_1",
      expiresAt: "2026-07-01T16:00:00.000Z",
      token: "one-time-token"
    });
    const tokenRow = database.prepare("SELECT token_hash FROM enrollment_tokens").get();
    const challenge = pki.beginEnrollment({
      token: token.token,
      deviceId: "dev_new",
      publicKey: deviceKeys.publicKey
    });
    const proofSignature = signBytes(enrollmentProofBytes(challenge, "dev_new", deviceKeys.publicKey), deviceKeys.secretKey);
    const enrollmentEvent = makeEnrollmentEvent({
      eventId: "evt_device_enrolled",
      deviceId: "dev_new"
    });
    const result = pki.completeEnrollment({
      token: token.token,
      challengeId: challenge.challengeId,
      proofSignature,
      hardwareBacked: true,
      enrollmentEvent
    });
    const device = database
      .prepare("SELECT id, status, certificate_fingerprint, hardware_backed, max_event_counter FROM devices WHERE id = ?")
      .get("dev_new");
    const event = database
      .prepare("SELECT event_type, status, server_sequence FROM ledger_events WHERE id = ?")
      .get("evt_device_enrolled");

    assert.equal(tokenRow.token_hash, hashEnrollmentToken("one-time-token"));
    assert.equal(result.certificate.certificateFingerprint.length, 64);
    assert.equal(verifyServerAckSignature(result.acknowledgement, serverKeys.publicKey), true);
    assert.equal(device.id, "dev_new");
    assert.equal(device.status, "enrolled");
    assert.equal(device.certificate_fingerprint, result.certificate.certificateFingerprint);
    assert.equal(device.hardware_backed, 1);
    assert.equal(device.max_event_counter, 1);
    assert.equal(event.event_type, "DEVICE_ENROLLED");
    assert.equal(event.status, "accepted");
    assert.equal(event.server_sequence, 1);
  } finally {
    database.close();
    cleanup();
  }
});

test("enrollment token is one-time and bad proof signatures are rejected", () => {
  const { database, pki, cleanup } = createPkiFixture();

  try {
    const issued = pki.issueEnrollmentToken({
      executiveId: "exec_1",
      issuedBy: "admin_1",
      expiresAt: "2026-07-01T16:00:00.000Z",
      token: "bad-proof-token"
    });
    const challenge = pki.beginEnrollment({
      token: issued.token,
      deviceId: "dev_bad",
      publicKey: deviceKeys.publicKey
    });

    assert.throws(
      () =>
        pki.completeEnrollment({
          token: issued.token,
          challengeId: challenge.challengeId,
          proofSignature: signBytes(Buffer.from("wrong bytes"), deviceKeys.secretKey),
          hardwareBacked: false,
          enrollmentEvent: makeEnrollmentEvent({
            eventId: "evt_bad_proof",
            deviceId: "dev_bad"
          })
        }),
      (error) => error instanceof PkiError && error.errorCode === "BAD_SIGNATURE"
    );

    const proofSignature = signBytes(enrollmentProofBytes(challenge, "dev_bad", deviceKeys.publicKey), deviceKeys.secretKey);
    pki.completeEnrollment({
      token: issued.token,
      challengeId: challenge.challengeId,
      proofSignature,
      hardwareBacked: false,
      enrollmentEvent: makeEnrollmentEvent({
        eventId: "evt_good_after_bad",
        deviceId: "dev_bad"
      })
    });

    assert.throws(
      () =>
        pki.beginEnrollment({
          token: issued.token,
          deviceId: "dev_reuse",
          publicKey: deviceKeys.publicKey
        }),
      (error) => error instanceof PkiError && error.errorCode === "POLICY_DENIED"
    );
  } finally {
    database.close();
    cleanup();
  }
});

test("device revocation updates device state and writes signed revocation list version", () => {
  const { database, pki, cleanup } = createPkiFixture();

  try {
    enrollDevice(pki, "revoke-token", "dev_revoke", "evt_revoke_enroll");
    const revocationList = pki.revokeDevice({
      deviceId: "dev_revoke",
      revokedBy: "admin_1",
      reason: "lost_device"
    });
    const device = database.prepare("SELECT status, revoked_at FROM devices WHERE id = ?").get("dev_revoke");
    const row = database.prepare("SELECT version, document, signature FROM revocation_list_versions").get();
    const { signature, ...unsigned } = revocationList;

    assert.equal(device.status, "revoked");
    assert.equal(device.revoked_at, "2026-07-01T15:00:03.000Z");
    assert.equal(revocationList.version, 1);
    assert.deepEqual(revocationList.revoked_device_ids, ["dev_revoke"]);
    assert.equal(verifyBytes(canonicalBytes(unsigned), signature, serverKeys.publicKey), true);
    assert.equal(row.version, 1);
    assert.deepEqual(JSON.parse(row.document), revocationList);
    assert.equal(row.signature, revocationList.signature);
  } finally {
    database.close();
    cleanup();
  }
});

function createPkiFixture() {
  const directory = mkdtempSync(join(tmpdir(), "vorcaro-pki-"));
  const database = openLedgerDatabase({ path: join(directory, "ledger.db") });
  seedExecutive(database);
  const pki = new PkiService({
    database,
    certificateAuthority: new LocalCertificateAuthority(),
    serverSigningSecretKey: serverKeys.secretKey,
    now: sequentialClock("2026-07-01T15:00:00.000Z")
  });

  return {
    database,
    pki,
    cleanup: () => rmSync(directory, { recursive: true, force: true })
  };
}

function seedExecutive(database) {
  database
    .prepare(
      `INSERT INTO executives (
        id, display_name, role, status, signing_public_key, key_version, created_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?)`
    )
    .run("exec_1", "Vorcaro CFO", "CFO", "active", executiveKeys.publicKey, 1, "2026-07-01T14:00:00Z");

  database
    .prepare(
      `INSERT INTO executive_keys (
        executive_id, key_version, signing_public_key, valid_from_sequence, valid_until_sequence
      ) VALUES (?, ?, ?, ?, ?)`
    )
    .run("exec_1", 1, executiveKeys.publicKey, 0, null);
}

function enrollDevice(pki, token, deviceId, eventId) {
  const issued = pki.issueEnrollmentToken({
    executiveId: "exec_1",
    issuedBy: "admin_1",
    expiresAt: "2026-07-01T16:00:00.000Z",
    token
  });
  const challenge = pki.beginEnrollment({
    token: issued.token,
    deviceId,
    publicKey: deviceKeys.publicKey
  });
  const proofSignature = signBytes(enrollmentProofBytes(challenge, deviceId, deviceKeys.publicKey), deviceKeys.secretKey);

  return pki.completeEnrollment({
    token: issued.token,
    challengeId: challenge.challengeId,
    proofSignature,
    hardwareBacked: true,
    enrollmentEvent: makeEnrollmentEvent({
      eventId,
      deviceId
    })
  });
}

function makeEnrollmentEvent(options) {
  const payload = Buffer.from(`payload:${options.eventId}`).toString("base64");

  return signClientEvent(
    {
      event_id: options.eventId,
      event_type: "DEVICE_ENROLLED",
      actor_id: "exec_1",
      device_id: options.deviceId,
      client_timestamp: "2026-07-01T14:23:11Z",
      base_server_sequence: 0n,
      device_event_counter: 1n,
      object_type: "device",
      object_id: options.deviceId,
      policy_metadata: {},
      payload_hash: payloadHash(payload),
      encrypted_payload: payload
    },
    executiveKeys.secretKey
  );
}

function enrollmentProofBytes(challenge, deviceId, publicKey) {
  return canonicalBytes({
    challenge_id: challenge.challengeId,
    challenge: challenge.challenge,
    device_id: deviceId,
    public_key: publicKey
  });
}

function sequentialClock(startIso) {
  let nextTime = Date.parse(startIso);

  return () => {
    const current = new Date(nextTime).toISOString();
    nextTime += 1000;
    return current;
  };
}
