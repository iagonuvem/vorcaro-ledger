import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { DatabaseSync } from "node:sqlite";

import {
  initializeLedgerDatabase,
  initializeProjectionsDatabase,
  openLedgerDatabase
} from "../dist/index.js";

const appendOnlyTables = [
  ["ledger_events", "status"],
  ["checkpoints", "key_version"],
  ["audit_log", "category"],
  ["recovery_approvals", "approval_signature"],
  ["revocation_list_versions", "signature"],
  ["snapshots", "signature"]
];

test("ledger migration creates strict authoritative schema with generated routing columns", () => {
  const { database, cleanup } = createLedgerDatabase();

  try {
    seedLedgerRows(database);

    const version = database.prepare("PRAGMA user_version").get();
    assert.equal(version.user_version, 1);

    const routing = database
      .prepare("SELECT account_id, entity_id FROM ledger_events WHERE id = ?")
      .get("evt_01JTEST0000000000000000000");
    assert.equal(routing.account_id, "acct_01JTEST000000000000000000");
    assert.equal(routing.entity_id, "ent_01JTEST0000000000000000000");

    assert.throws(
      () =>
        database
          .prepare("INSERT INTO object_heads (object_type, object_id, head_sequence) VALUES (?, ?, ?)")
          .run("account", "acct_bad", "not-an-integer"),
      /cannot store TEXT value in INTEGER column object_heads\.head_sequence/
    );
  } finally {
    database.close();
    cleanup();
  }
});

test("append-only tables reject update and delete without conditional escapes", () => {
  const { database, cleanup } = createLedgerDatabase();

  try {
    seedLedgerRows(database);

    for (const [tableName, updateColumn] of appendOnlyTables) {
      assert.throws(
        () => database.exec(`UPDATE ${tableName} SET ${updateColumn} = ${updateColumn}`),
        new RegExp(`${tableName} is append-only`)
      );
      assert.throws(
        () => database.exec(`DELETE FROM ${tableName}`),
        new RegExp(`${tableName} is append-only`)
      );
    }
  } finally {
    database.close();
    cleanup();
  }
});

test("only declared mutable append-path tables can be updated", () => {
  const { database, cleanup } = createLedgerDatabase();

  try {
    seedLedgerRows(database);

    database
      .prepare("UPDATE object_heads SET head_sequence = ?, conflicted = ? WHERE object_type = ? AND object_id = ?")
      .run(2, 1, "account", "acct_01JTEST000000000000000000");
    database.prepare("UPDATE devices SET max_event_counter = ?, last_seen_at = ? WHERE id = ?").run(
      2,
      "2026-07-01T14:24:00Z",
      "dev_01JTEST0000000000000000000"
    );

    const objectHead = database.prepare("SELECT head_sequence, conflicted FROM object_heads WHERE object_type = ?").get("account");
    const device = database
      .prepare("SELECT max_event_counter, last_seen_at FROM devices WHERE id = ?")
      .get("dev_01JTEST0000000000000000000");

    assert.equal(objectHead.head_sequence, 2);
    assert.equal(objectHead.conflicted, 1);
    assert.equal(device.max_event_counter, 2);
    assert.equal(device.last_seen_at, "2026-07-01T14:24:00Z");
  } finally {
    database.close();
    cleanup();
  }
});

test("projection migration creates rebuildable read-model schema", () => {
  const database = new DatabaseSync(":memory:");

  try {
    initializeProjectionsDatabase(database);
    database
      .prepare(
        `INSERT INTO proj_accounts (
          account_id, entity_id, name, account_type, institution_name,
          account_number_masked, currency, balance_minor_units,
          as_of_sequence, status, conflicted
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
      )
      .run(
        "acct_01JTEST000000000000000000",
        "ent_01JTEST0000000000000000000",
        "Operating",
        "checking",
        "Vorcaro Bank",
        "0000",
        "USD",
        125000,
        1,
        "active",
        0
      );

    assert.deepEqual(database.prepare("SELECT key FROM proj_meta").all(), []);
    assert.equal(
      database.prepare("SELECT balance_minor_units FROM proj_accounts WHERE account_id = ?").get("acct_01JTEST000000000000000000")
        .balance_minor_units,
      125000
    );
  } finally {
    database.close();
  }
});

test("read-only ledger connections enable query_only", () => {
  const directory = mkdtempSync(join(tmpdir(), "vorcaro-ledger-db-"));
  const databasePath = join(directory, "ledger.db");
  const writable = openLedgerDatabase({ path: databasePath });

  try {
    writable.close();
    const readonly = openLedgerDatabase({ path: databasePath, readonly: true });

    try {
      const queryOnly = readonly.prepare("PRAGMA query_only").get();
      assert.equal(queryOnly.query_only, 1);
      assert.throws(() => readonly.exec("CREATE TABLE should_fail (id TEXT) STRICT"), /attempt to write a readonly database/);
    } finally {
      readonly.close();
    }
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

function createLedgerDatabase() {
  const directory = mkdtempSync(join(tmpdir(), "vorcaro-ledger-db-"));
  const databasePath = join(directory, "ledger.db");
  const database = new DatabaseSync(databasePath);
  initializeLedgerDatabase(database);

  return {
    database,
    cleanup: () => rmSync(directory, { recursive: true, force: true })
  };
}

function seedLedgerRows(database) {
  database.exec(`
    INSERT INTO executives (
      id, display_name, role, status, signing_public_key, key_version, created_at
    ) VALUES (
      'exec_01JTEST0000000000000000000',
      'Vorcaro CFO',
      'CFO',
      'active',
      'public-key',
      1,
      '2026-07-01T14:00:00Z'
    );

    INSERT INTO devices (
      id, executive_id, certificate_fingerprint, public_key, status,
      hardware_backed, enrolled_at, risk_score, max_event_counter
    ) VALUES (
      'dev_01JTEST0000000000000000000',
      'exec_01JTEST0000000000000000000',
      'fingerprint',
      'device-public-key',
      'enrolled',
      1,
      '2026-07-01T14:00:00Z',
      0,
      1
    );

    INSERT INTO ledger_events (
      id, server_sequence, event_type, actor_id, device_id, device_event_counter,
      base_server_sequence, object_type, object_id, policy_metadata,
      encrypted_payload, payload_hash, previous_ledger_hash, resulting_ledger_hash,
      client_signature, server_signature, status, client_timestamp, server_timestamp, accepted_at
    ) VALUES (
      'evt_01JTEST0000000000000000000',
      1,
      'ACCOUNT_CREATED',
      'exec_01JTEST0000000000000000000',
      'dev_01JTEST0000000000000000000',
      1,
      0,
      'account',
      'acct_01JTEST000000000000000000',
      '{"account_id":"acct_01JTEST000000000000000000","entity_id":"ent_01JTEST0000000000000000000"}',
      X'001122',
      'sha256:1111111111111111111111111111111111111111111111111111111111111111',
      'sha256:0000000000000000000000000000000000000000000000000000000000000000',
      'sha256:2222222222222222222222222222222222222222222222222222222222222222',
      'client-signature',
      'server-signature',
      'accepted',
      '2026-07-01T14:23:11Z',
      '2026-07-01T14:23:12Z',
      '2026-07-01T14:23:12Z'
    );

    INSERT INTO object_heads (
      object_type, object_id, head_sequence, conflicted
    ) VALUES (
      'account',
      'acct_01JTEST000000000000000000',
      1,
      0
    );

    INSERT INTO checkpoints (
      sequence, ledger_hash, issued_at, key_version, signature
    ) VALUES (
      1,
      'sha256:2222222222222222222222222222222222222222222222222222222222222222',
      '2026-07-01T14:24:00Z',
      1,
      'checkpoint-signature'
    );

    INSERT INTO audit_log (
      category, actor, detail, previous_hash, entry_hash, created_at
    ) VALUES (
      'admin',
      'system',
      '{}',
      'sha256:0000000000000000000000000000000000000000000000000000000000000000',
      'sha256:3333333333333333333333333333333333333333333333333333333333333333',
      '2026-07-01T14:24:00Z'
    );

    INSERT INTO recovery_ceremonies (
      id, executive_id, initiated_by, new_public_key, status,
      required_approvals, created_at
    ) VALUES (
      'rcv_01JTEST0000000000000000000',
      'exec_01JTEST0000000000000000000',
      'exec_01JTEST0000000000000000000',
      'new-public-key',
      'open',
      3,
      '2026-07-01T14:25:00Z'
    );

    INSERT INTO recovery_approvals (
      ceremony_id, approver_id, approval_signature, created_at
    ) VALUES (
      'rcv_01JTEST0000000000000000000',
      'exec_01JTEST0000000000000000000',
      'approval-signature',
      '2026-07-01T14:26:00Z'
    );

    INSERT INTO revocation_list_versions (
      version, document, signature, issued_at
    ) VALUES (
      1,
      '{"version":1,"revoked_device_ids":[],"revoked_key_versions":[],"wipe_directives":[],"issued_at":"2026-07-01T14:27:00Z","signature":"revocation-signature"}',
      'revocation-signature',
      '2026-07-01T14:27:00Z'
    );

    INSERT INTO snapshots (
      id, up_to_sequence, content_hash, storage_ref, signature, created_at
    ) VALUES (
      'snap_01JTEST000000000000000000',
      1,
      'sha256:4444444444444444444444444444444444444444444444444444444444444444',
      'minio://snapshots/snap_01JTEST000000000000000000',
      'snapshot-signature',
      '2026-07-01T14:28:00Z'
    );
  `);
}
