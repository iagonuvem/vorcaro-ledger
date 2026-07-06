import assert from "node:assert/strict";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { test } from "node:test";

import { vaultPassphraseRequestSchema } from "../dist/main/ipc/contract.js";
import { VaultService } from "../dist/main/main/vault.js";

const passphrase = "correct horse battery staple";

test("vault creates a wrapped root key, locks, and unlocks with stable derived handles", async () => {
  const tempRoot = await mkdtemp(path.join(os.tmpdir(), "vorcaro-vault-"));
  const headerPath = path.join(tempRoot, "profile", "vault-header.json");

  try {
    const vault = new VaultService({ headerPath });
    const created = await vault.create(passphrase);
    assert.equal(created.state, "unlocked");
    assert.equal(created.keyVersion, 1);

    const firstSigningSeed = vault.signingKeySeedForInternalUse();
    const headerBody = await readFile(headerPath, "utf8");
    assert.doesNotMatch(headerBody, /correct horse battery staple/);
    assert.match(headerBody, /"argon2id"/);
    assert.match(headerBody, /"aes-256-gcm"/);

    assert.equal(vault.lock().state, "locked");
    assert.throws(() => vault.signingKeySeedForInternalUse(), /Vault is locked/);

    const restarted = new VaultService({ headerPath });
    assert.deepEqual(await restarted.status(), {
      state: "locked",
      keyVersion: 1,
      failedUnlocks: 0,
      lockedUntil: null
    });

    await assert.rejects(restarted.unlock("wrong horse battery staple"), /Unsupported state|authenticate|bad decrypt|unable/);
    const unlocked = await restarted.unlock(passphrase);
    assert.equal(unlocked.state, "unlocked");
    assert.equal(unlocked.keyVersion, 1);
    assert.deepEqual(restarted.signingKeySeedForInternalUse(), firstSigningSeed);
  } finally {
    await rm(tempRoot, { recursive: true, force: true });
  }
});

test("vault IPC passphrase schema rejects short passphrases", () => {
  assert.equal(vaultPassphraseRequestSchema.safeParse({ passphrase: "short" }).success, false);
  assert.equal(vaultPassphraseRequestSchema.safeParse({ passphrase }).success, true);
});
