import { createCipheriv, createDecipheriv, hkdfSync } from "node:crypto";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import path from "node:path";
import { z } from "zod";
import sodium from "sodium-native";

const vaultHeaderSchema = z
  .object({
    version: z.literal(1),
    keyVersion: z.number().int().positive(),
    kdf: z
      .object({
        name: z.literal("argon2id"),
        salt: z.string().min(1),
        opslimit: z.number().int().positive(),
        memlimit: z.number().int().positive(),
        algorithm: z.literal("argon2id13")
      })
      .strict(),
    wrappedRootKey: z
      .object({
        algorithm: z.literal("aes-256-gcm"),
        nonce: z.string().min(1),
        ciphertext: z.string().min(1),
        tag: z.string().min(1)
      })
      .strict()
  })
  .strict();

type VaultHeader = z.infer<typeof vaultHeaderSchema>;

export type VaultState = "uninitialized" | "locked" | "unlocked";

export type VaultStatus = {
  state: VaultState;
  keyVersion: number | null;
  failedUnlocks: number;
  lockedUntil: string | null;
};

export type VaultServiceOptions = {
  headerPath: string;
  opslimit?: number;
  memlimit?: number;
  now?: () => Date;
};

const rootKeyBytes = 32;
const kekBytes = 32;
const aesNonceBytes = 12;
const aesTagBytes = 16;
const maxFailedUnlocks = 5;
const lockoutMs = 5 * 60 * 1000;

export class VaultService {
  private readonly headerPath: string;
  private readonly opslimit: number;
  private readonly memlimit: number;
  private readonly now: () => Date;
  private rootKey: Buffer | null = null;
  private derivedKeyHandles: DerivedKeyHandles | null = null;
  private keyVersion: number | null = null;
  private failedUnlocks = 0;
  private lockedUntil: Date | null = null;

  constructor(options: VaultServiceOptions) {
    this.headerPath = options.headerPath;
    this.opslimit = options.opslimit ?? sodium.crypto_pwhash_OPSLIMIT_INTERACTIVE;
    this.memlimit = options.memlimit ?? sodium.crypto_pwhash_MEMLIMIT_INTERACTIVE;
    this.now = options.now ?? (() => new Date());
  }

  async create(passphrase: string): Promise<VaultStatus> {
    if (await this.headerExists()) {
      throw new Error("Vault already exists");
    }

    const rootKey = guardedBuffer(rootKeyBytes);
    sodium.randombytes_buf(rootKey);

    try {
      const header = this.buildHeader(passphrase, rootKey, 1);
      await mkdir(path.dirname(this.headerPath), { recursive: true });
      await writeFile(this.headerPath, `${JSON.stringify(header, null, 2)}\n`, { encoding: "utf8", mode: 0o600 });
      this.unlockRoot(rootKey, header.keyVersion);
      this.failedUnlocks = 0;
      this.lockedUntil = null;
      return this.currentStatus();
    } catch (error) {
      sodium.sodium_memzero(rootKey);
      throw error;
    }
  }

  async unlock(passphrase: string): Promise<VaultStatus> {
    this.assertNotLockedOut();

    const header = await this.readHeader();
    const kek = this.deriveKek(passphrase, header);

    try {
      const rootKey = unwrapRootKey(kek, header);
      this.unlockRoot(rootKey, header.keyVersion);
      this.failedUnlocks = 0;
      this.lockedUntil = null;
      return this.currentStatus();
    } catch (error) {
      this.recordFailedUnlock();
      throw error;
    } finally {
      kek.fill(0);
    }
  }

  lock(): VaultStatus {
    this.zeroizeUnlockedKeys();
    return this.currentStatus();
  }

  async status(): Promise<VaultStatus> {
    if (!this.rootKey && this.keyVersion === null) {
      try {
        this.keyVersion = (await this.readHeader()).keyVersion;
      } catch {
        this.keyVersion = null;
      }
    }

    return this.currentStatus();
  }

  private currentStatus(): VaultStatus {
    return {
      state: this.state(),
      keyVersion: this.keyVersion,
      failedUnlocks: this.failedUnlocks,
      lockedUntil: this.lockedUntil?.toISOString() ?? null
    };
  }

  signingKeySeedForInternalUse(): Buffer {
    if (!this.derivedKeyHandles) {
      throw new Error("Vault is locked");
    }

    return Buffer.from(this.derivedKeyHandles.signingKeySeed);
  }

  encryptionUnwrappingKeyForInternalUse(): Buffer {
    if (!this.derivedKeyHandles) {
      throw new Error("Vault is locked");
    }

    return Buffer.from(this.derivedKeyHandles.encryptionUnwrappingKey);
  }

  localDatabaseKeyForInternalUse(): Buffer {
    if (!this.derivedKeyHandles) {
      throw new Error("Vault is locked");
    }

    return Buffer.from(this.derivedKeyHandles.localDatabaseKey);
  }

  private buildHeader(passphrase: string, rootKey: Buffer, keyVersion: number): VaultHeader {
    const salt = Buffer.alloc(sodium.crypto_pwhash_SALTBYTES);
    sodium.randombytes_buf(salt);

    const headerBase = {
      version: 1 as const,
      keyVersion,
      kdf: {
        name: "argon2id" as const,
        salt: salt.toString("base64"),
        opslimit: this.opslimit,
        memlimit: this.memlimit,
        algorithm: "argon2id13" as const
      }
    };
    const kek = deriveKek(passphrase, salt, this.opslimit, this.memlimit);

    try {
      return vaultHeaderSchema.parse({
        ...headerBase,
        wrappedRootKey: wrapRootKey(kek, rootKey)
      });
    } finally {
      kek.fill(0);
      salt.fill(0);
    }
  }

  private async readHeader(): Promise<VaultHeader> {
    return vaultHeaderSchema.parse(JSON.parse(await readFile(this.headerPath, "utf8")));
  }

  private deriveKek(passphrase: string, header: VaultHeader): Buffer {
    return deriveKek(
      passphrase,
      Buffer.from(header.kdf.salt, "base64"),
      header.kdf.opslimit,
      header.kdf.memlimit
    );
  }

  private async headerExists(): Promise<boolean> {
    try {
      await readFile(this.headerPath);
      return true;
    } catch {
      return false;
    }
  }

  private unlockRoot(rootKey: Buffer, keyVersion: number): void {
    this.zeroizeUnlockedKeys();
    this.rootKey = guardedBuffer(rootKeyBytes);
    rootKey.copy(this.rootKey);
    sodium.sodium_memzero(rootKey);
    this.derivedKeyHandles = deriveChildKeys(this.rootKey);
    this.keyVersion = keyVersion;
  }

  private zeroizeUnlockedKeys(): void {
    if (this.rootKey) {
      sodium.sodium_memzero(this.rootKey);
    }

    if (this.derivedKeyHandles) {
      sodium.sodium_memzero(this.derivedKeyHandles.signingKeySeed);
      sodium.sodium_memzero(this.derivedKeyHandles.encryptionUnwrappingKey);
      sodium.sodium_memzero(this.derivedKeyHandles.deviceBindingKey);
      sodium.sodium_memzero(this.derivedKeyHandles.localDatabaseKey);
    }

    this.rootKey = null;
    this.derivedKeyHandles = null;
  }

  private state(): VaultState {
    if (this.rootKey) {
      return "unlocked";
    }

    return this.keyVersion === null ? "uninitialized" : "locked";
  }

  private assertNotLockedOut(): void {
    if (this.lockedUntil && this.lockedUntil.getTime() > this.now().getTime()) {
      throw new Error("Vault unlock temporarily locked");
    }
  }

  private recordFailedUnlock(): void {
    this.failedUnlocks += 1;

    if (this.failedUnlocks >= maxFailedUnlocks) {
      this.lockedUntil = new Date(this.now().getTime() + lockoutMs);
    }
  }
}

type DerivedKeyHandles = {
  signingKeySeed: Buffer;
  encryptionUnwrappingKey: Buffer;
  deviceBindingKey: Buffer;
  localDatabaseKey: Buffer;
};

function deriveKek(passphrase: string, salt: Buffer, opslimit: number, memlimit: number): Buffer {
  const output = Buffer.alloc(kekBytes);
  const password = Buffer.from(passphrase, "utf8");

  try {
    sodium.crypto_pwhash(output, password, salt, opslimit, memlimit, sodium.crypto_pwhash_ALG_ARGON2ID13);
    return output;
  } finally {
    password.fill(0);
  }
}

function wrapRootKey(kek: Buffer, rootKey: Buffer): VaultHeader["wrappedRootKey"] {
  const nonce = Buffer.alloc(aesNonceBytes);
  sodium.randombytes_buf(nonce);

  const cipher = createCipheriv("aes-256-gcm", kek, nonce);
  const ciphertext = Buffer.concat([cipher.update(rootKey), cipher.final()]);
  const tag = cipher.getAuthTag();

  return {
    algorithm: "aes-256-gcm",
    nonce: nonce.toString("base64"),
    ciphertext: ciphertext.toString("base64"),
    tag: tag.toString("base64")
  };
}

function unwrapRootKey(kek: Buffer, header: VaultHeader): Buffer {
  const rootKey = guardedBuffer(rootKeyBytes);
  const nonce = Buffer.from(header.wrappedRootKey.nonce, "base64");
  const ciphertext = Buffer.from(header.wrappedRootKey.ciphertext, "base64");
  const tag = Buffer.from(header.wrappedRootKey.tag, "base64");
  const decipher = createDecipheriv("aes-256-gcm", kek, nonce);

  decipher.setAuthTag(tag);
  Buffer.concat([decipher.update(ciphertext), decipher.final()]).copy(rootKey);
  return rootKey;
}

function deriveChildKeys(rootKey: Buffer): DerivedKeyHandles {
  return {
    signingKeySeed: guardedHkdf(rootKey, "vorcaro-ledger signing key seed"),
    encryptionUnwrappingKey: guardedHkdf(rootKey, "vorcaro-ledger encryption unwrapping key"),
    deviceBindingKey: guardedHkdf(rootKey, "vorcaro-ledger device binding key"),
    localDatabaseKey: guardedHkdf(rootKey, "vorcaro-ledger local database key")
  };
}

function guardedHkdf(rootKey: Buffer, info: string): Buffer {
  const derived = Buffer.from(hkdfSync("sha256", rootKey, Buffer.alloc(0), Buffer.from(info, "utf8"), 32));
  const guarded = guardedBuffer(32);
  derived.copy(guarded);
  derived.fill(0);
  return guarded;
}

function guardedBuffer(size: number): Buffer {
  return sodium.sodium_malloc(size);
}
