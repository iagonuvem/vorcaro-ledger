import { createCipheriv, createDecipheriv, randomBytes } from "node:crypto";

import { signBytes } from "@vorcaro/protocol";

export type WrapKeyInput = {
  readonly keyHandle: string;
  readonly plaintextKey: Buffer;
};

export type UnwrapKeyInput = {
  readonly keyHandle: string;
  readonly wrappedKey: Buffer | Uint8Array;
};

export type RewrapKeyInput = {
  readonly unwrapKeyHandle: string;
  readonly wrapKeyHandle: string;
  readonly wrappedKey: Buffer | Uint8Array;
};

export type SignWithKeyInput = {
  readonly keyHandle: string;
  readonly bytes: Buffer;
};

export type KeyManagementService = {
  wrapKey(input: WrapKeyInput): Buffer;
  unwrapKey(input: UnwrapKeyInput): Buffer;
  rewrapKey(input: RewrapKeyInput): Buffer;
  signWithKey(input: SignWithKeyInput): string;
};

export type LocalKeyManagementServiceOptions = {
  readonly wrappingKeys?: ReadonlyMap<string, Buffer>;
  readonly signingKeys?: ReadonlyMap<string, string>;
};

type EncryptedKeyEnvelope = {
  readonly algorithm: "AES-256-GCM";
  readonly iv: string;
  readonly auth_tag: string;
  readonly ciphertext: string;
};

export class LocalKeyManagementService implements KeyManagementService {
  private readonly wrappingKeys = new Map<string, Buffer>();
  private readonly signingKeys = new Map<string, string>();

  constructor(options: LocalKeyManagementServiceOptions = {}) {
    for (const [handle, key] of options.wrappingKeys ?? []) {
      this.registerWrappingKey(handle, key);
    }

    for (const [handle, key] of options.signingKeys ?? []) {
      this.registerSigningKey(handle, key);
    }
  }

  registerWrappingKey(handle: string, key: Buffer): void {
    if (key.length !== 32) {
      throw new KmsError("Wrapping keys must be 32 bytes");
    }

    this.wrappingKeys.set(handle, Buffer.from(key));
  }

  registerSigningKey(handle: string, secretKey: string): void {
    this.signingKeys.set(handle, secretKey);
  }

  wrapKey(input: WrapKeyInput): Buffer {
    const wrappingKey = this.getWrappingKey(input.keyHandle);
    const iv = randomBytes(12);
    const cipher = createCipheriv("aes-256-gcm", wrappingKey, iv);
    const ciphertext = Buffer.concat([cipher.update(input.plaintextKey), cipher.final()]);
    const envelope: EncryptedKeyEnvelope = {
      algorithm: "AES-256-GCM",
      iv: iv.toString("base64"),
      auth_tag: cipher.getAuthTag().toString("base64"),
      ciphertext: ciphertext.toString("base64")
    };

    return Buffer.from(JSON.stringify(envelope), "utf8");
  }

  unwrapKey(input: UnwrapKeyInput): Buffer {
    const wrappingKey = this.getWrappingKey(input.keyHandle);
    const envelope = LocalKeyManagementService.parseEnvelope(input.wrappedKey);
    const decipher = createDecipheriv("aes-256-gcm", wrappingKey, Buffer.from(envelope.iv, "base64"));
    decipher.setAuthTag(Buffer.from(envelope.auth_tag, "base64"));

    return Buffer.concat([
      decipher.update(Buffer.from(envelope.ciphertext, "base64")),
      decipher.final()
    ]);
  }

  rewrapKey(input: RewrapKeyInput): Buffer {
    const plaintextKey = this.unwrapKey({
      keyHandle: input.unwrapKeyHandle,
      wrappedKey: input.wrappedKey
    });

    return this.wrapKey({
      keyHandle: input.wrapKeyHandle,
      plaintextKey
    });
  }

  signWithKey(input: SignWithKeyInput): string {
    const secretKey = this.signingKeys.get(input.keyHandle);

    if (secretKey === undefined) {
      throw new KmsError("Unknown signing key handle");
    }

    return signBytes(input.bytes, secretKey);
  }

  private getWrappingKey(handle: string): Buffer {
    const key = this.wrappingKeys.get(handle);

    if (key === undefined) {
      throw new KmsError("Unknown wrapping key handle");
    }

    return key;
  }

  static parseEnvelope(raw: Buffer | Uint8Array): EncryptedKeyEnvelope {
    const parsed = JSON.parse(Buffer.from(raw).toString("utf8")) as Partial<EncryptedKeyEnvelope>;

    if (
      parsed.algorithm !== "AES-256-GCM" ||
      typeof parsed.iv !== "string" ||
      typeof parsed.auth_tag !== "string" ||
      typeof parsed.ciphertext !== "string"
    ) {
      throw new KmsError("Invalid wrapped key envelope");
    }

    return {
      algorithm: parsed.algorithm,
      iv: parsed.iv,
      auth_tag: parsed.auth_tag,
      ciphertext: parsed.ciphertext
    };
  }
}

export class KmsError extends Error {
  constructor(message: string) {
    super(message);
  }
}
