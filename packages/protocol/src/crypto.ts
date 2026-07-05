import { createHash, timingSafeEqual } from "node:crypto";
import sodium from "sodium-native";

import { canonicalBytes, type CanonicalJson } from "./canonical.js";
import {
  checkpointSchema,
  clientEventEnvelopeSchema,
  serverAckSchema,
  unsignedCheckpointSchema,
  unsignedClientEventEnvelopeSchema,
  unsignedServerAckSchema,
  type Checkpoint,
  type ClientEventEnvelope,
  type ServerAck,
  type UnsignedCheckpoint,
  type UnsignedClientEventEnvelope,
  type UnsignedServerAck
} from "./schemas.js";

export type Ed25519KeyPair = {
  publicKey: string;
  secretKey: string;
};

export function generateSigningKeyPair(): Ed25519KeyPair {
  const publicKey = Buffer.alloc(sodium.crypto_sign_PUBLICKEYBYTES);
  const secretKey = Buffer.alloc(sodium.crypto_sign_SECRETKEYBYTES);
  sodium.crypto_sign_keypair(publicKey, secretKey);
  return encodeKeyPair(publicKey, secretKey);
}

export function deriveSigningKeyPair(seed: Buffer): Ed25519KeyPair {
  if (seed.length !== sodium.crypto_sign_SEEDBYTES) {
    throw new TypeError(`Ed25519 seed must be ${sodium.crypto_sign_SEEDBYTES} bytes`);
  }

  const publicKey = Buffer.alloc(sodium.crypto_sign_PUBLICKEYBYTES);
  const secretKey = Buffer.alloc(sodium.crypto_sign_SECRETKEYBYTES);
  sodium.crypto_sign_seed_keypair(publicKey, secretKey, seed);
  return encodeKeyPair(publicKey, secretKey);
}

export function signBytes(bytes: Buffer, secretKeyBase64: string): string {
  const secretKey = Buffer.from(secretKeyBase64, "base64");
  if (secretKey.length !== sodium.crypto_sign_SECRETKEYBYTES) {
    throw new TypeError(`Ed25519 secret key must be ${sodium.crypto_sign_SECRETKEYBYTES} bytes`);
  }

  const signature = Buffer.alloc(sodium.crypto_sign_BYTES);
  sodium.crypto_sign_detached(signature, bytes, secretKey);
  return signature.toString("base64");
}

export function verifyBytes(bytes: Buffer, signatureBase64: string, publicKeyBase64: string): boolean {
  const signature = Buffer.from(signatureBase64, "base64");
  const publicKey = Buffer.from(publicKeyBase64, "base64");

  if (
    signature.length !== sodium.crypto_sign_BYTES ||
    publicKey.length !== sodium.crypto_sign_PUBLICKEYBYTES
  ) {
    return false;
  }

  return sodium.crypto_sign_verify_detached(signature, bytes, publicKey);
}

export function sha256Hex(bytes: Buffer | string): string {
  return createHash("sha256").update(bytes).digest("hex");
}

export function sha256Digest(bytes: Buffer | string): string {
  return `sha256:${sha256Hex(bytes)}`;
}

export function payloadHash(encryptedPayloadBase64: string): string {
  return sha256Digest(Buffer.from(encryptedPayloadBase64, "base64"));
}

export function constantTimeEqual(left: string, right: string): boolean {
  const leftBytes = Buffer.from(left);
  const rightBytes = Buffer.from(right);
  return leftBytes.length === rightBytes.length && timingSafeEqual(leftBytes, rightBytes);
}

export function unsignedClientEvent(event: ClientEventEnvelope): UnsignedClientEventEnvelope {
  const parsed = clientEventEnvelopeSchema.parse(event);
  const { client_signature: _clientSignature, ...unsigned } = parsed;
  return unsignedClientEventEnvelopeSchema.parse(unsigned);
}

export function canonicalEventBytes(event: ClientEventEnvelope | UnsignedClientEventEnvelope): Buffer {
  const unsigned =
    "client_signature" in event
      ? unsignedClientEvent(event)
      : unsignedClientEventEnvelopeSchema.parse(event);
  return canonicalBytes(unsigned as CanonicalJson);
}

export function signClientEvent(event: UnsignedClientEventEnvelope, secretKeyBase64: string): ClientEventEnvelope {
  const unsigned = unsignedClientEventEnvelopeSchema.parse(event);
  return clientEventEnvelopeSchema.parse({
    ...unsigned,
    client_signature: signBytes(canonicalEventBytes(unsigned), secretKeyBase64)
  });
}

export function verifyClientEventSignature(event: ClientEventEnvelope, publicKeyBase64: string): boolean {
  const parsed = clientEventEnvelopeSchema.parse(event);
  return verifyBytes(canonicalEventBytes(parsed), parsed.client_signature, publicKeyBase64);
}

export function computeLedgerHash(
  previousLedgerHash: string,
  serverSequence: bigint,
  event: ClientEventEnvelope | UnsignedClientEventEnvelope
): string {
  return sha256Digest(
    Buffer.concat([
      Buffer.from(previousLedgerHash, "utf8"),
      Buffer.from(serverSequence.toString(10), "utf8"),
      canonicalEventBytes(event)
    ])
  );
}

export function unsignedServerAck(ack: ServerAck): UnsignedServerAck {
  const parsed = serverAckSchema.parse(ack);
  const { server_signature: _serverSignature, ...unsigned } = parsed;
  return unsignedServerAckSchema.parse(unsigned);
}

export function canonicalServerAckBytes(ack: ServerAck | UnsignedServerAck): Buffer {
  const unsigned = "server_signature" in ack ? unsignedServerAck(ack) : unsignedServerAckSchema.parse(ack);
  return canonicalBytes(unsigned as CanonicalJson);
}

export function signServerAck(ack: UnsignedServerAck, secretKeyBase64: string): ServerAck {
  const unsigned = unsignedServerAckSchema.parse(ack);
  return serverAckSchema.parse({
    ...unsigned,
    server_signature: signBytes(canonicalServerAckBytes(unsigned), secretKeyBase64)
  });
}

export function verifyServerAckSignature(ack: ServerAck, publicKeyBase64: string): boolean {
  const parsed = serverAckSchema.parse(ack);
  return verifyBytes(canonicalServerAckBytes(parsed), parsed.server_signature, publicKeyBase64);
}

export function unsignedCheckpoint(checkpoint: Checkpoint): UnsignedCheckpoint {
  const parsed = checkpointSchema.parse(checkpoint);
  const { signature: _signature, ...unsigned } = parsed;
  return unsignedCheckpointSchema.parse(unsigned);
}

export function canonicalCheckpointBytes(checkpoint: Checkpoint | UnsignedCheckpoint): Buffer {
  const unsigned = "signature" in checkpoint ? unsignedCheckpoint(checkpoint) : unsignedCheckpointSchema.parse(checkpoint);
  return canonicalBytes(unsigned as CanonicalJson);
}

export function signCheckpoint(checkpoint: UnsignedCheckpoint, secretKeyBase64: string): Checkpoint {
  const unsigned = unsignedCheckpointSchema.parse(checkpoint);
  return checkpointSchema.parse({
    ...unsigned,
    signature: signBytes(canonicalCheckpointBytes(unsigned), secretKeyBase64)
  });
}

export function verifyCheckpointSignature(checkpoint: Checkpoint, publicKeyBase64: string): boolean {
  const parsed = checkpointSchema.parse(checkpoint);
  return verifyBytes(canonicalCheckpointBytes(parsed), parsed.signature, publicKeyBase64);
}

function encodeKeyPair(publicKey: Buffer, secretKey: Buffer): Ed25519KeyPair {
  return {
    publicKey: publicKey.toString("base64"),
    secretKey: secretKey.toString("base64")
  };
}
