declare module "sodium-native" {
  export const crypto_sign_PUBLICKEYBYTES: number;
  export const crypto_sign_SECRETKEYBYTES: number;
  export const crypto_sign_SEEDBYTES: number;
  export const crypto_sign_BYTES: number;

  export function crypto_sign_keypair(publicKey: Buffer, secretKey: Buffer): void;
  export function crypto_sign_seed_keypair(publicKey: Buffer, secretKey: Buffer, seed: Buffer): void;
  export function crypto_sign_detached(signature: Buffer, message: Buffer, secretKey: Buffer): void;
  export function crypto_sign_verify_detached(signature: Buffer, message: Buffer, publicKey: Buffer): boolean;
}
