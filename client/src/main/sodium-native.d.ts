declare module "sodium-native" {
  const sodium: {
    crypto_pwhash_SALTBYTES: number;
    crypto_pwhash_ALG_ARGON2ID13: number;
    crypto_pwhash_OPSLIMIT_INTERACTIVE: number;
    crypto_pwhash_MEMLIMIT_INTERACTIVE: number;
    randombytes_buf(buffer: Buffer): void;
    sodium_malloc(size: number): Buffer;
    sodium_memzero(buffer: Buffer): void;
    crypto_pwhash(
      output: Buffer,
      password: Buffer,
      salt: Buffer,
      opslimit: number,
      memlimit: number,
      algorithm: number
    ): void;
  };

  export default sodium;
}
