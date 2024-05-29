import memoryLenToPages from "./memoryLenToPages";

import {
  crypto_hash_sha512_BYTES,
  crypto_sign_ed25519_PUBLICKEYBYTES,
  crypto_sign_ed25519_SECRETKEYBYTES,
  crypto_sign_ed25519_SEEDBYTES,
  crypto_sign_ed25519_BYTES,
  crypto_box_x25519_NONCEBYTES,
  crypto_box_x25519_PUBLICKEYBYTES,
  crypto_box_x25519_SECRETKEYBYTES,
  crypto_box_poly1305_AUTHTAGBYTES,
  crypto_pwhash_argon2id_SALTBYTES,
  crypto_kx_SESSIONKEYBYTES,
  getEncryptedLen,
  getDecryptedLen,
} from "./interfaces";

const randomBytes = (bytes: number): WebAssembly.Memory => {
  const memoryLen = bytes * Uint8Array.BYTES_PER_ELEMENT;

  const pages = memoryLenToPages(memoryLen);

  return new WebAssembly.Memory({ initial: pages, maximum: pages });
};

const randomNumberInRange = (min: number, max: number): WebAssembly.Memory => {
  const bytesNeeded = Math.ceil(Math.log2(max - min) / 8);
  const memoryLen = bytesNeeded * Uint8Array.BYTES_PER_ELEMENT;
  const pages = memoryLenToPages(memoryLen);

  return new WebAssembly.Memory({ initial: pages, maximum: pages });
};

const sha512Memory = (arrayLen: number): WebAssembly.Memory => {
  const memoryLen = arrayLen + crypto_hash_sha512_BYTES;
  const pages = memoryLenToPages(memoryLen);

  return new WebAssembly.Memory({ initial: pages, maximum: pages });
};

const argon2Memory = (mnemonicLen: number): WebAssembly.Memory => {
  const memoryLen =
    (75 * 1024 * 1024 +
      mnemonicLen +
      crypto_sign_ed25519_SEEDBYTES +
      crypto_pwhash_argon2id_SALTBYTES) *
    Uint8Array.BYTES_PER_ELEMENT;
  const pages = memoryLenToPages(memoryLen);

  return new WebAssembly.Memory({ initial: pages, maximum: pages });
};

const newKeyPairMemory = (): WebAssembly.Memory => {
  const memoryLen =
    (crypto_sign_ed25519_PUBLICKEYBYTES + crypto_sign_ed25519_SECRETKEYBYTES) *
    Uint8Array.BYTES_PER_ELEMENT;
  const pages = memoryLenToPages(memoryLen);

  return new WebAssembly.Memory({ initial: pages, maximum: pages });
};

const keyPairFromSeedMemory = (): WebAssembly.Memory => {
  const memoryLen =
    (crypto_sign_ed25519_PUBLICKEYBYTES +
      crypto_sign_ed25519_SECRETKEYBYTES +
      crypto_sign_ed25519_SEEDBYTES) *
    Uint8Array.BYTES_PER_ELEMENT;
  const pages = memoryLenToPages(memoryLen);

  return new WebAssembly.Memory({ initial: pages, maximum: pages });
};

const keyPairFromSecretKeyMemory = (): WebAssembly.Memory => {
  const memoryLen =
    (crypto_sign_ed25519_PUBLICKEYBYTES + crypto_sign_ed25519_SECRETKEYBYTES) *
    Uint8Array.BYTES_PER_ELEMENT;
  const pages = memoryLenToPages(memoryLen);

  return new WebAssembly.Memory({ initial: pages, maximum: pages });
};

const signMemory = (messageLen: number): WebAssembly.Memory => {
  const memoryLen =
    (messageLen +
      crypto_sign_ed25519_BYTES +
      crypto_sign_ed25519_SECRETKEYBYTES +
      crypto_hash_sha512_BYTES) *
    Uint8Array.BYTES_PER_ELEMENT;
  const pages = memoryLenToPages(memoryLen);

  return new WebAssembly.Memory({ initial: pages, maximum: pages });
};

const verifyMemory = (messageLen: number): WebAssembly.Memory => {
  const memoryLen =
    (messageLen +
      crypto_sign_ed25519_BYTES +
      crypto_sign_ed25519_PUBLICKEYBYTES) *
    Uint8Array.BYTES_PER_ELEMENT;
  const pages = memoryLenToPages(memoryLen);

  return new WebAssembly.Memory({ initial: pages, maximum: pages });
};

const encryptAsymmetricMemory = (
  messageLen: number,
  additionalDataLen: number,
): WebAssembly.Memory => {
  const sealedBoxLen = getEncryptedLen(messageLen);
  const memoryLen =
    (messageLen +
      crypto_sign_ed25519_PUBLICKEYBYTES +
      additionalDataLen +
      sealedBoxLen +
      1 * (messageLen + crypto_box_poly1305_AUTHTAGBYTES) + // malloc'd
      2 * crypto_box_x25519_PUBLICKEYBYTES + // malloc'd
      2 * crypto_box_x25519_SECRETKEYBYTES + // malloc'd
      crypto_box_x25519_NONCEBYTES) * // malloc'd
    Uint8Array.BYTES_PER_ELEMENT;
  const pages = memoryLenToPages(memoryLen);

  return new WebAssembly.Memory({ initial: pages, maximum: pages });
};

const decryptAsymmetricMemory = (
  encryptedLen: number,
  additionalDataLen: number,
): WebAssembly.Memory => {
  const decryptedLen = getDecryptedLen(encryptedLen);
  const memoryLen =
    (encryptedLen +
      crypto_sign_ed25519_SECRETKEYBYTES +
      additionalDataLen +
      decryptedLen +
      2 * crypto_box_x25519_PUBLICKEYBYTES + // malloc'd
      crypto_box_x25519_NONCEBYTES + // malloc'd
      crypto_box_x25519_SECRETKEYBYTES) * // malloc'd
    Uint8Array.BYTES_PER_ELEMENT;
  const pages = memoryLenToPages(memoryLen);

  return new WebAssembly.Memory({ initial: pages, maximum: pages });
};

const encryptSymmetricMemory = (
  messageLen: number,
  additionalDataLen: number,
): WebAssembly.Memory => {
  const sealedBoxLen = getEncryptedLen(messageLen);
  const memoryLen =
    (messageLen +
      crypto_kx_SESSIONKEYBYTES +
      additionalDataLen +
      sealedBoxLen +
      1 * (messageLen + crypto_box_poly1305_AUTHTAGBYTES) + // malloc'd
      2 * crypto_hash_sha512_BYTES + // malloc'd
      crypto_box_x25519_NONCEBYTES) * // malloc'd
    Uint8Array.BYTES_PER_ELEMENT;
  const pages = memoryLenToPages(memoryLen);

  return new WebAssembly.Memory({ initial: pages, maximum: pages });
};

const decryptSymmetricMemory = (
  encryptedLen: number,
  additionalDataLen: number,
): WebAssembly.Memory => {
  const decryptedLen = getDecryptedLen(encryptedLen);
  const memoryLen =
    (encryptedLen +
      crypto_kx_SESSIONKEYBYTES +
      additionalDataLen +
      decryptedLen +
      2 * crypto_hash_sha512_BYTES + // malloc'd
      crypto_box_x25519_NONCEBYTES) * // malloc'd
    Uint8Array.BYTES_PER_ELEMENT;
  const pages = memoryLenToPages(memoryLen);

  return new WebAssembly.Memory({ initial: pages, maximum: pages });
};

export default {
  randomBytes,
  randomNumberInRange,
  sha512Memory,
  argon2Memory,
  newKeyPairMemory,
  keyPairFromSeedMemory,
  keyPairFromSecretKeyMemory,
  signMemory,
  verifyMemory,
  encryptAsymmetricMemory,
  decryptAsymmetricMemory,
  encryptSymmetricMemory,
  decryptSymmetricMemory,
};
