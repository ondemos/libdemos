import memoryLenToPages from "../utils/memoryLenToPages";

import {
  crypto_hash_sha512_BYTES,
  crypto_sign_ed25519_BYTES,
  crypto_sign_ed25519_PUBLICKEYBYTES,
  crypto_sign_ed25519_SECRETKEYBYTES,
} from "../utils/interfaces";

const generateCommitmentDetailsMemory = (
  identitiesLen: number,
  nonceLen: number,
): WebAssembly.Memory => {
  const memoryLen =
    identitiesLen *
      (nonceLen +
        crypto_sign_ed25519_PUBLICKEYBYTES +
        crypto_sign_ed25519_SECRETKEYBYTES) +
    6 * crypto_hash_sha512_BYTES;
  const memoryPages = memoryLenToPages(memoryLen);

  return new WebAssembly.Memory({
    initial: memoryPages,
    maximum: memoryPages,
  });
};

const generateProofMemory = (
  identitiesLen: number,
  nonceLen: number,
  proofLen: number,
): WebAssembly.Memory => {
  const memoryLen =
    4 +
    (1 + identitiesLen) * crypto_hash_sha512_BYTES +
    identitiesLen * nonceLen * Uint8Array.BYTES_PER_ELEMENT +
    (identitiesLen + 2) * crypto_sign_ed25519_PUBLICKEYBYTES +
    crypto_sign_ed25519_BYTES +
    proofLen * Uint8Array.BYTES_PER_ELEMENT;
  const memoryPages = memoryLenToPages(memoryLen);

  return new WebAssembly.Memory({
    initial: memoryPages,
    maximum: memoryPages,
  });
};

const verifyProofMemory = (proofLen: number): WebAssembly.Memory => {
  const memoryLen =
    proofLen * Uint8Array.BYTES_PER_ELEMENT +
    5 * crypto_hash_sha512_BYTES +
    crypto_sign_ed25519_BYTES +
    crypto_sign_ed25519_PUBLICKEYBYTES;
  const memoryPages = memoryLenToPages(memoryLen);

  return new WebAssembly.Memory({
    initial: memoryPages,
    maximum: memoryPages,
  });
};

const commitMemory = (detailsLen: number): WebAssembly.Memory => {
  const memoryLen = detailsLen + 3 * crypto_hash_sha512_BYTES;
  const pages = memoryLenToPages(memoryLen);

  return new WebAssembly.Memory({ initial: pages, maximum: pages });
};

export default {
  generateCommitmentDetailsMemory,
  generateProofMemory,
  verifyProofMemory,
  commitMemory,
};
