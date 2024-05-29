import memoryLenToPages from "../utils/memoryLenToPages";

import {
  crypto_hash_sha512_BYTES,
  crypto_auth_hmacsha512_BYTES,
  crypto_sign_ed25519_PUBLICKEYBYTES,
  crypto_sign_ed25519_SECRETKEYBYTES,
  commitLen,
  commitDetailsLen,
  nonceLen,
  getProofLen,
} from "../utils/interfaces";

const generateIdentitiesMemory = (
  identitiesLen: number,
): WebAssembly.Memory => {
  const memoryLen =
    identitiesLen *
      (nonceLen +
        crypto_sign_ed25519_PUBLICKEYBYTES +
        crypto_sign_ed25519_SECRETKEYBYTES) +
    commitDetailsLen +
    2 * crypto_hash_sha512_BYTES;
  const memoryPages = memoryLenToPages(memoryLen);

  return new WebAssembly.Memory({
    initial: memoryPages,
    maximum: memoryPages,
  });
};

const generateProofMemory = (
  identitiesLen: number,
  identityChosenIndex: number,
): WebAssembly.Memory => {
  const proofLen = getProofLen(identitiesLen, identityChosenIndex);
  const memoryLen =
    2 * crypto_auth_hmacsha512_BYTES +
    2 * commitLen +
    identitiesLen *
      (nonceLen +
        crypto_sign_ed25519_PUBLICKEYBYTES +
        crypto_sign_ed25519_SECRETKEYBYTES) +
    proofLen * Uint8Array.BYTES_PER_ELEMENT;
  const memoryPages = memoryLenToPages(memoryLen);

  return new WebAssembly.Memory({
    initial: memoryPages,
    maximum: memoryPages,
  });
};

const verifyProofMemory = (proofLen: number): WebAssembly.Memory => {
  const memoryLen =
    2 * crypto_hash_sha512_BYTES +
    commitLen +
    proofLen * Uint8Array.BYTES_PER_ELEMENT;
  const memoryPages = memoryLenToPages(memoryLen);

  return new WebAssembly.Memory({
    initial: memoryPages,
    maximum: memoryPages,
  });
};

const commitMemory = (): WebAssembly.Memory => {
  const memoryLen = 5 * crypto_hash_sha512_BYTES + commitDetailsLen;
  const pages = memoryLenToPages(memoryLen);

  return new WebAssembly.Memory({ initial: pages, maximum: pages });
};

export default {
  generateIdentitiesMemory,
  generateProofMemory,
  verifyProofMemory,
  commitMemory,
};
