import demosMemory from "./memory";

import libdemos from "@libdemos";

import type { LibDemos } from "@libdemos";

import {
  crypto_aead_chacha20poly1305_ietf_KEYBYTES,
  getEncryptedLen,
} from "../utils/interfaces";

/**
 * Encrypts a message with additional data using
 * the crypto_aead_chacha20poly1305_ietf_encrypt operation from
 * libsodium with a precomputed symmetric key Uint8Array(32).
 * The nonce is calculated by taking the second half of the
 * sha512 hash of a Uint8Array(64) random array that is produced
 * in secure memory on wasm. The auth tag is generated using Poly1305.
 *
 * If you need to perform bulk encryptions with predictable message
 * and additional data sizes then it will be more efficient to preload
 * the wasm module and reuse it as follows:
 *
 * ```ts
 * const messageLen = message.length;
 * const additionalLen = additionalData.length;
 *
 * const wasmMemory = demosMemory.encryptSymmetricKeyMemory(messageLen, additionalLen);
 * const wasmModule = await demosMethodsModule({ wasmMemory });
 * ```
 *
 * If not all messages and additional data are equal, you can always just use
 * the largest Uint8Arrays as inputs.
 *
 * ```ts
 * import demos from \"@deliberative/crypto\"
 *
 * const message = new Uint8Array(128).fill(1);
 * const symmetricKey = new Uint8Array(32).fill(3);
 * const additionalData = new Uint8Array(64).fill(2);
 *
 * const box = await demos.encryptSymmetricKey(
 *    message,
 *    symmetricKey,
 *    additionalData
 * );
 * ```
 *
 * @param message - the message to encrypt
 * @param symmetricKey - the precomputed symmetric key
 * @param additionalData - the additional data for aead
 * @param module - wasm module in case of bulk encryptions
 *
 * @returns Encrypted box [nonce 16 || encrypted_data || auth tag 12]
 */
const encryptSymmetric = async (
  message: Uint8Array,
  symmetricKey: Uint8Array,
  additionalData: Uint8Array,
  module?: LibDemos,
): Promise<Uint8Array> => {
  const len = message.length;
  const additionalLen = additionalData.length;

  const wasmMemory = module
    ? module.wasmMemory
    : demosMemory.encryptSymmetricMemory(len, additionalLen);

  const demosModule = module || (await libdemos({ wasmMemory }));

  const ptr1 = demosModule._malloc(len * Uint8Array.BYTES_PER_ELEMENT);
  const dataArray = new Uint8Array(
    wasmMemory.buffer,
    ptr1,
    len * Uint8Array.BYTES_PER_ELEMENT,
  );
  dataArray.set(message);

  const ptr2 = demosModule._malloc(crypto_aead_chacha20poly1305_ietf_KEYBYTES);
  const k = new Uint8Array(
    wasmMemory.buffer,
    ptr2,
    crypto_aead_chacha20poly1305_ietf_KEYBYTES,
  );
  k.set(symmetricKey);

  const ptr3 = demosModule._malloc(
    additionalLen * Uint8Array.BYTES_PER_ELEMENT,
  );
  const additional = new Uint8Array(
    wasmMemory.buffer,
    ptr3,
    additionalLen * Uint8Array.BYTES_PER_ELEMENT,
  );
  additional.set(additionalData);

  const sealedBoxLen = getEncryptedLen(len);

  const ptr4 = demosModule._malloc(sealedBoxLen * Uint8Array.BYTES_PER_ELEMENT);
  const encrypted = new Uint8Array(
    wasmMemory.buffer,
    ptr4,
    sealedBoxLen * Uint8Array.BYTES_PER_ELEMENT,
  );

  const result = demosModule._encrypt_chachapoly_symmetric(
    len,
    dataArray.byteOffset,
    k.byteOffset,
    additionalLen,
    additional.byteOffset,
    encrypted.byteOffset,
  );

  demosModule._free(ptr1);
  demosModule._free(ptr2);
  demosModule._free(ptr3);

  switch (result) {
    case 0: {
      const enc = Uint8Array.from(encrypted);
      demosModule._free(ptr4);

      return enc;
    }

    default:
      demosModule._free(ptr4);

      throw new Error("An unexpected error occured.");
  }
};

export default encryptSymmetric;
