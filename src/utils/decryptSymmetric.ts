import demosMemory from "./memory";

import libdemos from "@libdemos";

import type { LibDemos } from "@libdemos";

import {
  crypto_aead_chacha20poly1305_ietf_KEYBYTES,
  getDecryptedLen,
} from "../utils/interfaces";

/**
 * Decrypts a box with additional data using the
 * crypto_aead_chacha20poly1305_ietf_decrypt function from libsodium and
 * a provided symmetric key in Uint8Array(32) format.
 * The encrypted box is a Uint8Array[nonce 16 || encrypted_data || auth tag 12].
 *
 * If you need to perform bulk decryptions with predictable box
 * and additional data sizes then it will be more efficient to preload
 * the wasm module and reuse it as follows:
 *
 * ```ts
 * const messageLen = message.length;
 * const additionalLen = additionalData.length;
 *
 * const wasmMemory = demosMemory.decryptSymmetricKeyMemory(messageLen, additionalLen);
 * const wasmModule = await demosMethodsModule({ wasmMemory });
 * ```
 *
 * If not all boxes and additional data are equal, you can always just use
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
 * const decrypted = await demos.decryptSymmetricKey(
 *    box,
 *    symmetricKey,
 *    additionalData
 * );
 *
 * \/\/ message should be equal to decrypted.
 * ```
 *
 * @param encrypted - the encrypted box including nonce and auth tag
 * @param symmetricKey - the precomputed symmetric key
 * @param additionalData - the additional data for aead
 * @param module - wasm module in case of bulk decryptions
 *
 * @returns The decrypted message
 */
const decryptSymmetric = async (
  encrypted: Uint8Array,
  symmetricKey: Uint8Array,
  additionalData: Uint8Array,
  module?: LibDemos,
): Promise<Uint8Array> => {
  const len = encrypted.length;
  const additionalLen = additionalData.length;

  const wasmMemory =
    module?.wasmMemory ??
    demosMemory.decryptSymmetricMemory(len, additionalLen);

  const demosModule = module ?? (await libdemos({ wasmMemory }));

  const decryptedLen = getDecryptedLen(len);

  const ptr1 = demosModule._malloc(len * Uint8Array.BYTES_PER_ELEMENT);
  const encryptedArray = new Uint8Array(
    wasmMemory.buffer,
    ptr1,
    len * Uint8Array.BYTES_PER_ELEMENT,
  );
  encryptedArray.set(encrypted);

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

  const ptr4 = demosModule._malloc(decryptedLen * Uint8Array.BYTES_PER_ELEMENT);
  const decrypted = new Uint8Array(
    wasmMemory.buffer,
    ptr4,
    decryptedLen * Uint8Array.BYTES_PER_ELEMENT,
  );

  const result = demosModule._decrypt_chachapoly_symmetric(
    len,
    encryptedArray.byteOffset,
    k.byteOffset,
    additionalLen,
    additional.byteOffset,
    decrypted.byteOffset,
  );

  demosModule._free(ptr1);
  demosModule._free(ptr2);
  demosModule._free(ptr3);

  switch (result) {
    case 0: {
      const decr = Uint8Array.from([...decrypted]);
      demosModule._free(ptr4);

      return decr;
    }

    case -1: {
      demosModule._free(ptr4);

      throw new Error("Could allocate memory for the nonce helper array.");
    }

    case -2: {
      demosModule._free(ptr4);

      throw new Error("Could allocate memory for the ciphertext helper array.");
    }

    case -3: {
      demosModule._free(ptr4);

      throw new Error("Unsuccessful decryption attempt");
    }

    default: {
      demosModule._free(ptr4);

      throw new Error("Unexpected error occured");
    }
  }
};

export default decryptSymmetric;
