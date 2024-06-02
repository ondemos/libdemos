import demosMemory from "./memory";

import libdemos from "@libdemos";

import type { LibDemos } from "@libdemos";

import {
  crypto_sign_ed25519_PUBLICKEYBYTES,
  crypto_sign_ed25519_SECRETKEYBYTES,
  getDecryptedLen,
} from "./interfaces";

/**
 * Decrypts a box with additional data using the
 * crypto_aead_chacha20poly1305_ietf_decrypt function from libsodium and
 * computes a symmetric key Uint8Array(32) from the sender's
 * Ed25519 public key and the receiver's Ed25519 secret key.
 * The X25519 key counterparts are computed in wasm from the libsodium provided
 * crypto_sign_ed25519_pk_to_curve25519 and crypto_sign_ed25519_sk_to_curve25519
 * functions.
 * The symmetric key for encryption is then computed by crypto_kx_client_session_keys.
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
 * const wasmMemory = dcryptoMemory.decryptMemory(messageLen, additionalLen);
 * const wasmModule = await dcryptoMethodsModule({ wasmMemory });
 * ```
 *
 * If not all boxes and additional data are equal, you can always just use
 * the largest Uint8Arrays as inputs.
 *
 * @example
 * ```ts
 * import dcrypto from \"@deliberative/crypto\"
 *
 * const message = new Uint8Array(128).fill(1);
 * const additionalData = new Uint8Array(64).fill(2);
 *
 * const aliceKeyPair = await dcrypto.keyPair();
 * const bobKeyPair = await dcrypto.keyPair();
 *
 * const box = await dcrypto.encrypt(
 *    message,
 *    bobKeyPair.publicKey,
 *    aliceKeyPair.secretKey,
 *    additionalData
 * );
 *
 * const decrypted = await dcrypto.decrypt(
 *    box,
 *    bobKeyPair.secretKey,
 *    additionalData
 * );
 *
 * \/\/ message should be equal to decrypted.
 * ```
 *
 * @param encrypted - The encrypted box including sender public key, nonce and auth tag
 * @param receiverSecretKey - The receiver secret key
 * @param additionalData - The additional data for aead
 * @param module - The wasm module in case of bulk decryptions
 * @returns The decrypted message
 */
const decryptAsymmetric = async (
  encrypted: Uint8Array,
  publicKey: Uint8Array,
  secretKey: Uint8Array,
  additionalData: Uint8Array,
  module?: LibDemos,
): Promise<Uint8Array> => {
  const len = encrypted.length;
  const additionalLen = additionalData.length;

  const wasmMemory =
    module?.wasmMemory ??
    demosMemory.decryptAsymmetricMemory(len, additionalLen);

  const demosModule = module ?? (await libdemos({ wasmMemory }));

  const decryptedLen = getDecryptedLen(len);

  const ptr1 = demosModule._malloc(len * Uint8Array.BYTES_PER_ELEMENT);
  const encryptedArray = new Uint8Array(
    wasmMemory.buffer,
    ptr1,
    len * Uint8Array.BYTES_PER_ELEMENT,
  );
  encryptedArray.set(encrypted);

  const ptr2 = demosModule._malloc(crypto_sign_ed25519_PUBLICKEYBYTES);
  const pub = new Uint8Array(
    wasmMemory.buffer,
    ptr2,
    crypto_sign_ed25519_PUBLICKEYBYTES,
  );
  pub.set(publicKey);

  const ptr3 = demosModule._malloc(crypto_sign_ed25519_SECRETKEYBYTES);
  const sec = new Uint8Array(
    wasmMemory.buffer,
    ptr3,
    crypto_sign_ed25519_SECRETKEYBYTES,
  );
  sec.set(secretKey);

  const ptr4 = demosModule._malloc(
    additionalLen * Uint8Array.BYTES_PER_ELEMENT,
  );
  const additional = new Uint8Array(
    wasmMemory.buffer,
    ptr4,
    additionalLen * Uint8Array.BYTES_PER_ELEMENT,
  );
  additional.set(additionalData);

  const ptr5 = demosModule._malloc(decryptedLen * Uint8Array.BYTES_PER_ELEMENT);
  const decrypted = new Uint8Array(
    wasmMemory.buffer,
    ptr5,
    decryptedLen * Uint8Array.BYTES_PER_ELEMENT,
  );

  const result = demosModule._decrypt_chachapoly_asymmetric(
    len,
    encryptedArray.byteOffset,
    pub.byteOffset,
    sec.byteOffset,
    additionalLen,
    additional.byteOffset,
    decrypted.byteOffset,
  );

  demosModule._free(ptr1);
  demosModule._free(ptr2);
  demosModule._free(ptr3);

  switch (result) {
    case 0: {
      const decr = Uint8Array.from(decrypted);
      demosModule._free(ptr4);

      return decr;
    }

    case -1: {
      demosModule._free(ptr4);

      throw new Error(
        "Could not allocate memory for the ephemeral public key array.",
      );
    }

    case -2: {
      demosModule._free(ptr4);

      throw new Error("Could not allocate memory for the nonce helper array.");
    }

    case -3: {
      demosModule._free(ptr4);

      throw new Error(
        "Could not allocate memory for the ed25519 converted to x25519 public key array.",
      );
    }

    case -4: {
      demosModule._free(ptr4);

      throw new Error(
        "Could not allocate memory for the ed25519 converted to x25519 secret key array.",
      );
    }

    case -5: {
      demosModule._free(ptr4);

      throw new Error("Could not allocate memory for the shared secret array.");
    }

    case -6: {
      demosModule._free(ptr4);

      throw new Error("Could not successfully generate a shared secret.");
    }

    case -7: {
      demosModule._free(ptr4);

      throw new Error("Could not allocate memory for the ciphertext array.");
    }

    case -8: {
      demosModule._free(ptr4);

      throw new Error("Unsuccessful decryption attempt");
    }

    default: {
      demosModule._free(ptr4);

      throw new Error("Unexpected error occured");
    }
  }
};

export default decryptAsymmetric;
