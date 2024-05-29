import demosMemory from "./memory";

import libdemos from "@libdemos";

import type { LibDemos } from "@libdemos";

import {
  crypto_sign_ed25519_SECRETKEYBYTES,
  crypto_sign_ed25519_PUBLICKEYBYTES,
  getEncryptedLen,
} from "./interfaces";

/**
 * Encrypts a message with additional data using
 * the crypto_aead_chacha20poly1305_ietf_encrypt operation from
 * libsodium and computes a symmetric key Uint8Array(32) from the sender's
 * Ed25519 secret key and the receiver's Ed25519 public key.
 * The X25519 key counterparts are computed in wasm from the libsodium provided
 * crypto_sign_ed25519_pk_to_curve25519 and crypto_sign_ed25519_sk_to_curve25519
 * functions.
 * The symmetric key for encryption is then computed by crypto_kx_server_session_keys.
 * The nonce is calculated by taking the first half of the
 * sha512 hash of a Uint8Array(3 * 32) array with 32 random bytes, the X25519 public key
 * and the X25519 secret key.
 * The auth tag is generated using Poly1305.
 *
 * If you need to perform bulk encryptions with predictable message
 * and additional data sizes then it will be more efficient to preload
 * the wasm module and reuse it as follows:
 *
 * ```ts
 * const messageLen = message.length;
 * const additionalLen = additionalData.length;
 *
 * const wasmMemory = dcryptoMemory.encryptMemory(messageLen, additionalLen);
 * const wasmModule = await dcryptoMethodsModule({ wasmMemory });
 * ```
 *
 * If not all messages and additional data are equal, you can always just use
 * the largest Uint8Arrays as inputs.
 *
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
 * ```
 *
 * @param message - the message to encrypt
 * @param receiverPublicKey - the receiver's Ed25519 public key
 * @param senderSecretKey - the sender's Ed25519 secret key
 * @param additionalData - the additional data for aead
 * @param module - wasm module in case of bulk encryptions
 *
 * @returns Encrypted box [nonce 16 || encrypted_data || auth tag 12]
 */
const encryptAsymmetric = async (
  message: Uint8Array,
  receiverPublicKey: Uint8Array,
  senderSecretKey: Uint8Array,
  additionalData: Uint8Array,
  module?: LibDemos,
): Promise<Uint8Array> => {
  const len = message.length;
  const additionalLen = additionalData.length;

  const wasmMemory = module
    ? module.wasmMemory
    : demosMemory.encryptAsymmetricMemory(len, additionalLen);

  const demosModule = module || (await libdemos({ wasmMemory }));

  const ptr1 = demosModule._malloc(len * Uint8Array.BYTES_PER_ELEMENT);
  const dataArray = new Uint8Array(
    wasmMemory.buffer,
    ptr1,
    len * Uint8Array.BYTES_PER_ELEMENT,
  );
  dataArray.set(message);

  const ptr2 = demosModule._malloc(crypto_sign_ed25519_PUBLICKEYBYTES);
  const pk = new Uint8Array(
    wasmMemory.buffer,
    ptr2,
    crypto_sign_ed25519_PUBLICKEYBYTES,
  );
  pk.set(receiverPublicKey);

  const ptr3 = demosModule._malloc(crypto_sign_ed25519_SECRETKEYBYTES);
  const sk = new Uint8Array(
    wasmMemory.buffer,
    ptr3,
    crypto_sign_ed25519_SECRETKEYBYTES,
  );
  sk.set(senderSecretKey);

  const ptr4 = demosModule._malloc(
    additionalLen * Uint8Array.BYTES_PER_ELEMENT,
  );
  const additional = new Uint8Array(
    wasmMemory.buffer,
    ptr4,
    additionalLen * Uint8Array.BYTES_PER_ELEMENT,
  );
  additional.set(additionalData);

  const sealedBoxLen = getEncryptedLen(len);

  const ptr5 = demosModule._malloc(sealedBoxLen * Uint8Array.BYTES_PER_ELEMENT);
  const encrypted = new Uint8Array(
    wasmMemory.buffer,
    ptr5,
    sealedBoxLen * Uint8Array.BYTES_PER_ELEMENT,
  );

  const result = demosModule._encrypt_chachapoly_asymmetric(
    len,
    dataArray.byteOffset,
    pk.byteOffset,
    sk.byteOffset,
    additionalLen,
    additional.byteOffset,
    encrypted.byteOffset,
  );

  demosModule._free(ptr1);
  demosModule._free(ptr2);
  demosModule._free(ptr3);
  demosModule._free(ptr4);

  switch (result) {
    case 0: {
      const enc = Uint8Array.from(encrypted);
      demosModule._free(ptr5);

      return enc;
    }

    case -1: {
      demosModule._free(ptr5);

      throw new Error("Could not allocate memory for the ciphertext array.");
    }

    case -2: {
      demosModule._free(ptr5);

      throw new Error(
        "Could not allocate memory for the ephemeral x25519 public key array.",
      );
    }

    case -3: {
      demosModule._free(ptr5);

      throw new Error(
        "Could not allocate memory for the ephemeral x25519 secret key array.",
      );
    }

    case -4: {
      demosModule._free(ptr5);

      throw new Error(
        "Could not allocate memory for the receiver's ed25519 converted to x25519 public key array.",
      );
    }

    case -5: {
      demosModule._free(ptr5);

      throw new Error("Could not convert Ed25519 public key to X25519.");
    }

    case -6: {
      demosModule._free(ptr5);

      throw new Error("Could not allocate memory for the shared secret array.");
    }

    case -7: {
      demosModule._free(ptr5);

      throw new Error("Could not create a shared secret.");
    }

    case -8: {
      demosModule._free(ptr5);

      throw new Error("Could not allocate memory for the nonce helper array.");
    }

    default: {
      demosModule._free(ptr5);

      throw new Error("An unexpected error occured.");
    }
  }
};

export default encryptAsymmetric;
