import demosMemory from "./memory";

import libdemos from "@libdemos";

import {
  crypto_sign_ed25519_PUBLICKEYBYTES,
  crypto_sign_ed25519_SECRETKEYBYTES,
  crypto_hash_sha512_BYTES,
  crypto_auth_hmacsha512_KEYBYTES,
  getProofLen,
} from "../utils/interfaces";

import type { LibDemos } from "@libdemos";

const generateProof = async (
  identityChosenIndex: number,
  currentCommit: Uint8Array,
  previousCommit: Uint8Array,
  nonces: Uint8Array[],
  publicKeys: Uint8Array[],
  secretKeys: Uint8Array[],
  module?: LibDemos,
): Promise<Uint8Array> => {
  const identitiesLen = nonces.length;
  if (
    identitiesLen !== publicKeys.length ||
    identitiesLen !== secretKeys.length
  )
    throw new Error("Unbalanced information provided.");

  if (identityChosenIndex >= identitiesLen)
    throw new Error("Identity chosen is out of bounds.");

  const wasmMemory = module
    ? module.wasmMemory
    : demosMemory.generateProofMemory(identitiesLen, identityChosenIndex);
  const demosModule =
    module ||
    (await libdemos({
      wasmMemory,
    }));

  const ptr1 = demosModule._malloc(crypto_hash_sha512_BYTES);
  const currentCommitArray = new Uint8Array(
    wasmMemory.buffer,
    ptr1,
    crypto_hash_sha512_BYTES,
  );
  currentCommitArray.set(currentCommit);

  const ptr2 = demosModule._malloc(crypto_hash_sha512_BYTES);
  const previousCommitArray = new Uint8Array(
    wasmMemory.buffer,
    ptr2,
    crypto_hash_sha512_BYTES,
  );
  previousCommitArray.set(previousCommit);

  const ptr3 = demosModule._malloc(
    identitiesLen *
      crypto_auth_hmacsha512_KEYBYTES *
      Uint8Array.BYTES_PER_ELEMENT,
  );
  const noncesArray = new Uint8Array(
    wasmMemory.buffer,
    ptr3,
    identitiesLen *
      crypto_auth_hmacsha512_KEYBYTES *
      Uint8Array.BYTES_PER_ELEMENT,
  );
  for (let i = 0; i < identitiesLen; i++) {
    noncesArray.set(nonces[i], i * crypto_auth_hmacsha512_KEYBYTES);
  }

  const ptr4 = demosModule._malloc(
    identitiesLen * crypto_sign_ed25519_PUBLICKEYBYTES,
  );
  const publicKeysArray = new Uint8Array(
    wasmMemory.buffer,
    ptr4,
    identitiesLen * crypto_sign_ed25519_PUBLICKEYBYTES,
  );
  for (let i = 0; i < identitiesLen; i++) {
    publicKeysArray.set(publicKeys[i], i * crypto_sign_ed25519_PUBLICKEYBYTES);
  }

  const ptr5 = demosModule._malloc(crypto_sign_ed25519_SECRETKEYBYTES);
  const secretKeyArray = new Uint8Array(
    wasmMemory.buffer,
    ptr5,
    crypto_sign_ed25519_SECRETKEYBYTES,
  );
  secretKeyArray.set(secretKeys[identityChosenIndex]);

  const proofLen = getProofLen(identitiesLen, identityChosenIndex);

  const ptr6 = demosModule._malloc(proofLen * Uint8Array.BYTES_PER_ELEMENT);
  const proofArray = new Uint8Array(
    wasmMemory.buffer,
    ptr6,
    proofLen * Uint8Array.BYTES_PER_ELEMENT,
  );

  const result = demosModule._generate_proof(
    proofLen,
    identitiesLen,
    currentCommitArray.byteOffset,
    previousCommitArray.byteOffset,
    noncesArray.byteOffset,
    publicKeysArray.byteOffset,
    secretKeyArray.byteOffset,
    proofArray.byteOffset,
  );

  demosModule._free(ptr1);
  demosModule._free(ptr2);
  demosModule._free(ptr3);
  demosModule._free(ptr4);
  demosModule._free(ptr5);

  switch (result) {
    case 0: {
      const proof = Uint8Array.from([...proofArray]);
      demosModule._free(ptr6);

      return proof;
    }

    case -1: {
      demosModule._free(ptr6);

      throw new Error("Identities length should be at least 1.");
    }

    case -2: {
      demosModule._free(ptr6);

      throw new Error("Proof length is less than the minimum.");
    }

    case -3: {
      demosModule._free(ptr6);

      throw new Error(
        "Public key corresponding to secret key not in list of identities' public keys.",
      );
    }

    case -4: {
      demosModule._free(ptr6);

      throw new Error("Preallocated proof length is wrong.");
    }

    case -5: {
      demosModule._free(ptr6);

      throw new Error("Could not calculate target nonce hash.");
    }

    case -6: {
      demosModule._free(ptr6);

      throw new Error("Could not calculate nonce hash.");
    }

    case -7: {
      demosModule._free(ptr6);

      throw new Error("Could not calculate public key hash.");
    }

    case -8: {
      demosModule._free(ptr6);

      throw new Error(
        "Could not calculate hash of concatenated hashed nonce and hashed public key.",
      );
    }

    case -9: {
      demosModule._free(ptr6);

      throw new Error("Could not calculate signature.");
    }

    default: {
      demosModule._free(ptr6);

      throw new Error("An unexpected error occured.");
    }
  }
};

export default generateProof;
