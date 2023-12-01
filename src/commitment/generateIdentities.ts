import demosMemory from "./memory";

import demosMethodsModule from "../../build/demosMethodsModule";

import {
  crypto_sign_ed25519_PUBLICKEYBYTES,
  crypto_sign_ed25519_SECRETKEYBYTES,
  crypto_hash_sha512_BYTES,
} from "../utils/interfaces";

import type { DemosMethodsModule } from "../../build/demosMethodsModule";

/**
 * Verifies that the hash was indeed included in the calculation of the Merkle root.
 * @param hash: The hash of the base element in question.
 * @param root: The Merkle root.
 * @param proof: The first element is the first leave that was added for the calculation etc. The last
 * byte is either 0 or 1, indicating whether it is to the left or to the right in the tree.
 */
const generateIdentities = async (
  identitiesLen = 1,
  nonceLen = 12,
  module?: DemosMethodsModule,
): Promise<{
  nonces: Uint8Array[];
  publicKeys: Uint8Array[];
  secretKeys: Uint8Array[];
  reversibleCommitDetails: Uint8Array;
  irreversibleCommitDetails: Uint8Array;
}> => {
  const wasmMemory = module
    ? module.wasmMemory
    : demosMemory.generateCommitmentDetailsMemory(identitiesLen, nonceLen);
  const demosModule =
    module ||
    (await demosMethodsModule({
      wasmMemory,
    }));

  const noncesArrayLen =
    identitiesLen * nonceLen * Uint8Array.BYTES_PER_ELEMENT;
  const ptr1 = demosModule._malloc(noncesArrayLen);
  const noncesArray = new Uint8Array(
    demosModule.HEAPU8.buffer,
    ptr1,
    noncesArrayLen,
  );

  const ptr2 = demosModule._malloc(
    identitiesLen * crypto_sign_ed25519_PUBLICKEYBYTES,
  );
  const publicKeysArray = new Uint8Array(
    demosModule.HEAPU8.buffer,
    ptr2,
    identitiesLen * crypto_sign_ed25519_PUBLICKEYBYTES,
  );

  const ptr3 = demosModule._malloc(
    identitiesLen * crypto_sign_ed25519_SECRETKEYBYTES,
  );
  const secretKeysArray = new Uint8Array(
    demosModule.HEAPU8.buffer,
    ptr3,
    identitiesLen * crypto_sign_ed25519_SECRETKEYBYTES,
  );

  const ptr4 = demosModule._malloc(2 * crypto_hash_sha512_BYTES);
  const reversibleCommitArray = new Uint8Array(
    demosModule.HEAPU8.buffer,
    ptr4,
    2 * crypto_hash_sha512_BYTES,
  );

  const ptr5 = demosModule._malloc(crypto_hash_sha512_BYTES);
  const irreversibleCommitArray = new Uint8Array(
    demosModule.HEAPU8.buffer,
    ptr5,
    crypto_hash_sha512_BYTES,
  );

  const result = demosModule._generate_identities(
    identitiesLen,
    nonceLen,
    noncesArray.byteOffset,
    publicKeysArray.byteOffset,
    secretKeysArray.byteOffset,
    reversibleCommitArray.byteOffset,
    irreversibleCommitArray.byteOffset,
  );

  switch (result) {
    case 0: {
      const nonces: Uint8Array[] = [];
      const publicKeys: Uint8Array[] = [];
      const secretKeys: Uint8Array[] = [];

      for (let i = 0; i < identitiesLen; i++) {
        nonces.push(noncesArray.slice(i * nonceLen, (i + 1) * nonceLen));
        publicKeys.push(
          publicKeysArray.slice(
            i * crypto_sign_ed25519_PUBLICKEYBYTES,
            (i + 1) * crypto_sign_ed25519_PUBLICKEYBYTES,
          ),
        );

        const secretKeyArray = secretKeysArray.slice(
          i * crypto_sign_ed25519_SECRETKEYBYTES,
          (i + 1) * crypto_sign_ed25519_SECRETKEYBYTES,
        );

        secretKeys.push(secretKeyArray);
      }

      demosModule._free(ptr1);
      demosModule._free(ptr2);
      demosModule._free(ptr3);

      const reversibleCommitDetails = Uint8Array.from([
        ...reversibleCommitArray,
      ]);
      demosModule._free(ptr4);

      const irreversibleCommitDetails = Uint8Array.from([
        ...irreversibleCommitArray,
      ]);
      demosModule._free(ptr5);

      return {
        nonces,
        publicKeys,
        secretKeys,
        reversibleCommitDetails,
        irreversibleCommitDetails,
      };
    }

    case -1: {
      demosModule._free(ptr1);
      demosModule._free(ptr2);
      demosModule._free(ptr3);
      demosModule._free(ptr4);
      demosModule._free(ptr5);

      throw new Error("Identities length should be at least 1.");
    }

    case -2: {
      demosModule._free(ptr1);
      demosModule._free(ptr2);
      demosModule._free(ptr3);
      demosModule._free(ptr4);
      demosModule._free(ptr5);

      throw new Error("Could not calculate nonce hash.");
    }

    case -3: {
      demosModule._free(ptr1);
      demosModule._free(ptr2);
      demosModule._free(ptr3);
      demosModule._free(ptr4);
      demosModule._free(ptr5);

      throw new Error("Could not calculate public key hash.");
    }

    case -4: {
      demosModule._free(ptr1);
      demosModule._free(ptr2);
      demosModule._free(ptr3);
      demosModule._free(ptr4);
      demosModule._free(ptr5);

      throw new Error(
        "Could not calculate hash of concatenated hashed nonce and hashed public key.",
      );
    }

    default: {
      demosModule._free(ptr1);
      demosModule._free(ptr2);
      demosModule._free(ptr3);
      demosModule._free(ptr4);
      demosModule._free(ptr5);

      throw new Error("An unexpected error occured.");
    }
  }
};

export default generateIdentities;
