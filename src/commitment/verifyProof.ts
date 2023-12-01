import demosMemory from "./memory";

import demosMethodsModule from "../../build/demosMethodsModule";

import { crypto_hash_sha512_BYTES } from "../utils/interfaces";

import type { DemosMethodsModule } from "../../build/demosMethodsModule";

/**
 * Verifies that the hash was indeed included in the calculation of the Merkle root.
 * @param hash: The hash of the base element in question.
 * @param root: The Merkle root.
 * @param proof: The first element is the first leave that was added for the calculation etc. The last
 * byte is either 0 or 1, indicating whether it is to the left or to the right in the tree.
 */
const verifyProof = async (
  commitment: Uint8Array,
  proof: Uint8Array,
  module?: DemosMethodsModule,
): Promise<number> => {
  const proofLen = proof.length;
  const wasmMemory = module
    ? module.wasmMemory
    : demosMemory.verifyProofMemory(proofLen);
  const demosModule =
    module ||
    (await demosMethodsModule({
      wasmMemory,
    }));

  const ptr1 = demosModule._malloc(crypto_hash_sha512_BYTES);
  const commitmentArray = new Uint8Array(
    demosModule.HEAPU8.buffer,
    ptr1,
    crypto_hash_sha512_BYTES,
  );
  commitmentArray.set(commitment);

  const ptr2 = demosModule._malloc(proofLen * Uint8Array.BYTES_PER_ELEMENT);
  const proofArray = new Uint8Array(
    demosModule.HEAPU8.buffer,
    ptr2,
    proofLen * Uint8Array.BYTES_PER_ELEMENT,
  );
  proofArray.set(proof);

  const result = demosModule._verify_proof(
    proofLen,
    commitmentArray.byteOffset,
    proofArray.byteOffset,
  );

  demosModule._free(ptr1);
  demosModule._free(ptr2);

  if (result >= 0) {
    return result;
  } else {
    switch (result) {
      case -1:
        throw new Error("Proof deserialization error occured.");

      case -2:
        throw new Error("Could not allocate memory for hash concatenation.");

      case -3:
        throw new Error("Could not allocate memory for hash.");

      case -4:
        throw new Error("Could not allocate memory for ownership ladder.");

      case -5:
        throw new Error(
          "Deserialization error. Number of proof artifacts between commitment and public key start index is less than 1. At least the corresponding nonce is required.",
        );

      case -6:
        throw new Error(
          "Could not calculate ownership ladder between prover and commitment.",
        );

      case -7:
        throw new Error(
          "Deserialization error. The length of artifacts of ownership ladder is not correct.",
        );

      case -8:
        throw new Error("Could not calculate hash of prover public key.");

      case -9:
        throw new Error(
          "Could not calculate hash of concatenation of nonce and prover public key nonces.",
        );

      case -10:
        throw new Error(
          "Could not calculate ownership ladder from identities before the prover.",
        );

      case -11:
        throw new Error(
          "Could not calculate ownership ladder from prover to previous commit.",
        );

      case -12:
        throw new Error("Could not recalculate commitment.");

      case -13:
        throw new Error("Recalculated commitment is wrong.");

      case -14:
        throw new Error("Wrong signature.");

      default:
        throw new Error("An unexpected error occured.");
    }
  }
};

export default verifyProof;
