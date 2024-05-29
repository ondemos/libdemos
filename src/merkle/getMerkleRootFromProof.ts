import demosMemory from "./memory";

import libdemos from "@libdemos";

import { crypto_hash_sha512_BYTES } from "../utils/interfaces";

/**
 * @function
 * Calculates the Merkle root from the element hash and its Merkle proof.
 *
 * @param hash: The hash of the base element in question.
 * @param proof: The first element is the first leave that was added for the calculation etc. The last
 * byte is either 0 or 1, indicating whether it is to the left or to the right in the tree.
 *
 * @returns The Merkle root
 */
const getMerkleRootFromProof = async (
  hash: Uint8Array,
  proof: Uint8Array,
): Promise<Uint8Array> => {
  const proofLen = proof.length;
  if (proofLen % (crypto_hash_sha512_BYTES + 1) !== 0)
    throw new Error("Proof length not multiple of hash length + 1.");
  const proofArtifactsLen = proofLen / (crypto_hash_sha512_BYTES + 1);

  const wasmMemory = demosMemory.verifyMerkleProofMemory(proofLen);
  const demosModule = await libdemos({
    wasmMemory,
  });

  const ptr1 = demosModule._malloc(crypto_hash_sha512_BYTES);
  const elementHash = new Uint8Array(
    wasmMemory.buffer,
    ptr1,
    crypto_hash_sha512_BYTES,
  );
  elementHash.set(hash);

  const ptr2 = demosModule._malloc(proofLen);
  const proofArray = new Uint8Array(wasmMemory.buffer, ptr2, proofLen);
  proofArray.set(proof);

  const ptr3 = demosModule._malloc(crypto_hash_sha512_BYTES);
  const rootArray = new Uint8Array(
    wasmMemory.buffer,
    ptr3,
    crypto_hash_sha512_BYTES,
  );

  const result = demosModule._get_merkle_root_from_proof(
    proofArtifactsLen,
    elementHash.byteOffset,
    proofArray.byteOffset,
    rootArray.byteOffset,
  );

  demosModule._free(ptr1);
  demosModule._free(ptr2);

  switch (result) {
    case 0: {
      const proof = Uint8Array.from(rootArray);
      demosModule._free(ptr3);

      return proof;
    }

    case -1: {
      demosModule._free(ptr3);

      throw new Error(
        "Could not allocate memory for hash concatenation helper array.",
      );
    }

    case -2: {
      demosModule._free(ptr3);

      throw new Error("Proof artifact position is neither left nor right.");
    }

    case -3: {
      demosModule._free(ptr3);

      throw new Error("Could not calculate hash.");
    }

    default: {
      demosModule._free(ptr3);

      throw new Error("Unexpected error occured.");
    }
  }
};

export default getMerkleRootFromProof;
