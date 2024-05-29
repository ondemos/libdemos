import demosMemory from "./memory";

import libdemos from "@libdemos";

import { crypto_hash_sha512_BYTES } from "../utils/interfaces";

/**
 * Verifies that the hash was indeed included in the calculation of the Merkle root.
 * @param hash: The hash of the base element in question.
 * @param root: The Merkle root.
 * @param proof: The first element is the first leave that was added for the calculation etc. The last
 * byte is either 0 or 1, indicating whether it is to the left or to the right in the tree.
 */
const verifyMerkleProof = async (
  hash: Uint8Array,
  root: Uint8Array,
  proof: Uint8Array,
): Promise<boolean> => {
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

  const ptr2 = demosModule._malloc(crypto_hash_sha512_BYTES);
  const rootArray = new Uint8Array(
    wasmMemory.buffer,
    ptr2,
    crypto_hash_sha512_BYTES,
  );
  rootArray.set(root);

  const ptr3 = demosModule._malloc(proofLen);
  const proofArray = new Uint8Array(wasmMemory.buffer, ptr3, proofLen);
  proofArray.set(proof);

  const result = demosModule._verify_merkle_proof(
    proofArtifactsLen,
    elementHash.byteOffset,
    rootArray.byteOffset,
    proofArray.byteOffset,
  );

  demosModule._free(ptr1);
  demosModule._free(ptr2);
  demosModule._free(ptr3);

  switch (result) {
    case 0:
      return true;

    case 1:
      return false;

    case -1:
      throw new Error(
        "Could not allocate memory for hash concatenation helper array.",
      );

    case -2:
      throw new Error("Could not allocate memory for hashes helper array.");

    case -3:
      throw new Error("Proof artifact position is neither left nor right.");

    case -4:
      throw new Error("Could not calculate hash.");

    default:
      throw new Error("Unexpected error occured.");
  }
};

export default verifyMerkleProof;
