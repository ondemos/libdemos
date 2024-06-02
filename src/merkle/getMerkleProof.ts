import demosMemory from "./memory";

import sha512 from "../utils/sha512";

import libdemos from "@libdemos";

import { crypto_hash_sha512_BYTES } from "../utils/interfaces";

import type { LibDemos } from "@libdemos";

/**
 * @function
 * getMerkleProof
 *
 * @description
 * Returns the Merkle proof of an element of a tree.
 * Can be used as a receipt of a transaction etc.
 *
 * @param {Uint8Array[]} tree: The tree.
 * @param {Uint8Array} element: The element.
 *
 * @returns {Promise<Uint8Array>}: The Merkle proof.
 */
const getMerkleProof = async (
  tree: Uint8Array[],
  element: Uint8Array,
  module?: LibDemos,
): Promise<Uint8Array> => {
  const treeLen = tree.length;
  if (treeLen === 0) {
    throw new Error("Cannot calculate Merkle proof of element of empty tree.");
  } else if (treeLen === 1) {
    // "No point in calculating proof of a tree with single leaf.",
    return new Uint8Array(crypto_hash_sha512_BYTES + 1).fill(1);
  }

  const wasmMemory =
    module?.wasmMemory ?? demosMemory.getMerkleProofMemory(treeLen);
  const demosModule =
    module ??
    (await libdemos({
      wasmMemory,
    }));

  const ptr1 = demosModule._malloc(treeLen * crypto_hash_sha512_BYTES);
  const leavesHashed = new Uint8Array(
    wasmMemory.buffer,
    ptr1,
    treeLen * crypto_hash_sha512_BYTES,
  );

  let i = 0;
  let hash: Uint8Array;
  for (let j = 0; j < treeLen; j++) {
    hash = await sha512(tree[i], demosModule);
    leavesHashed.set(hash, i * crypto_hash_sha512_BYTES);
    i++;
  }

  const ptr2 = demosModule._malloc(crypto_hash_sha512_BYTES);
  const elementHash = new Uint8Array(
    wasmMemory.buffer,
    ptr2,
    crypto_hash_sha512_BYTES,
  );

  hash = await sha512(element);
  elementHash.set(hash);

  const ptr3 = demosModule._malloc(treeLen * (crypto_hash_sha512_BYTES + 1));
  const proof = new Uint8Array(
    wasmMemory.buffer,
    ptr3,
    treeLen * (crypto_hash_sha512_BYTES + 1),
  );

  const result = demosModule._get_merkle_proof(
    treeLen,
    leavesHashed.byteOffset,
    elementHash.byteOffset,
    proof.byteOffset,
  );

  demosModule._free(ptr1);
  demosModule._free(ptr2);

  switch (result) {
    case -1: {
      demosModule._free(ptr3);

      throw new Error("Element not in tree.");
    }

    case -2: {
      demosModule._free(ptr3);

      throw new Error("Could not allocate memory for hashes helper array.");
    }

    case -3: {
      demosModule._free(ptr3);

      throw new Error(
        "Could not allocate memory for hash concatenation helper array.",
      );
    }

    case -4: {
      demosModule._free(ptr3);

      throw new Error("Could not calculate hash.");
    }

    default: {
      const proofArray = Uint8Array.from(proof.slice(0, result));
      demosModule._free(ptr3);

      return proofArray;
    }
  }
};

export default getMerkleProof;
