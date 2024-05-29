import demosMemory from "./memory";

import libdemos from "@libdemos";

import {
  crypto_auth_hmacsha512_BYTES,
  crypto_hash_sha512_BYTES,
} from "../utils/interfaces";

import type { LibDemos } from "@libdemos";

const commit = async (
  details: Uint8Array,
  previousCommit: Uint8Array,
  module?: LibDemos,
): Promise<Uint8Array> => {
  if (details.length !== crypto_auth_hmacsha512_BYTES)
    throw new Error(
      "Details should be either one hash or the concatenation of two hashes.",
    );

  if (previousCommit.length !== crypto_hash_sha512_BYTES)
    throw new Error(
      "A commitment must always be the length of a SHA512 digest.",
    );

  const wasmMemory = module ? module.wasmMemory : demosMemory.commitMemory();
  const demosModule =
    module ||
    (await libdemos({
      wasmMemory,
    }));

  const ptr1 = demosModule._malloc(crypto_hash_sha512_BYTES);
  const updatedCommitArray = new Uint8Array(
    wasmMemory.buffer,
    ptr1,
    crypto_hash_sha512_BYTES,
  );

  const ptr2 = demosModule._malloc(crypto_hash_sha512_BYTES);
  const previousCommitArray = new Uint8Array(
    wasmMemory.buffer,
    ptr2,
    crypto_hash_sha512_BYTES,
  );
  previousCommitArray.set(previousCommit);

  const ptr3 = demosModule._malloc(crypto_auth_hmacsha512_BYTES);
  const detailsArray = new Uint8Array(
    wasmMemory.buffer,
    ptr3,
    crypto_auth_hmacsha512_BYTES,
  );
  detailsArray.set(details);

  const result = demosModule._commit(
    updatedCommitArray.byteOffset,
    previousCommitArray.byteOffset,
    detailsArray.byteOffset,
  );

  demosModule._free(ptr2);
  demosModule._free(ptr3);

  if (result !== 0) {
    demosModule._free(ptr1);
    if (result === -1) {
      throw new Error("Could not calculate details' hash.");
    } else if (result === -2) {
      throw new Error("A memory allocation error occured.");
    } else if (result === -3) {
      throw new Error("Could not calculate updated commit.");
    } else {
      throw new Error("An unexpected error occured.");
    }
  }

  const updatedCommit = new Uint8Array([...updatedCommitArray]);
  demosModule._free(ptr1);

  return updatedCommit;
};

export default commit;
