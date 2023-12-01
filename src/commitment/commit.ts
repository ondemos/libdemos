import demosMemory from "./memory";

import demosMethodsModule from "../../build/demosMethodsModule";

import { crypto_hash_sha512_BYTES } from "../utils/interfaces";

import type { DemosMethodsModule } from "../../build/demosMethodsModule";

const commit = async (
  details: Uint8Array,
  previousCommitment: Uint8Array,
  module?: DemosMethodsModule,
): Promise<Uint8Array> => {
  const detailsLen = details.length;

  if (
    detailsLen !== crypto_hash_sha512_BYTES &&
    detailsLen !== 2 * crypto_hash_sha512_BYTES
  )
    throw new Error(
      "Details should be either one hash or the concatenation of two hashes.",
    );

  if (previousCommitment.length !== crypto_hash_sha512_BYTES)
    throw new Error(
      "A commitment must always be the length of a SHA512 digest.",
    );

  const wasmMemory = module
    ? module.wasmMemory
    : demosMemory.commitMemory(detailsLen);
  const demosModule =
    module ||
    (await demosMethodsModule({
      wasmMemory,
    }));

  const ptr1 = demosModule._malloc(crypto_hash_sha512_BYTES);
  const updatedCommitArray = new Uint8Array(
    demosModule.HEAPU8.buffer,
    ptr1,
    crypto_hash_sha512_BYTES,
  );

  const ptr2 = demosModule._malloc(crypto_hash_sha512_BYTES);
  const previousCommitArray = new Uint8Array(
    demosModule.HEAPU8.buffer,
    ptr2,
    crypto_hash_sha512_BYTES,
  );
  previousCommitArray.set(previousCommitment);

  const ptr3 = demosModule._malloc(detailsLen);
  const detailsArray = new Uint8Array(
    demosModule.HEAPU8.buffer,
    ptr3,
    detailsLen,
  );
  detailsArray.set(details);

  let result = 0;
  if (detailsLen === 2 * crypto_hash_sha512_BYTES) {
    result = demosModule._commitment_update_reversible(
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
  } else {
    result = demosModule._commitment_update_irreversible(
      updatedCommitArray.byteOffset,
      previousCommitArray.byteOffset,
      detailsArray.byteOffset,
    );

    demosModule._free(ptr2);
    demosModule._free(ptr3);

    if (result !== 0) {
      demosModule._free(ptr1);
      if (result === -1) {
        throw new Error("A memory allocation error occured.");
      } else if (result === -2) {
        throw new Error("Could not calculate updated commit.");
      } else {
        throw new Error("An unexpected error occured.");
      }
    }
  }

  const updatedCommit = new Uint8Array([...updatedCommitArray]);
  demosModule._free(ptr1);

  return updatedCommit;
};

export default commit;
