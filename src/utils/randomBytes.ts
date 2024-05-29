import demosMemory from "./memory";

import libdemos from "@libdemos";

import type { LibDemos } from "@libdemos";

/**
 * @function
 * Returns a Uint8Array of cryptographically random bytes.
 *
 * @param n: The length of the array.
 * @param module?: In case we want to cache the WASM loading.
 *
 * @returns Uint8Array
 */
const randomBytes = async (
  n: number,
  module?: LibDemos,
): Promise<Uint8Array> => {
  const wasmMemory = module?.wasmMemory || demosMemory.randomBytes(n);

  const demosModule =
    module ||
    (await libdemos({
      wasmMemory,
    }));

  const ptr = demosModule._malloc(n * Uint8Array.BYTES_PER_ELEMENT);
  const bytes = new Uint8Array(
    wasmMemory.buffer,
    ptr,
    n * Uint8Array.BYTES_PER_ELEMENT,
  );

  const result = demosModule._random_bytes(n, bytes.byteOffset);

  if (result === 0) {
    const rb = new Uint8Array([...bytes]);
    demosModule._free(ptr);

    return rb;
  }

  demosModule._free(ptr);

  throw new Error("Could not generate random data");
};

export default randomBytes;
