import demosMemory from "./memory";

import libdemos from "@libdemos";

import type { LibDemos } from "@libdemos";

/**
 * @function
 * Returns a cryptographically random number between two positive integers.
 *
 * @param min: The minimum number.
 * @param max: The maximum number.
 * @param module: In case we want to cache the WASM loading.
 *
 * @returns number
 */
const randomNumberInRange = async (
  min: number,
  max: number,
  module?: LibDemos,
): Promise<number> => {
  if (min < 0 || max < 0) throw new Error("Only positive integers allowed.");
  if (min === max) return min;

  const wasmMemory =
    module?.wasmMemory ?? demosMemory.randomNumberInRange(min, max);

  const demosModule = module ?? (await libdemos({ wasmMemory }));

  const res = demosModule._random_number_in_range(min, max);

  if (res < 0) throw new Error("Could not allocate memory for random bytes.");

  return res;
};

export default randomNumberInRange;
