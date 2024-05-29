import demosMemory from "./memory";
import randomNumberInRange from "./randomNumberInRange";

import libdemos from "@libdemos";

/**
 * @function
 * Fisher-Yates shuffle of array.
 *
 * @param array: The array to randomly shuffle.
 *
 * @returns Promise<T[]>
 */
const arrayRandomShuffle = async <T>(array: T[]): Promise<T[]> => {
  const n = array.length;

  // If array has <2 items, there is nothing to do
  if (n < 2) return array;

  const shuffled = [...array];

  const wasmMemory = demosMemory.randomNumberInRange(0, n);
  const module = await libdemos({ wasmMemory });

  for (let i = n - 1; i > 0; i--) {
    const j = await randomNumberInRange(0, i + 1, module);
    const temp = shuffled[i];
    shuffled[i] = shuffled[j];
    shuffled[j] = temp;
  }

  return shuffled;
};

export default arrayRandomShuffle;
