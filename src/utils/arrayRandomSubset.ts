import arrayRandomShuffle from "./arrayRandomShuffle";

/**
 * @function
 * Random slice of an array.
 *
 * @param array: The array to get random slice from.
 * @param elements: Number of elements.
 *
 * @returns Promise<T[]>
 */
const arrayRandomSubset = async <T>(
  array: T[],
  elements: number,
): Promise<T[]> => {
  const n = array.length;

  // Sanity check
  if (n < elements || n < 2)
    throw new Error("Not enough elements in the array");

  const shuffled = await arrayRandomShuffle(array);

  return shuffled.slice(0, elements);
};

export default arrayRandomSubset;
