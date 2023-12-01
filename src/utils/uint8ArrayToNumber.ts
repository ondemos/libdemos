import { numberUint8ArrayLen, bigintUint8ArrayLen } from "./constants";

/**
 * @function
 * Converts a number in Uint8Array format back to number.
 *
 * @param array: The Uint8Array to convert.
 *
 * @returns number | bigint
 */
const uint8ArrayToNumber = (array: Uint8Array): number | bigint => {
  const arrayLen = array.length;
  const start = 0;

  if (arrayLen !== numberUint8ArrayLen && arrayLen !== bigintUint8ArrayLen)
    throw new Error(
      `Array of size ${arrayLen} cannot be converted to int or bigint.`,
    );

  if (arrayLen === numberUint8ArrayLen) {
    const bytes = array.subarray(start, start + 4);
    let n = 0;
    for (const byte of bytes.values()) {
      n = (n << 8) | byte;
    }

    return n;
  }

  const hex: string[] = [];
  array.forEach((i) => {
    let h = i.toString(16);
    if (h.length % 2) {
      h = "0" + h;
    }
    hex.push(h);
  });

  return BigInt("0x" + hex.join(""));

  // const hex = array.reduce(
  //   (str, byte) => str + byte.toString(16).padStart(2, "0x"),
  //   "",
  // );
  //
  // return BigInt(hex);
};

export default uint8ArrayToNumber;
