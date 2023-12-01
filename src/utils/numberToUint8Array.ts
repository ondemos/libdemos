/**
 * @function
 * Converts a number into a Uint8Array.
 *
 * @param n: number
 *
 * @returns Uint8Array
 */
const numberToUint8Array = (n: number | bigint): Uint8Array => {
  if (typeof n === "number")
    return Uint8Array.of(
      (n & 0xff000000) >> 24,
      (n & 0x00ff0000) >> 16,
      (n & 0x0000ff00) >> 8,
      (n & 0x000000ff) >> 0,
    );

  const hex = "0x" + n.toString(16);

  const match = hex.match(/.{1,2}/g);

  if (!match) throw new Error("n is not bigint.");

  return Uint8Array.from(match.map((byte) => parseInt(byte, 16)));
};

export default numberToUint8Array;
