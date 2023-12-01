/**
 * Webassembly Memory is separated into 64kb contiguous memory "pages".
 * This function takes memory length in bytes and converts it to pages.
 */
const memoryLenToPages = (
  memoryLen: number,
  minPages?: number,
  maxPages?: number,
): number => {
  minPages = minPages || 4; // 256kb // 48 = 3mb // 256 = 16mb // 6 = 384kb
  maxPages = maxPages || 32768; // 2gb // 16384 = 1gb
  const pageSize = 64 * 1024;
  const ceil = Math.ceil(memoryLen / pageSize);
  if (ceil > maxPages)
    throw new Error(
      `Memory required is ${ceil * pageSize} bytes while declared maximum is ${
        maxPages * pageSize
      } bytes`,
    );

  return ceil < minPages ? minPages : ceil;
};

export default memoryLenToPages;
