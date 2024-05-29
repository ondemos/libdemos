import demosMemory from "./memory";
import { crypto_hash_sha512_BYTES } from "../utils/interfaces";

import libdemos from "@libdemos";

import type { LibDemos } from "@libdemos";

const sha512 = async (
  data: Uint8Array,
  module?: LibDemos,
): Promise<Uint8Array> => {
  const dataLen = data.length;

  const wasmMemory = module
    ? module.wasmMemory
    : demosMemory.sha512Memory(dataLen);

  const demosModule = module || (await libdemos({ wasmMemory }));

  const ptr1 = demosModule._malloc(dataLen * Uint8Array.BYTES_PER_ELEMENT);
  const arr = new Uint8Array(
    wasmMemory.buffer,
    ptr1,
    dataLen * Uint8Array.BYTES_PER_ELEMENT,
  );
  arr.set(data);

  const ptr2 = demosModule._malloc(crypto_hash_sha512_BYTES);
  const hash = new Uint8Array(
    wasmMemory.buffer,
    ptr2,
    crypto_hash_sha512_BYTES,
  );

  const result = demosModule._sha512(dataLen, arr.byteOffset, hash.byteOffset);

  const h = Uint8Array.from(hash);

  demosModule._free(ptr1);
  demosModule._free(ptr2);

  if (result === 0) return h;

  throw new Error("Could not hash the array.");
};

export default sha512;
