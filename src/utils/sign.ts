import demosMemory from "./memory";
import {
  crypto_sign_ed25519_BYTES,
  crypto_sign_ed25519_SECRETKEYBYTES,
} from "./interfaces";

import libdemos from "@libdemos";

import type { LibDemos } from "@libdemos";

/**
 * @function
 * Returns the signature of the data provided.
 */
const sign = async (
  message: Uint8Array,
  secretKey: Uint8Array,
  module?: LibDemos,
): Promise<Uint8Array> => {
  const messageLen = message.length;

  const wasmMemory = module
    ? module.wasmMemory
    : demosMemory.signMemory(messageLen);

  const demosModule = module ?? (await libdemos({ wasmMemory }));

  const ptr1 = demosModule._malloc(messageLen * Uint8Array.BYTES_PER_ELEMENT);
  const dataArray = new Uint8Array(
    wasmMemory.buffer,
    ptr1,
    messageLen * Uint8Array.BYTES_PER_ELEMENT,
  );
  dataArray.set(message);

  const ptr2 = demosModule._malloc(crypto_sign_ed25519_BYTES);
  const signature = new Uint8Array(
    wasmMemory.buffer,
    ptr2,
    crypto_sign_ed25519_BYTES,
  );

  const ptr3 = demosModule._malloc(crypto_sign_ed25519_SECRETKEYBYTES);
  const sk = new Uint8Array(
    wasmMemory.buffer,
    ptr3,
    crypto_sign_ed25519_SECRETKEYBYTES,
  );
  sk.set(secretKey);

  demosModule._sign(
    messageLen,
    dataArray.byteOffset,
    sk.byteOffset,
    signature.byteOffset,
  );

  const sig = Uint8Array.from(signature);

  demosModule._free(ptr1);
  demosModule._free(ptr2);
  demosModule._free(ptr3);

  return sig;
};

export default sign;
