import demosMemory from "./memory";
import {
  crypto_sign_ed25519_BYTES,
  crypto_sign_ed25519_PUBLICKEYBYTES,
} from "./interfaces";

import libdemos from "@libdemos";

import type { LibDemos } from "@libdemos";

const verify = async (
  message: Uint8Array,
  signature: Uint8Array,
  publicKey: Uint8Array,
  module?: LibDemos,
): Promise<boolean> => {
  const len = message.length;

  const wasmMemory = module ? module.wasmMemory : demosMemory.verifyMemory(len);

  const demosModule = module ?? (await libdemos({ wasmMemory }));

  const ptr1 = demosModule._malloc(len * Uint8Array.BYTES_PER_ELEMENT);
  const dataArray = new Uint8Array(
    wasmMemory.buffer,
    ptr1,
    len * Uint8Array.BYTES_PER_ELEMENT,
  );
  dataArray.set(message);

  const ptr2 = demosModule._malloc(crypto_sign_ed25519_BYTES);
  const sig = new Uint8Array(
    wasmMemory.buffer,
    ptr2,
    crypto_sign_ed25519_BYTES,
  );
  sig.set(signature);

  const ptr3 = demosModule._malloc(crypto_sign_ed25519_PUBLICKEYBYTES);
  const key = new Uint8Array(
    wasmMemory.buffer,
    ptr3,
    crypto_sign_ed25519_PUBLICKEYBYTES,
  );
  key.set(publicKey);

  const result = demosModule._verify(
    len,
    dataArray.byteOffset,
    key.byteOffset,
    sig.byteOffset,
  );

  demosModule._free(ptr1);
  demosModule._free(ptr2);
  demosModule._free(ptr3);

  return result === 0;
};

export default verify;
