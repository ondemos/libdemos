import demosMemory from "./memory";

import randomBytes from "../utils/randomBytes";

import {
  crypto_sign_ed25519_SEEDBYTES,
  crypto_pwhash_argon2id_SALTBYTES,
} from "../utils/interfaces";

import libdemos from "@libdemos";

import type { LibDemos } from "@libdemos";

const normalize = (str: string) => {
  return (str || "").normalize("NFKD");
};

const argon2 = async (
  mnemonic: string,
  salt?: Uint8Array,
  module?: LibDemos,
): Promise<Uint8Array> => {
  const mnemonicNormalized = normalize(mnemonic);
  // const mnemonicBuffer = Buffer.from(mnemonicNormalized, "utf8");
  const encoder = new TextEncoder();
  const mnemonicBuffer = encoder.encode(mnemonicNormalized).buffer;
  const mnemonicInt8Array = new Int8Array(mnemonicBuffer);
  const mnemonicArrayLen = mnemonicInt8Array.length;

  salt = salt || (await randomBytes(crypto_pwhash_argon2id_SALTBYTES));

  const wasmMemory = module
    ? module.wasmMemory
    : demosMemory.argon2Memory(mnemonicArrayLen);

  const demosModule = module || (await libdemos({ wasmMemory }));

  const ptr1 = demosModule._malloc(crypto_sign_ed25519_SEEDBYTES);
  const seed = new Uint8Array(
    wasmMemory.buffer,
    ptr1,
    crypto_sign_ed25519_SEEDBYTES,
  );

  const ptr2 = demosModule._malloc(
    mnemonicArrayLen * Uint8Array.BYTES_PER_ELEMENT,
  );
  const mnmnc = new Int8Array(
    wasmMemory.buffer,
    ptr2,
    mnemonicArrayLen * Uint8Array.BYTES_PER_ELEMENT,
  );
  mnmnc.set(mnemonicInt8Array);

  const ptr3 = demosModule._malloc(crypto_pwhash_argon2id_SALTBYTES);
  const saltArray = new Uint8Array(
    wasmMemory.buffer,
    ptr3,
    crypto_pwhash_argon2id_SALTBYTES,
  );
  saltArray.set(salt);

  const result = demosModule._argon2(
    mnemonicArrayLen,
    seed.byteOffset,
    mnmnc.byteOffset,
    saltArray.byteOffset,
  );

  const s = Uint8Array.from(seed);

  demosModule._free(ptr1);
  demosModule._free(ptr2);
  demosModule._free(ptr3);

  if (result === 0) {
    return s;
  } else {
    throw new Error("Could not generate argon2id for mnemonic.");
  }
};

export default argon2;
