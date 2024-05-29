import demosMemory from "./memory";

import libdemos from "@libdemos";

import type { LibDemos } from "@libdemos";

import {
  SignKeyPair,
  crypto_sign_ed25519_PUBLICKEYBYTES,
  crypto_sign_ed25519_SECRETKEYBYTES,
  crypto_sign_ed25519_SEEDBYTES,
} from "../utils/interfaces";

const newKeyPair = async (module?: LibDemos): Promise<SignKeyPair> => {
  const wasmMemory = module
    ? module.wasmMemory
    : demosMemory.newKeyPairMemory();

  const demosModule = module || (await libdemos({ wasmMemory }));

  const ptr1 = demosModule._malloc(crypto_sign_ed25519_PUBLICKEYBYTES);
  const publicKey = new Uint8Array(
    wasmMemory.buffer,
    ptr1,
    crypto_sign_ed25519_PUBLICKEYBYTES,
  );

  const ptr2 = demosModule._malloc(crypto_sign_ed25519_SECRETKEYBYTES);
  const secretKey = new Uint8Array(
    wasmMemory.buffer,
    ptr2,
    crypto_sign_ed25519_SECRETKEYBYTES,
  );

  const result = demosModule._keypair(
    publicKey.byteOffset,
    secretKey.byteOffset,
  );

  const keyPair = {
    publicKey: Uint8Array.from(publicKey),
    secretKey: Uint8Array.from(secretKey),
  };

  demosModule._free(ptr1);
  demosModule._free(ptr2);

  switch (result) {
    case 0: {
      return keyPair;
    }

    default: {
      throw new Error("An unexpected error occured.");
    }
  }
};

const keyPairFromSeed = async (
  seed: Uint8Array,
  module?: LibDemos,
): Promise<SignKeyPair> => {
  const wasmMemory = module
    ? module.wasmMemory
    : demosMemory.keyPairFromSeedMemory();

  const demosModule = module || (await libdemos({ wasmMemory }));

  const ptr1 = demosModule._malloc(crypto_sign_ed25519_PUBLICKEYBYTES);
  const publicKey = new Uint8Array(
    wasmMemory.buffer,
    ptr1,
    crypto_sign_ed25519_PUBLICKEYBYTES,
  );

  const ptr2 = demosModule._malloc(crypto_sign_ed25519_SECRETKEYBYTES);
  const secretKey = new Uint8Array(
    wasmMemory.buffer,
    ptr2,
    crypto_sign_ed25519_SECRETKEYBYTES,
  );

  const ptr3 = demosModule._malloc(crypto_sign_ed25519_SEEDBYTES);
  const seedBytes = new Uint8Array(
    wasmMemory.buffer,
    ptr3,
    crypto_sign_ed25519_SEEDBYTES,
  );
  seedBytes.set(seed);

  const result = demosModule._keypair_from_seed(
    publicKey.byteOffset,
    secretKey.byteOffset,
    seedBytes.byteOffset,
  );

  demosModule._free(ptr3);

  switch (result) {
    case 0: {
      const keyPair = {
        publicKey: Uint8Array.from(publicKey),
        secretKey: Uint8Array.from(secretKey),
      };

      demosModule._free(ptr1);
      demosModule._free(ptr2);

      return keyPair;
    }

    default: {
      demosModule._free(ptr1);
      demosModule._free(ptr2);

      throw new Error("An unexpected error occured.");
    }
  }
};

const keyPairFromSecretKey = async (
  secretKey: Uint8Array,
  module?: LibDemos,
): Promise<SignKeyPair> => {
  const wasmMemory = module
    ? module.wasmMemory
    : demosMemory.keyPairFromSecretKeyMemory();

  const demosModule = module || (await libdemos({ wasmMemory }));

  const ptr1 = demosModule._malloc(crypto_sign_ed25519_PUBLICKEYBYTES);
  const pk = new Uint8Array(
    wasmMemory.buffer,
    ptr1,
    crypto_sign_ed25519_PUBLICKEYBYTES,
  );

  const ptr2 = demosModule._malloc(crypto_sign_ed25519_SECRETKEYBYTES);
  const sk = new Uint8Array(
    wasmMemory.buffer,
    ptr2,
    crypto_sign_ed25519_SECRETKEYBYTES,
  );
  sk.set(secretKey);

  const result = demosModule._keypair_from_secret_key(
    pk.byteOffset,
    sk.byteOffset,
  );

  demosModule._free(ptr2);

  switch (result) {
    case 0: {
      const keyPair = {
        publicKey: Uint8Array.from(pk),
        secretKey,
      };

      demosModule._free(ptr1);

      return keyPair;
    }

    default: {
      demosModule._free(ptr1);

      throw new Error("An unexpected error occured.");
    }
  }
};

export default {
  newKeyPair,
  keyPairFromSeed,
  keyPairFromSecretKey,
};
