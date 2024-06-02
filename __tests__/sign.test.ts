import ondemos from "../src";
import nacl from "tweetnacl";

import {
  crypto_sign_ed25519_PUBLICKEYBYTES,
  crypto_sign_ed25519_SECRETKEYBYTES,
  crypto_sign_ed25519_SEEDBYTES,
} from "../src/utils/interfaces";

const arraysAreEqual = (arr1: Uint8Array, arr2: Uint8Array): boolean => {
  const len = arr1.length;
  if (len !== arr2.length) return false;

  for (let i = 0; i < len; i++) {
    if (arr1[i] !== arr2[i]) return false;
  }

  return true;
};

describe("Signing and verifying with Ed25519 keys test suite.", () => {
  test("Generating a new keypair works.", async () => {
    const keypair = await ondemos.keyPair();

    const wasmMemory = ondemos.loadWasmMemory.keyPair();
    const module = await ondemos.loadWasmModule({ wasmMemory });
    const someOtherKeypair = await ondemos.keyPair(module);

    expect(typeof keypair === "object").toBe(true);
    expect(keypair.secretKey.length).toBe(crypto_sign_ed25519_SECRETKEYBYTES);
    expect(keypair.publicKey.length).toBe(crypto_sign_ed25519_PUBLICKEYBYTES);

    expect(arraysAreEqual(keypair.secretKey, someOtherKeypair.secretKey)).toBe(
      false,
    );
  });

  test("Generating a new keypair from a random seed works.", async () => {
    const seed = await ondemos.randomBytes(crypto_sign_ed25519_SEEDBYTES);
    const keypair = await ondemos.keyPairFromSeed(seed);

    const wasmMemory = ondemos.loadWasmMemory.keyPairFromSeed();
    const module = await ondemos.loadWasmModule({ wasmMemory });
    const sameKeypair = await ondemos.keyPairFromSeed(seed, module);

    expect(typeof keypair === "object").toBe(true);
    expect(keypair.secretKey.length).toBe(crypto_sign_ed25519_SECRETKEYBYTES);
    expect(keypair.publicKey.length).toBe(crypto_sign_ed25519_PUBLICKEYBYTES);

    expect(arraysAreEqual(sameKeypair.secretKey, keypair.secretKey)).toBe(true);
  });

  test("Generating a new keypair from a secret key works.", async () => {
    const original = await ondemos.keyPair();
    const keypair = await ondemos.keyPairFromSecretKey(original.secretKey);

    const wasmMemory = ondemos.loadWasmMemory.keyPairFromSecretKey();
    const module = await ondemos.loadWasmModule({ wasmMemory });
    const sameKeypair = await ondemos.keyPairFromSecretKey(
      original.secretKey,
      module,
    );

    expect(typeof keypair === "object").toBe(true);
    expect(keypair.secretKey.length).toBe(crypto_sign_ed25519_SECRETKEYBYTES);
    expect(keypair.publicKey.length).toBe(crypto_sign_ed25519_PUBLICKEYBYTES);
    expect(arraysAreEqual(original.publicKey, keypair.publicKey)).toBe(true);

    expect(arraysAreEqual(sameKeypair.secretKey, original.secretKey)).toBe(
      true,
    );
  });

  test("Signing a Uint8Array message works.", async () => {
    const keyPair = await ondemos.keyPair();
    const randomMessage = await ondemos.randomBytes(256);
    const signature = await ondemos.sign(randomMessage, keyPair.secretKey);

    const wasmMemory = ondemos.loadWasmMemory.sign(randomMessage.length);
    const module = await ondemos.loadWasmModule({ wasmMemory });
    const otherSignature = await ondemos.sign(
      randomMessage,
      keyPair.secretKey,
      module,
    );

    expect(signature.length).toBe(64);

    expect(arraysAreEqual(signature, otherSignature)).toBe(true);
  });

  test("Signing a Uint8Array message can be verified by tweetnacl.", async () => {
    const keyPair = await ondemos.keyPair();
    const randomMessage = await ondemos.randomBytes(256);
    const signature = await ondemos.sign(randomMessage, keyPair.secretKey);

    const naclVerification = nacl.sign.detached.verify(
      randomMessage,
      signature,
      keyPair.publicKey,
    );

    expect(naclVerification).toBe(true);
  });

  test("Verifying the signature of a Uint8Array message works.", async () => {
    const mnemonic = await ondemos.generateMnemonic();
    const keypair = await ondemos.keyPairFromMnemonic(mnemonic);
    const randomMessage = await ondemos.randomBytes(256);
    const signature = await ondemos.sign(randomMessage, keypair.secretKey);
    const verification = await ondemos.verify(
      randomMessage,
      signature,
      keypair.publicKey,
    );

    const wasmMemory = ondemos.loadWasmMemory.verify(randomMessage.length);
    const module = await ondemos.loadWasmModule({ wasmMemory });
    const otherVerification = await ondemos.verify(
      randomMessage,
      signature,
      keypair.publicKey,
      module,
    );

    expect(verification).toBe(true);
    expect(otherVerification).toBe(true);
  });

  test("Verifying the signature of a Uint8Array message from tweetnacl works.", async () => {
    const keyPair = await ondemos.keyPair();
    const randomMessage = await ondemos.randomBytes(256);
    const signature = nacl.sign.detached(randomMessage, keyPair.secretKey);

    const naclVerification = nacl.sign.detached.verify(
      randomMessage,
      signature,
      keyPair.publicKey,
    );

    const verification = await ondemos.verify(
      randomMessage,
      signature,
      keyPair.publicKey,
    );

    expect(naclVerification).toBe(true);
    expect(verification).toBe(true);
  });

  test("Verifying signature with wrong key should return false.", async () => {
    const rightKeyPair = await ondemos.keyPair();
    const wrongKeyPair = await ondemos.keyPair();
    const randomMessage = await ondemos.randomBytes(10240);
    const signature = await ondemos.sign(randomMessage, rightKeyPair.secretKey);
    const verification = await ondemos.verify(
      randomMessage,
      signature,
      wrongKeyPair.publicKey,
    );

    expect(verification).toBe(false);
  });
});
