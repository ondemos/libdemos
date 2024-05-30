import ondemos from "../src";

import {
  crypto_hash_sha512_BYTES,
  crypto_aead_chacha20poly1305_ietf_KEYBYTES,
} from "../src/utils/interfaces";

const arraysAreEqual = (arr1: Uint8Array, arr2: Uint8Array): boolean => {
  const len = arr1.length;
  if (len !== arr2.length) return false;

  for (let i = 0; i < len; i++) {
    if (arr1[i] !== arr2[i]) return false;
  }

  return true;
};

describe("Encryption and decryption with symmetric key test suite.", () => {
  test("End to End encryption and decryption work.", async () => {
    const message = await ondemos.randomBytes(32);
    const aliceKeyPair = await ondemos.keyPair();
    const bobKeyPair = await ondemos.keyPair();

    const previousBlockHash = await ondemos.randomBytes(
      crypto_hash_sha512_BYTES,
    );

    const encrypted = await ondemos.encryptAsymmetric(
      message,
      bobKeyPair.publicKey,
      aliceKeyPair.secretKey,
      previousBlockHash,
    );
    const decrypted = await ondemos.decryptAsymmetric(
      encrypted,
      aliceKeyPair.publicKey,
      bobKeyPair.secretKey,
      previousBlockHash,
    );

    const encryptionMemory = ondemos.loadWasmMemory.encryptAsymmetric(
      message.length,
      crypto_hash_sha512_BYTES,
    );
    const encryptionModule = await ondemos.loadWasmModule({
      wasmMemory: encryptionMemory,
    });
    const encryptedWithModule = await ondemos.encryptAsymmetric(
      message,
      bobKeyPair.publicKey,
      aliceKeyPair.secretKey,
      previousBlockHash,
      encryptionModule,
    );

    const decryptionMemory = ondemos.loadWasmMemory.decryptAsymmetric(
      encrypted.length,
      crypto_hash_sha512_BYTES,
    );
    const decryptionModule = await ondemos.loadWasmModule({
      wasmMemory: decryptionMemory,
    });
    const decryptedWithModule = await ondemos.decryptAsymmetric(
      encrypted,
      aliceKeyPair.publicKey,
      bobKeyPair.secretKey,
      previousBlockHash,
      decryptionModule,
    );

    expect(decrypted[0]).toBe(message[0]);
    expect(decrypted[1]).toBe(message[1]);
    expect(decrypted[31]).toBe(message[31]);
    expect(arraysAreEqual(encryptedWithModule, encrypted)).toBe(false);
    expect(arraysAreEqual(decryptedWithModule, decrypted)).toBe(true);
  });

  test("Encryption and decryption with provided key work.", async () => {
    const message = await ondemos.randomBytes(32);
    const key = await ondemos.randomBytes(
      crypto_aead_chacha20poly1305_ietf_KEYBYTES,
    );

    const previousBlockHash = await ondemos.randomBytes(
      crypto_hash_sha512_BYTES,
    );

    const encrypted = await ondemos.encryptSymmetric(
      message,
      key,
      previousBlockHash,
    );
    const decrypted = await ondemos.decryptSymmetric(
      encrypted,
      key,
      previousBlockHash,
    );

    const encryptionMemory = ondemos.loadWasmMemory.encryptSymmetric(
      message.length,
      crypto_hash_sha512_BYTES,
    );
    const encryptionModule = await ondemos.loadWasmModule({
      wasmMemory: encryptionMemory,
    });
    const encryptedWithModule = await ondemos.encryptSymmetric(
      message,
      key,
      previousBlockHash,
      encryptionModule,
    );

    const decryptionMemory = ondemos.loadWasmMemory.decryptSymmetric(
      encrypted.length,
      crypto_hash_sha512_BYTES,
    );
    const decryptionModule = await ondemos.loadWasmModule({
      wasmMemory: decryptionMemory,
    });
    const decryptedWithModule = await ondemos.decryptSymmetric(
      encrypted,
      key,
      previousBlockHash,
      decryptionModule,
    );

    expect(decrypted[0]).toBe(message[0]);
    expect(decrypted[1]).toBe(message[1]);
    expect(decrypted[31]).toBe(message[31]);
    expect(arraysAreEqual(encryptedWithModule, encrypted)).toBe(false);
    expect(arraysAreEqual(decryptedWithModule, decrypted)).toBe(true);
  });

  it("Should be impossible to decrypt with wrong key", async () => {
    const message = await ondemos.randomBytes(32);
    const key = await ondemos.randomBytes(
      crypto_aead_chacha20poly1305_ietf_KEYBYTES,
    );

    const previousBlockHash = await ondemos.randomBytes(
      crypto_hash_sha512_BYTES,
    );
    const encrypted = await ondemos.encryptSymmetric(
      message,
      key,
      previousBlockHash,
    );

    const anotherKey = await ondemos.randomBytes(
      crypto_aead_chacha20poly1305_ietf_KEYBYTES,
    );

    await expect(
      ondemos.decryptSymmetric(encrypted, anotherKey, previousBlockHash),
    ).rejects.toThrow("Unsuccessful decryption attempt");
  });
});
