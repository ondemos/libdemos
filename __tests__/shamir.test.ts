import ondemos from "../src";

import { crypto_sign_ed25519_SECRETKEYBYTES } from "../src/utils/interfaces";

const arraysAreEqual = (arr1: Uint8Array, arr2: Uint8Array): boolean => {
  const len = arr1.length;
  if (len !== arr2.length) return false;

  for (let i = 0; i < len; i++) {
    if (arr1[i] !== arr2[i]) return false;
  }

  return true;
};

describe("Starting the Shamir test suite.", () => {
  test("Splitting a secret key to Shamir shares works.", async () => {
    const mnemonic = await ondemos.generateMnemonic();
    const keypair = await ondemos.keyPairFromMnemonic(mnemonic);
    const shares = await ondemos.splitSecret(keypair.secretKey, 254, 30);
    expect(shares.length).toBe(254);
    expect(shares[9].length).toBe(crypto_sign_ed25519_SECRETKEYBYTES + 1);
  });

  it("Should be impossible to split a secret of length less than 2.", async () => {
    const secret = new Uint8Array(1).fill(4);
    await expect(ondemos.splitSecret(secret, 10, 6)).rejects.toThrow(
      "Need more data",
    );
  });

  it("Should be impossible to split a secret with threshold less than 2.", async () => {
    const secret = await ondemos.randomBytes(256);
    await expect(ondemos.splitSecret(secret, 10, 1)).rejects.toThrow(
      "Threshold is less than 2",
    );
  });

  it("Should be impossible to split a secret into shares less than threshold.", async () => {
    const secret = await ondemos.randomBytes(256);
    await expect(ondemos.splitSecret(secret, 10, 11)).rejects.toThrow(
      "Shares are less than threshold",
    );
  });

  it("Should be impossible to split a secret into more than 255 shares.", async () => {
    const secret = await ondemos.randomBytes(256);
    await expect(ondemos.splitSecret(secret, 256, 11)).rejects.toThrow(
      "Shares exceed 255",
    );
  });

  test("Combining Shamir shares to recreate a secret key works.", async () => {
    const mnemonic = await ondemos.generateMnemonic();
    const keypair = await ondemos.keyPairFromMnemonic(mnemonic);
    const sharesLen = 9;
    const threshold = 5;
    const shares = await ondemos.splitSecret(
      keypair.secretKey,
      sharesLen,
      threshold,
    );

    const secretKey = await ondemos.restoreSecret(shares);

    const randomSubset1 = await ondemos.randomShuffle(shares);
    const secretKey1 = await ondemos.restoreSecret(randomSubset1);

    const randomSubset2 = await ondemos.randomSubset(shares, threshold);
    const secretKey2 = await ondemos.restoreSecret(randomSubset2);

    const randomSubset3 = await ondemos.randomSubset(shares, threshold - 1);
    const secretKey3 = await ondemos.restoreSecret(randomSubset3);

    expect(secretKey.length === keypair.secretKey.length).toBe(true);
    expect(arraysAreEqual(secretKey, keypair.secretKey)).toBe(true);
    expect(arraysAreEqual(secretKey1, keypair.secretKey)).toBe(true);
    expect(arraysAreEqual(secretKey2, keypair.secretKey)).toBe(true);
    expect(arraysAreEqual(secretKey3, keypair.secretKey)).toBe(false);
  });

  it("Should be impossible to restore a shared secret with less than 2 shares.", async () => {
    const shares = [new Uint8Array(13)];
    await expect(ondemos.restoreSecret(shares)).rejects.toThrow(
      "Not enough shares provided.",
    );
  });

  it("Should be impossible to restore a shared secret with more than 255 shares.", async () => {
    const shares: Uint8Array[] = [];
    for (let i = 0; i < 257; i++) {
      shares.push(new Uint8Array(20));
    }
    await expect(ondemos.restoreSecret(shares)).rejects.toThrow(
      "Need at most 255 shares.",
    );
  });

  it("Should be impossible to restore a shared secret with shares of variable length.", async () => {
    const shares: Uint8Array[] = [];
    shares.push(new Uint8Array(8));
    shares.push(new Uint8Array(10));
    await expect(ondemos.restoreSecret(shares)).rejects.toThrow(
      "Shares length varies.",
    );
  });
});
