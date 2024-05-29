import ondemos from "../src";

const uint8ToHex = (array: Uint8Array) => {
  return (
    "0x" +
    array.reduce((str, byte) => str + byte.toString(16).padStart(2, "0"), "")
  );
};

describe("Commitment scheme test suite.", () => {
  test("Generating commitment details works.", async () => {
    const initialCommit = await ondemos.randomBytes(
      ondemos.constants.crypto_hash_sha512_BYTES,
    );

    console.log(uint8ToHex(initialCommit));

    const newIdentities = await ondemos.generateIdentities(100);

    // console.log(newIdentities);

    const commit = await ondemos.commit(
      newIdentities.commitDetails,
      initialCommit,
    );

    console.log(uint8ToHex(commit));

    const chosenIdentity1 = 68;
    const chosenIdentity2 = 52;

    const proof1 = await ondemos.generateProof(
      chosenIdentity1,
      commit,
      initialCommit,
      newIdentities.nonces,
      newIdentities.publicKeys,
      newIdentities.secretKeys,
    );

    const proof2 = await ondemos.generateProof(
      chosenIdentity2,
      commit,
      initialCommit,
      newIdentities.nonces,
      newIdentities.publicKeys,
      newIdentities.secretKeys,
    );

    expect(proof1.length).toBeLessThan(proof2.length);

    console.log(proof1);
    console.log(proof2);

    const identityDistanceFromCommit1 = await ondemos.verifyProof(
      commit,
      proof1,
    );
    const identityDistanceFromCommit2 = await ondemos.verifyProof(
      commit,
      proof2,
    );

    expect(identityDistanceFromCommit1).toBeLessThan(
      identityDistanceFromCommit2,
    );
  });
});
