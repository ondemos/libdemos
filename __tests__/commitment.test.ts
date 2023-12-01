import dcrypto from "@deliberative/crypto";

import dcommitment from "../src";

describe("Commitment scheme test suite.", () => {
  test("Generating commitment details works.", async () => {
    const initialCommit = await dcrypto.randomBytes(
      dcrypto.constants.crypto_hash_sha512_BYTES,
    );

    console.log(initialCommit);

    const newIdentities = await dcommitment.generateIdentities(4);

    console.log(newIdentities);

    const committed1 = await dcommitment.commit(
      newIdentities.irreversibleCommitDetails,
      initialCommit,
    );

    const committed2 = await dcommitment.commit(
      newIdentities.reversibleCommitDetails,
      initialCommit,
    );

    expect(committed1).toStrictEqual(committed2);

    console.log(committed1);

    const proof1 = await dcommitment.generateProof(
      committed1,
      initialCommit,
      newIdentities.nonces,
      newIdentities.publicKeys,
      newIdentities.secretKeys[3],
    );

    const proof2 = await dcommitment.generateProof(
      committed1,
      initialCommit,
      newIdentities.nonces,
      newIdentities.publicKeys,
      newIdentities.secretKeys[0],
    );

    console.log(proof1);
    console.log(proof2);

    const identityDistanceFromCommit1 = await dcommitment.verifyProof(committed1, proof1);
    const identityDistanceFromCommit2 = await dcommitment.verifyProof(committed2, proof2);

    expect(identityDistanceFromCommit1).toBeLessThan(identityDistanceFromCommit2);
  });
});
