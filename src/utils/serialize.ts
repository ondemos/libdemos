import { numberUint8ArrayLen } from "./constants";

import numberToUint8Array from "./numberToUint8Array";

import {
  crypto_hash_sha512_BYTES,
  crypto_sign_ed25519_BYTES,
  crypto_sign_ed25519_PUBLICKEYBYTES,
} from "./interfaces";

import type { CommitmentOwnershipProof } from "./interfaces";

const serialize = (proof: CommitmentOwnershipProof): Uint8Array => {
  const artifactsAfterPKLen =
    proof.artifactsBetweenCommitmentAndPublicKey.length;
  const artifactsBeforePKLen =
    proof.artifactsBetweenPublicKeyAndPreviousCommit.length;

  const proofSerialized = new Uint8Array(
    crypto_hash_sha512_BYTES +
      numberUint8ArrayLen +
      artifactsAfterPKLen * crypto_hash_sha512_BYTES +
      artifactsBeforePKLen * crypto_hash_sha512_BYTES +
      numberUint8ArrayLen +
      crypto_sign_ed25519_PUBLICKEYBYTES +
      crypto_sign_ed25519_BYTES,
  );

  proofSerialized.set([...proof.previousCommit]);

  const numberOfArtifactsBetweenCommitmentAndPublicKey = numberToUint8Array(
    proof.numberOfArtifactsBetweenCommitmentAndPublicKey,
  );
  proofSerialized.set(
    [...numberOfArtifactsBetweenCommitmentAndPublicKey],
    crypto_hash_sha512_BYTES,
  );

  for (let i = 0; i < artifactsAfterPKLen; i++) {
    proofSerialized.set(
      [...proof.artifactsBetweenCommitmentAndPublicKey[i]],
      crypto_hash_sha512_BYTES + i * crypto_hash_sha512_BYTES,
    );
  }

  for (let i = 0; i < artifactsBeforePKLen; i++) {
    proofSerialized.set(
      [...proof.artifactsBetweenPublicKeyAndPreviousCommit[i]],
      crypto_hash_sha512_BYTES +
        artifactsAfterPKLen * crypto_hash_sha512_BYTES +
        i * crypto_hash_sha512_BYTES,
    );
  }

  const numberOfArtifactsBetweenPublicKeyAndPreviousCommit = numberToUint8Array(
    proof.numberOfArtifactsBetweenPublicKeyAndPreviousCommit,
  );
  proofSerialized.set(
    [...numberOfArtifactsBetweenPublicKeyAndPreviousCommit],
    crypto_hash_sha512_BYTES +
      artifactsAfterPKLen * crypto_hash_sha512_BYTES +
      artifactsBeforePKLen * crypto_hash_sha512_BYTES,
  );

  proofSerialized.set(
    [...proof.publicKey],
    crypto_hash_sha512_BYTES +
      artifactsAfterPKLen * crypto_hash_sha512_BYTES +
      artifactsBeforePKLen * crypto_hash_sha512_BYTES +
      numberUint8ArrayLen,
  );

  proofSerialized.set(
    [...proof.signature],
    crypto_hash_sha512_BYTES +
      artifactsAfterPKLen * crypto_hash_sha512_BYTES +
      artifactsBeforePKLen * crypto_hash_sha512_BYTES +
      numberUint8ArrayLen +
      crypto_sign_ed25519_PUBLICKEYBYTES,
  );

  return proofSerialized;
};

export default serialize;
