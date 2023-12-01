import uint8ArrayToNumber from "./uint8ArrayToNumber";
import { numberUint8ArrayLen } from "./constants";

import {
  crypto_hash_sha512_BYTES,
  crypto_sign_ed25519_BYTES,
  crypto_sign_ed25519_PUBLICKEYBYTES,
} from "./interfaces";

import type { CommitmentOwnershipProof } from "./interfaces";

const deserialize = (proof: Uint8Array): CommitmentOwnershipProof => {
  const proofLen = proof.length;

  const previousCommit = proof.slice(0, crypto_hash_sha512_BYTES);

  const numberOfArtifactsBetweenCommitmentAndPublicKey = uint8ArrayToNumber(
    proof.slice(
      crypto_hash_sha512_BYTES,
      crypto_hash_sha512_BYTES + numberUint8ArrayLen,
    ),
  ) as number;

  const artifactsBetweenCommitmentAndPublicKey: Uint8Array[] = [];
  for (let i = 0; i < numberOfArtifactsBetweenCommitmentAndPublicKey; i++) {
    artifactsBetweenCommitmentAndPublicKey.push(
      proof.slice(
        crypto_hash_sha512_BYTES +
          numberUint8ArrayLen +
          i * crypto_hash_sha512_BYTES,
        crypto_hash_sha512_BYTES +
          numberUint8ArrayLen +
          (i + 1) * crypto_hash_sha512_BYTES,
      ),
    );
  }

  const numberOfArtifactsBetweenPublicKeyAndPreviousCommit = uint8ArrayToNumber(
    proof.slice(
      proofLen -
        crypto_sign_ed25519_PUBLICKEYBYTES -
        crypto_sign_ed25519_BYTES -
        numberUint8ArrayLen,
      proofLen - crypto_sign_ed25519_PUBLICKEYBYTES - crypto_sign_ed25519_BYTES,
    ),
  ) as number;

  const artifactsBetweenPublicKeyAndPreviousCommit: Uint8Array[] = [];
  for (let i = 0; i < numberOfArtifactsBetweenPublicKeyAndPreviousCommit; i++) {
    artifactsBetweenPublicKeyAndPreviousCommit.push(
      proof.slice(
        crypto_hash_sha512_BYTES +
          numberUint8ArrayLen +
          numberOfArtifactsBetweenCommitmentAndPublicKey *
            crypto_hash_sha512_BYTES +
          i * crypto_hash_sha512_BYTES,
        crypto_hash_sha512_BYTES +
          numberUint8ArrayLen +
          numberOfArtifactsBetweenCommitmentAndPublicKey *
            crypto_hash_sha512_BYTES +
          (i + 1) * crypto_hash_sha512_BYTES,
      ),
    );
  }

  const publicKey = proof.slice(
    proofLen - crypto_sign_ed25519_PUBLICKEYBYTES - crypto_sign_ed25519_BYTES,
    proofLen - crypto_sign_ed25519_BYTES,
  );
  const signature = proof.slice(proofLen - crypto_sign_ed25519_BYTES, proofLen);

  return {
    previousCommit,
    numberOfArtifactsBetweenCommitmentAndPublicKey,
    artifactsBetweenCommitmentAndPublicKey,
    artifactsBetweenPublicKeyAndPreviousCommit,
    numberOfArtifactsBetweenPublicKeyAndPreviousCommit,
    publicKey,
    signature,
  };
};

export default deserialize;
