export interface CommitmentOwnershipProof {
  previousCommit: Uint8Array;
  numberOfArtifactsBetweenCommitmentAndPublicKey: number;
  numberOfArtifactsBetweenPublicKeyAndPreviousCommit: number;
  artifactsBetweenCommitmentAndPublicKey: Uint8Array[];
  artifactsBetweenPublicKeyAndPreviousCommit: Uint8Array[];
  publicKey: Uint8Array;
  signature: Uint8Array;
}

export const crypto_hash_sha512_BYTES = 64 * Uint8Array.BYTES_PER_ELEMENT;
export const crypto_sign_ed25519_BYTES = 64 * Uint8Array.BYTES_PER_ELEMENT;
export const crypto_sign_ed25519_PUBLICKEYBYTES = 32;
export const crypto_sign_ed25519_SECRETKEYBYTES = 64;

export default {
  crypto_hash_sha512_BYTES,
  crypto_sign_ed25519_BYTES,
  crypto_sign_ed25519_PUBLICKEYBYTES,
  crypto_sign_ed25519_SECRETKEYBYTES,
};
