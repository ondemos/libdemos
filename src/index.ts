import commitment from "./commitment";
import merkle from "./merkle";
import shamir from "./shamir";
import utils from "./utils";

import type { SignKeyPair, Proof } from "./utils/interfaces";

import libdemos from "@libdemos";

const ondemos = {
  generateIdentities: commitment.generateIdentities,
  generateProof: commitment.generateProof,
  commit: commitment.commit,
  verifyProof: commitment.verifyProof,

  randomBytes: utils.randomBytes,
  randomShuffle: utils.arrayRandomShuffle,
  randomSubset: utils.arrayRandomSubset,
  randomNumber: utils.randomNumberInRange,
  sha512: utils.sha512,
  argon2: utils.argon2,
  keyPair: utils.keyPair.newKeyPair,
  keyPairFromSeed: utils.keyPair.keyPairFromSeed,
  keyPairFromSecretKey: utils.keyPair.keyPairFromSecretKey,
  sign: utils.sign,
  verify: utils.verify,
  encryptAsymmetric: utils.encryptAsymmetric,
  decryptAsymmetric: utils.decryptAsymmetric,
  encryptSymmetric: utils.encryptSymmetric,
  decryptSymmetric: utils.decryptSymmetric,
  generateMnemonic: utils.generateMnemonic,
  keyPairFromMnemonic: utils.keyPairFromMnemonic,
  validateMnemonic: utils.validateMnemonic,
  wordlist: utils.wordlist,

  getMerkleRoot: merkle.getMerkleRoot,
  getMerkleProof: merkle.getMerkleProof,
  getMerkleRootFromProof: merkle.getMerkleRootFromProof,
  verifyMerkleProof: merkle.verifyMerkleProof,

  splitSecret: shamir.splitSecret,
  restoreSecret: shamir.restoreSecret,

  loadWasmModule: libdemos,
  loadWasmMemory: {
    generateIdentities: commitment.memory.generateIdentitiesMemory,
    generateProof: commitment.memory.generateProofMemory,
    commit: commitment.memory.commitMemory,
    verifyProof: commitment.memory.verifyProofMemory,
    randomBytes: utils.memory.randomBytes,
    sha512: utils.memory.sha512Memory,
    argon2: utils.memory.argon2Memory,
    keyPair: utils.memory.newKeyPairMemory,
    keyPairFromSeed: utils.memory.keyPairFromSeedMemory,
    keyPairFromSecretKey: utils.memory.keyPairFromSecretKeyMemory,
    sign: utils.memory.signMemory,
    verify: utils.memory.verifyMemory,
    encryptAsymmetric: utils.memory.encryptAsymmetricMemory,
    decryptAsymmetric: utils.memory.decryptAsymmetricMemory,
    encryptSymmetric: utils.memory.encryptSymmetricMemory,
    decryptSymmetric: utils.memory.decryptSymmetricMemory,
  },

  constants: {
    commit_BYTES: utils.interfaces.commitLen,
    commit_details_BYTES: utils.interfaces.commitDetailsLen,
    commit_nonce_BYTES: utils.interfaces.nonceLen,
    getProofLen: utils.interfaces.getProofLen,
    crypto_hash_sha512_BYTES: utils.interfaces.crypto_hash_sha512_BYTES,
    crypto_box_poly1305_AUTHTAGBYTES:
      utils.interfaces.crypto_box_poly1305_AUTHTAGBYTES,
    crypto_box_x25519_PUBLICKEYBYTES:
      utils.interfaces.crypto_box_x25519_PUBLICKEYBYTES,
    crypto_box_x25519_SECRETKEYBYTES:
      utils.interfaces.crypto_box_x25519_SECRETKEYBYTES,
    crypto_box_x25519_NONCEBYTES: utils.interfaces.crypto_box_x25519_NONCEBYTES,
    crypto_kx_SESSIONKEYBYTES: utils.interfaces.crypto_kx_SESSIONKEYBYTES,
    crypto_sign_ed25519_BYTES: utils.interfaces.crypto_sign_ed25519_BYTES,
    crypto_sign_ed25519_SEEDBYTES:
      utils.interfaces.crypto_sign_ed25519_SEEDBYTES,
    crypto_sign_ed25519_PUBLICKEYBYTES:
      utils.interfaces.crypto_sign_ed25519_PUBLICKEYBYTES,
    crypto_sign_ed25519_SECRETKEYBYTES:
      utils.interfaces.crypto_sign_ed25519_SECRETKEYBYTES,
  },
};

export { SignKeyPair, Proof };

export default ondemos;
