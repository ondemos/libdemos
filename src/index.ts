import commitment from "./commitment";
import utils from "./utils";

import type { CommitmentOwnershipProof } from "./utils/interfaces";

import demosMethodsModule from "../build/demosMethodsModule";

const libdemos = {
  generateIdentities: commitment.generateIdentities,
  generateProof: commitment.generateProof,
  commit: commitment.commit,
  verifyProof: commitment.verifyProof,

  loadWasmModule: demosMethodsModule,
  loadWasmMemory: {
    generateCommitmentDetails:
      commitment.memory.generateCommitmentDetailsMemory,
    generateProof: commitment.memory.generateProofMemory,
    commit: commitment.memory.commitMemory,
    verifyProof: commitment.memory.verifyProofMemory,
  },

  constants: {
    commitment_BYTES: utils.interfaces.crypto_hash_sha512_BYTES,
    commitment_details_reversible_BYTES:
      2 * utils.interfaces.crypto_hash_sha512_BYTES,
    commitment_details_irreversible_BYTES:
      utils.interfaces.crypto_hash_sha512_BYTES,
  },
};

export { CommitmentOwnershipProof };

export default libdemos;
