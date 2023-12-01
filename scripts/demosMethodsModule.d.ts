/// <reference types="emscripten" />

export interface DemosMethodsModule extends EmscriptenModule {
  wasmMemory: WebAssembly.Memory;

  _sha512(
    DATA_LEN: number,
    data: number, // Uint8Array, // byteOffset
    hash: number, // Uint8Array
  ): number;

  _keypair(
    public_key: number, // Uint8Array,
    secret_key: number, // Uint8Array
  ): number;

  _sign(
    signature: number, // Uint8Array,
    DATA_LEN: number,
    data: number, // Uint8Array,
    SECRET_KEY_LEN: number,
    secret_key: number, // Uint8Array,
  ): number;
  _verify(
    DATA_LEN: number,
    data: number, // Uint8Array,
    signature: number, // Uint8Array,
    public_key: number, // Uint8Array,
  ): number;

  _split_secret(
    SHARES_LEN: number,
    THRESHOLD: number,
    SECRET_LEN: number,
    secret: number, // Uint8Array, // byteOffset
    shares: number, // Uint8Array, // byteOffset
  ): number;
  _restore_secret(
    SHARES_LEN: number,
    SECRET_LEN: number,
    shares: number, // Uint8Array,
    secret: number, // Uint8Array,
  ): number;

  _random_bytes(
    SIZE: number,
    array: number, // Uint8Array
  ): number;

  _get_merkle_root(
    LEAVES_LEN: number,
    leaves_hashed: number, // Uint8Array.byteOffset
    root: number, // Uint8Array.byteOffset
  ): number;
  _get_merkle_proof(
    LEAVES_LEN: number,
    leaves_hashed: number, // Uint8Array.byteOffset
    element_hash: number, // Uint8Array.byteOffset
    proof: number, // Uint8Array.byteOffset
  ): number;
  _get_merkle_root_from_proof(
    PROOF_LEN: number,
    element_hash: number, // Uint8Array.byteOffset
    proof: number, // Uint8Array.byteOffset
    root: number, // Uint8Array.byteOffset
  ): number;
  _verify_merkle_proof(
    PROOF_LEN: number,
    element_hash: number, // Uint8Array.byteOffset
    root: number, // Uint8Array.byteOffset
    proof: number, // Uint8Array.byteOffset
  ): number;

  _generate_identities(
    IDENTITIES_LEN: number,
    NONCE_LEN: number,
    nonces: number,
    public_keys: number,
    secret_keys: number,
    reversible_details: number,
    irreversible_details: number,
  ): number;
  _commitment_update_reversible(
    updatedCommit: number,
    previousCommit: number,
    details: number,
  ): number;
  _commitment_update_irreversible(
    updatedCommit: number,
    previousCommit: number,
    details: number,
  ): number;
  _generate_proof(
    PROOF_LEN: number,
    IDENTITIES_LEN: number,
    NONCE_LEN: number,
    commitment: number,
    previousCommit: number,
    nonces: number,
    public_keys: number,
    secret_key: number,
    proof: number,
  ): number;
  _verify_proof(
    PROOF_LEN: number,
    commitment: number, // Uint8Array.byteOffset
    proof: number, // Uint8Array.byteOffset
  ): number;
}

declare const demosMethodsModule: EmscriptenModuleFactory<DemosMethodsModule>;
export default demosMethodsModule;
