/// <reference types="emscripten" />

export interface LibDemos extends EmscriptenModule {
  wasmMemory: WebAssembly.Memory;

  _sha512(
    DATA_LEN: number,
    data: number,
    hash: number
  ): number;

  _argon2(
    MNEMONIC_LEN: number,
    seed: number,
    mnemonic: number,
    salt: number
  ): number;

  _keypair(
    public_key: number, // Uint8Array,
    secret_key: number, // Uint8Array
  ): number;

  _keypair_from_seed(
    public_key: number, // Uint8Array,
    secret_key: number, // Uint8Array,
    seed: number, // Uint8Array,
  ): number;
  _keypair_from_secret_key(
    public_key: number, // Uint8Array,
    secret_key: number, // Uint8Array,
  ): number;

  _sign(
    DATA_LEN: number,
    data: number, // Uint8Array,
    secret_key: number, // Uint8Array,
    signature: number, // Uint8Array,
  ): number;
  _verify(
    DATA_LEN: number,
    data: number, // Uint8Array,
    public_key: number, // Uint8Array,
    signature: number, // Uint8Array,
  ): number;

  _encrypt_chachapoly_asymmetric(
    DATA_LEN: number,
    data: number, // Uint8Array,
    public_key: number, // Uint8Array,
    secret_key: number, // Uint8Array,
    ADDITIONAL_DATA_LEN: number,
    additional_data: number, // Uint8Array,
    encrypted: number, // Uint8Array,
  ): number;
  
  _decrypt_chachapoly_asymmetric(
    ENCRYPTED_LEN: number,
    encrypted_data: number, // Uint8Array,
    public_key: number, // Uint8Array,
    secret_key: number, // Uint8Array,
    ADDITIONAL_DATA_LEN: number,
    additional_data: number, // Uint8Array,
    data: number, // Uint8Array,
  ): number;

  _encrypt_chachapoly_symmetric(
    DATA_LEN: number, 
    data: number,
    key: number,
    ADDITIONAL_DATA_LEN: number,
    additional_data: number,
    encrypted: number,
  ): number;

  _decrypt_chachapoly_symmetric(
    ENCRYPTED_LEN: number,
    encrypted_data: number, // Uint8Array,
    key: number, // Uint8Array,
    ADDITIONAL_DATA_LEN: number,
    additional_data: number, // Uint8Array,
    data: number, // Uint8Array,
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
  _random_number_in_range(
    MIN: number,
    MAX: number,
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
    nonces: number,
    public_keys: number,
    secret_keys: number,
    commit_details: number,
  ): number;
  _commit(
    updatedCommit: number,
    previousCommit: number,
    details: number,
  ): number;
  _generate_proof(
    PROOF_LEN: number,
    IDENTITIES_LEN: number,
    currentCommit: number,
    previousCommit: number,
    nonces: number,
    public_keys: number,
    secret_key: number,
    proof: number,
  ): number;
  _verify_proof(
    PROOF_LEN: number,
    currentCommit: number, // Uint8Array.byteOffset
    proof: number, // Uint8Array.byteOffset
  ): number;
}

declare const libdemos: EmscriptenModuleFactory<LibDemos>;
export default libdemos;
