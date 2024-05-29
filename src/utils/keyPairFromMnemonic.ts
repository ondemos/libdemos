import validateMnemonic from "./validateMnemonic";

import sha512 from "./sha512";
import argon2 from "./argon2";

import keyPair from "./keyPair";

import {
  crypto_pwhash_argon2id_SALTBYTES,
  crypto_hash_sha512_BYTES,
} from "../utils/interfaces";

/**
 * Generates an Ed25519 key pair from the provided mnemonic.
 * Optionally, you can strenthen the generation with a password.
 * The mnemonic is converted into a seed through the use of argon2id.
 * The password is used as a salt for argon2id.
 * From the generated seed we extract the key pair.
 *
 * @param mnemonic - Sequence of words from the predefined wordlist
 * @param password - Optional salt for the seed derivation
 * @returns An Ed25519 key pair
 */
const keyPairFromMnemonic = async (mnemonic: string, password?: string) => {
  const isValid = await validateMnemonic(mnemonic);
  if (!isValid) throw new Error("Invalid mnemonic.");

  // const defaultSalt = Uint8Array.from(Buffer.from("password12345678", "utf8"));
  const defaultSalt = new Uint8Array(crypto_pwhash_argon2id_SALTBYTES);
  const encoder = new TextEncoder();
  encoder.encodeInto("password12345678", defaultSalt);
  const salt = new Uint8Array(crypto_pwhash_argon2id_SALTBYTES);

  if (password) {
    const pwdBuffer = encoder.encode(password).buffer;
    const pwdHash = await sha512(new Uint8Array(pwdBuffer));

    salt.set(
      pwdHash.slice(
        crypto_hash_sha512_BYTES - crypto_pwhash_argon2id_SALTBYTES,
        crypto_hash_sha512_BYTES,
      ),
    );
  } else {
    salt.set(defaultSalt);
  }

  const seed = await argon2(mnemonic, salt);

  const keypair = await keyPair.keyPairFromSeed(seed);
  if (!keypair) throw new Error("Invalid seed from mnemonic.");

  return keypair;
};

export default keyPairFromMnemonic;
