const sha512 = async (data: Uint8Array) => {
  const crypto = globalThis.crypto;
  const h = await crypto.subtle.digest("SHA-512", data);

  return new Uint8Array(h);
};

export default sha512;
