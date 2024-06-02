import demosMemory from "./memory";

import libdemos from "@libdemos";

import type { LibDemos } from "@libdemos";

const splitSecret = async (
  secret: Uint8Array,
  sharesLen: number,
  threshold: number,
  module?: LibDemos,
) => {
  const secretLen = secret.length;
  if (secretLen < 2) throw new Error("Need more data.");

  if (threshold < 2) throw new Error("Threshold is less than 2");
  if (sharesLen < threshold) throw new Error("Shares are less than threshold");
  if (sharesLen > 255) throw new Error("Shares exceed 255");

  const wasmMemory =
    module?.wasmMemory ??
    demosMemory.splitSecretMemory(secretLen, sharesLen, threshold);
  const demosModule = module ?? (await libdemos({ wasmMemory })); // await shamirMethodsModule({ wasmMemory });

  const ptr1 = demosModule._malloc(secretLen * Uint8Array.BYTES_PER_ELEMENT);
  const secretArray = new Uint8Array(
    wasmMemory.buffer,
    ptr1,
    secretLen * Uint8Array.BYTES_PER_ELEMENT,
  );
  secretArray.set(secret);

  const ptr2 = demosModule._malloc(
    sharesLen * (secretLen + 1) * Uint8Array.BYTES_PER_ELEMENT,
  );
  const sharesArray = new Uint8Array(
    wasmMemory.buffer,
    ptr2,
    sharesLen * (secretLen + 1) * Uint8Array.BYTES_PER_ELEMENT,
  );

  const result = demosModule._split_secret(
    sharesLen,
    threshold,
    secretLen,
    secretArray.byteOffset,
    sharesArray.byteOffset,
  );

  demosModule._free(ptr1);

  switch (result) {
    case 0: {
      const values: Uint8Array[] = [];
      for (let i = 0; i < sharesLen; i++) {
        values.push(
          sharesArray.slice(i * (secretLen + 1), (i + 1) * (secretLen + 1)),
        );
      }

      demosModule._free(ptr2);

      return values;
    }

    // case -1: {
    //   throw new Error("Threshold is less than 2");
    // }
    //
    // case -2: {
    //   throw new Error("Shares are less than threshold");
    // }
    //
    // case -3: {
    //   throw new Error("Shares exceed 255");
    // }

    default: {
      demosModule._free(ptr2);

      throw new Error("Unexpected error occured");
    }
  }
};

export default splitSecret;
