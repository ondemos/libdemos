import demosMemory from "./memory";

import libdemos from "@libdemos";

import type { LibDemos } from "@libdemos";

const restoreSecret = async (shares: Uint8Array[], module?: LibDemos) => {
  const sharesLen = shares.length;

  const shareItemLen = shares[0].length;
  const lengthVerification = shares.every((v) => v.length === shareItemLen);
  if (!lengthVerification) throw new Error("Shares length varies.");

  const secretLen = shareItemLen - 1;

  const wasmMemory =
    module?.wasmMemory ?? demosMemory.restoreSecretMemory(secretLen, sharesLen);

  const demosModule = module ?? (await libdemos({ wasmMemory })); // await shamirMethodsModule({ wasmMemory });

  const ptr1 = demosModule._malloc(
    sharesLen * (secretLen + 1) * Uint8Array.BYTES_PER_ELEMENT,
  );
  const sharesArray = new Uint8Array(
    wasmMemory.buffer,
    ptr1,
    sharesLen * (secretLen + 1) * Uint8Array.BYTES_PER_ELEMENT,
  );
  for (let i = 0; i < sharesLen; i++) {
    sharesArray.set(shares[i], i * (secretLen + 1));
  }

  const ptr2 = demosModule._malloc(secretLen * Uint8Array.BYTES_PER_ELEMENT);
  const secretArray = new Uint8Array(
    wasmMemory.buffer,
    ptr2,
    secretLen * Uint8Array.BYTES_PER_ELEMENT,
  );

  const result = demosModule._restore_secret(
    sharesLen,
    secretLen,
    sharesArray.byteOffset,
    secretArray.byteOffset,
  );

  demosModule._free(ptr1);

  switch (result) {
    case 0: {
      const sec = Uint8Array.from(secretArray);
      demosModule._free(ptr2);

      return sec;
    }

    case -1: {
      demosModule._free(ptr2);

      throw new Error("Not enough shares provided.");
    }

    case -2: {
      demosModule._free(ptr2);

      throw new Error("Need at most 255 shares.");
    }

    default: {
      demosModule._free(ptr2);

      throw new Error("An unexpected error occured.");
    }
  }
};

export default restoreSecret;
