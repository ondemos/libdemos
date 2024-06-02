import ondemos from "../src";

describe("Merkle test suite.", () => {
  test("Merkle root calculation works.", async () => {
    const tree: Uint8Array[] = [];
    const dataLen = 128;
    const leavesLen = 201;

    const randomBytesMemory = ondemos.loadWasmMemory.randomBytes(dataLen);
    const randomBytesModule = await ondemos.loadWasmModule({
      wasmMemory: randomBytesMemory,
    });
    for (let i = 0; i < leavesLen; i++) {
      const rand = await ondemos.randomBytes(dataLen, randomBytesModule);
      tree.push(rand);
    }

    const root = await ondemos.getMerkleRoot(tree);
    const root2 = await ondemos.getMerkleRoot(tree);

    expect(root.length).toBe(64);
    expect(root[0]).toBe(root2[0]);
    expect(root[1]).toBe(root2[1]);
    expect(root[63]).toBe(root2[63]);
  });

  test("Merkle proof should be able to recalculate Merkle root.", async () => {
    const tree: Uint8Array[] = [];
    const element = new Uint8Array(128);
    const elements = 201;
    const elementIndex = 99;
    const anotherElementIndex = 168;

    const randomBytesMemory = ondemos.loadWasmMemory.randomBytes(elements);
    const randomBytesModule = await ondemos.loadWasmModule({
      wasmMemory: randomBytesMemory,
    });
    for (let i = 0; i < elements; i++) {
      const rand = await ondemos.randomBytes(128, randomBytesModule);

      if (i === elementIndex) element.set([...rand]);

      tree.push(rand);
    }

    const root = await ondemos.getMerkleRoot(tree);

    const proof = await ondemos.getMerkleProof(tree, tree[elementIndex]);

    const elementHash = await ondemos.sha512(element);

    const rootCalculated = await ondemos.getMerkleRootFromProof(
      elementHash,
      proof,
    );

    const anotherProof = await ondemos.getMerkleProof(
      tree,
      tree[anotherElementIndex],
    );

    const anotherElementHash = await ondemos.sha512(tree[anotherElementIndex]);

    const anotherRootCalculated = await ondemos.getMerkleRootFromProof(
      anotherElementHash,
      anotherProof,
    );

    expect(root).toStrictEqual(rootCalculated);
    expect(rootCalculated).toStrictEqual(anotherRootCalculated);

    proof[ondemos.constants.crypto_hash_sha512_BYTES] = 2;
    await expect(
      ondemos.getMerkleRootFromProof(elementHash, proof),
    ).rejects.toThrow("Proof artifact position is neither left nor right.");
  });

  test("Merkle proof verification works for odd number of elements.", async () => {
    const tree: Uint8Array[] = [];
    const element = new Uint8Array(128);
    const elements = 201;
    const elementIndex = 139;

    const randomBytesMemory = ondemos.loadWasmMemory.randomBytes(elements);
    const randomBytesModule = await ondemos.loadWasmModule({
      wasmMemory: randomBytesMemory,
    });
    for (let i = 0; i < elements; i++) {
      const rand = await ondemos.randomBytes(128, randomBytesModule);

      if (i === elementIndex) element.set([...rand]);

      tree.push(rand);
    }

    const root = await ondemos.getMerkleRoot(tree);

    const proof = await ondemos.getMerkleProof(tree, tree[elementIndex]);

    const elementHash = await ondemos.sha512(element);

    const verification = await ondemos.verifyMerkleProof(
      elementHash,
      root,
      proof,
    );

    expect(verification).toBe(true);
  });

  test("Merkle proof verification works for even number of elements.", async () => {
    const tree: Uint8Array[] = [];
    const element = new Uint8Array(128);
    const elements = 200;
    const elementIndex = 161;

    const randomBytesMemory = ondemos.loadWasmMemory.randomBytes(elements);
    const randomBytesModule = await ondemos.loadWasmModule({
      wasmMemory: randomBytesMemory,
    });
    for (let i = 0; i < elements; i++) {
      const rand = await ondemos.randomBytes(128, randomBytesModule);

      if (i === elementIndex) element.set([...rand]);

      tree.push(rand);
    }

    const root = await ondemos.getMerkleRoot(tree);

    const proof = await ondemos.getMerkleProof(tree, tree[elementIndex]);

    const elementHash = await ondemos.sha512(element);

    const verification = await ondemos.verifyMerkleProof(
      elementHash,
      root,
      proof,
    );

    expect(verification).toBe(true);
  });

  it("Should throw an error when faced with false data.", async () => {
    const tree: Uint8Array[] = [];
    const element = new Uint8Array(128);
    const elements = 201;
    const elementIndex = 99;

    const randomBytesMemory = ondemos.loadWasmMemory.randomBytes(elements);
    const randomBytesModule = await ondemos.loadWasmModule({
      wasmMemory: randomBytesMemory,
    });
    for (let i = 0; i < elements; i++) {
      const rand = await ondemos.randomBytes(128, randomBytesModule);

      if (i === elementIndex) element.set([...rand]);

      tree.push(rand);
    }

    const root = await ondemos.getMerkleRoot(tree);
    const proof = await ondemos.getMerkleProof(tree, tree[elementIndex]);
    const elementHash = await ondemos.sha512(element);

    await expect(
      ondemos.verifyMerkleProof(
        elementHash,
        root,
        proof.slice(0, proof.length - 1),
      ),
    ).rejects.toThrow("Proof length not multiple of hash length + 1.");

    const proofWrongPosition = Uint8Array.from([...proof]);
    proofWrongPosition[ondemos.constants.crypto_hash_sha512_BYTES] = 2;
    await expect(
      ondemos.verifyMerkleProof(elementHash, root, proofWrongPosition),
    ).rejects.toThrow("Proof artifact position is neither left nor right.");

    const proofWrongByte = Uint8Array.from([...proof]);
    proofWrongByte[1] = proof[1] === 255 ? 254 : proof[1] + 1;

    const verification = await ondemos.verifyMerkleProof(
      elementHash,
      root,
      proofWrongByte,
    );

    expect(verification).toBe(false);
  });
});
