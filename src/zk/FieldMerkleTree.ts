import { fieldHash2, modField } from "../utils/field.ts";

export interface FieldMerkleProof {
  leaf: bigint;
  leafIndex: number;
  pathElements: bigint[];
  pathIndices: number[];
  root: bigint;
}

function nodeKey(level: number, index: number): string {
  return `${level}:${index}`;
}

export class FieldMerkleTree {
  readonly depth: number;
  readonly zeroValues: bigint[];
  readonly leaves: bigint[];
  readonly nodes: Map<string, bigint>;

  constructor(depth = 32) {
    if (depth < 1 || depth > 32) {
      throw new Error("Field Merkle tree depth must be between 1 and 32");
    }

    this.depth = depth;
    this.leaves = [];
    this.nodes = new Map();
    this.zeroValues = [];
    this.zeroValues[0] = fieldHash2(0n, 0n);

    for (let level = 1; level <= depth; level += 1) {
      this.zeroValues[level] = this.hashPair(
        this.zeroValues[level - 1],
        this.zeroValues[level - 1],
      );
    }
  }

  hashPair(left: bigint, right: bigint): bigint {
    return fieldHash2(left, right);
  }

  insert(leaf: bigint): { index: number; root: bigint } {
    if (this.leaves.length >= 2 ** this.depth) {
      throw new Error("Field Merkle tree is full");
    }

    const index = this.leaves.length;
    const normalizedLeaf = modField(leaf);
    this.leaves.push(normalizedLeaf);
    this.nodes.set(nodeKey(0, index), normalizedLeaf);

    let currentHash = normalizedLeaf;
    let currentIndex = index;

    for (let level = 0; level < this.depth; level += 1) {
      const isRightNode = currentIndex % 2 === 1;
      const siblingIndex = isRightNode ? currentIndex - 1 : currentIndex + 1;
      const sibling =
        this.nodes.get(nodeKey(level, siblingIndex)) ?? this.zeroValues[level];
      const left = isRightNode ? sibling : currentHash;
      const right = isRightNode ? currentHash : sibling;

      currentHash = this.hashPair(left, right);
      currentIndex = Math.floor(currentIndex / 2);
      this.nodes.set(nodeKey(level + 1, currentIndex), currentHash);
    }

    return {
      index,
      root: currentHash,
    };
  }

  getRoot(): bigint {
    return (
      this.nodes.get(nodeKey(this.depth, 0)) ?? this.zeroValues[this.depth]
    );
  }

  generateProof(leafIndex: number): FieldMerkleProof {
    if (leafIndex < 0 || leafIndex >= this.leaves.length) {
      throw new Error(`Unknown leaf index ${leafIndex}`);
    }

    const pathElements: bigint[] = [];
    const pathIndices: number[] = [];
    let index = leafIndex;

    for (let level = 0; level < this.depth; level += 1) {
      const siblingIndex = index ^ 1;
      pathElements.push(
        this.nodes.get(nodeKey(level, siblingIndex)) ?? this.zeroValues[level],
      );
      pathIndices.push(index & 1);
      index = Math.floor(index / 2);
    }

    return {
      leaf: this.leaves[leafIndex],
      leafIndex,
      pathElements,
      pathIndices,
      root: this.getRoot(),
    };
  }
}
