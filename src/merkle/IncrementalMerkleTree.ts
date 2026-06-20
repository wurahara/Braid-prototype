import { braidHash } from "../crypto/index.ts";

export interface IncrementalMerkleTreeSnapshot {
  depth: number;
  label: string;
  rootHistorySize: number;
  nextIndex: number;
  currentRootIndex: number;
  zeros: string[];
  filledSubtrees: string[];
  roots: string[];
}

export class IncrementalMerkleTree {
  depth: number;
  label: string;
  rootHistorySize: number;
  nextIndex: number;
  currentRootIndex: number;
  zeros: string[];
  filledSubtrees: string[];
  roots: string[];

  constructor(
    options: { depth?: number; label?: string; rootHistorySize?: number } = {},
  ) {
    const depth = options.depth ?? 20;
    if (depth < 1 || depth > 32) {
      throw new Error("Merkle tree depth must be between 1 and 32");
    }

    this.depth = depth;
    this.label = options.label ?? "braid-tree";
    this.rootHistorySize = options.rootHistorySize ?? 100;
    this.nextIndex = 0;
    this.currentRootIndex = 0;
    this.zeros = [];
    this.filledSubtrees = [];
    this.roots = new Array(this.rootHistorySize);

    this.zeros[0] = braidHash({ label: this.label, level: 0, value: "zero" });

    for (let level = 1; level <= depth; level += 1) {
      this.zeros[level] = this.hashPair(
        level - 1,
        this.zeros[level - 1],
        this.zeros[level - 1],
      );
    }

    for (let level = 0; level < depth; level += 1) {
      this.filledSubtrees[level] = this.zeros[level];
    }

    this.roots.fill(this.zeros[depth]);
  }

  static fromSnapshot(
    snapshot: IncrementalMerkleTreeSnapshot,
  ): IncrementalMerkleTree {
    const tree = new IncrementalMerkleTree({
      depth: snapshot.depth,
      label: snapshot.label,
      rootHistorySize: snapshot.rootHistorySize,
    });

    tree.nextIndex = snapshot.nextIndex;
    tree.currentRootIndex = snapshot.currentRootIndex;
    tree.zeros = [...snapshot.zeros];
    tree.filledSubtrees = [...snapshot.filledSubtrees];
    tree.roots = [...snapshot.roots];

    return tree;
  }

  hashPair(level: number, left: string, right: string): string {
    return braidHash({
      label: this.label,
      left,
      level,
      right,
    });
  }

  insert(leaf: string): { index: number; root: string } {
    if (this.nextIndex >= 2 ** this.depth) {
      throw new Error("Merkle tree is full");
    }

    let currentIndex = this.nextIndex;
    let currentHash = leaf;

    for (let level = 0; level < this.depth; level += 1) {
      let left: string;
      let right: string;

      if (currentIndex % 2 === 0) {
        left = currentHash;
        right = this.zeros[level];
        this.filledSubtrees[level] = currentHash;
      } else {
        left = this.filledSubtrees[level];
        right = currentHash;
      }

      currentHash = this.hashPair(level, left, right);
      currentIndex = Math.floor(currentIndex / 2);
    }

    this.currentRootIndex = (this.currentRootIndex + 1) % this.rootHistorySize;
    this.roots[this.currentRootIndex] = currentHash;

    const leafIndex = this.nextIndex;
    this.nextIndex += 1;

    return {
      index: leafIndex,
      root: currentHash,
    };
  }

  getRoot(): string {
    return this.roots[this.currentRootIndex];
  }

  isKnownRoot(root: string): boolean {
    return this.roots.includes(root);
  }

  snapshot(): IncrementalMerkleTreeSnapshot {
    return {
      depth: this.depth,
      label: this.label,
      rootHistorySize: this.rootHistorySize,
      nextIndex: this.nextIndex,
      currentRootIndex: this.currentRootIndex,
      zeros: [...this.zeros],
      filledSubtrees: [...this.filledSubtrees],
      roots: [...this.roots],
    };
  }
}
