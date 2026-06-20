// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "./IPoseidon2.sol";

contract FieldIncrementalMerkleTree {
    uint256 public constant SNARK_SCALAR_FIELD =
        21888242871839275222246405745257275088548364400416034343698204186575808495617;
    uint32 public constant ROOT_HISTORY_SIZE = 100;

    IPoseidon2 public immutable poseidonHasher;
    uint32 public immutable levels;
    uint64 public nextIndex;
    uint32 public currentRootIndex;

    mapping(uint256 => uint256) public filledSubtrees;
    mapping(uint256 => uint256) public roots;
    mapping(uint256 => uint256) public zeroValues;

    error MerkleTreeDepthOutOfRange();
    error MerkleTreeFull();

    constructor(uint32 treeLevels, IPoseidon2 poseidon) {
        if (treeLevels == 0 || treeLevels > 32) {
            revert MerkleTreeDepthOutOfRange();
        }

        poseidonHasher = poseidon;
        levels = treeLevels;

        uint256 currentZero = merkleHash(0, 0);
        zeroValues[0] = currentZero;

        for (uint32 level = 0; level < treeLevels; level++) {
            filledSubtrees[level] = currentZero;
            currentZero = merkleHash(currentZero, currentZero);
            zeroValues[level + 1] = currentZero;
        }

        for (uint32 index = 0; index < ROOT_HISTORY_SIZE; index++) {
            roots[index] = currentZero;
        }
    }

    function merkleHash(uint256 left, uint256 right) public view returns (uint256) {
        uint256[2] memory input = [left, right];
        return poseidonHasher.poseidon(input);
    }

    function insert(uint256 leaf) internal returns (uint32 leafIndex, uint256 newRoot) {
        uint32 treeLevels = levels;
        uint64 currentNextIndex = nextIndex;
        if (currentNextIndex >= (uint64(1) << treeLevels)) {
            revert MerkleTreeFull();
        }

        uint64 currentIndex = currentNextIndex;
        uint256 currentHash = leaf;

        for (uint32 level = 0; level < treeLevels;) {
            uint256 left;
            uint256 right;

            if (currentIndex & 1 == 0) {
                left = currentHash;
                right = zeroValues[level];
                filledSubtrees[level] = currentHash;
            } else {
                left = filledSubtrees[level];
                right = currentHash;
            }

            currentHash = merkleHash(left, right);
            currentIndex >>= 1;
            unchecked {
                level++;
            }
        }

        uint32 newRootIndex = currentRootIndex + 1;
        if (newRootIndex == ROOT_HISTORY_SIZE) {
            newRootIndex = 0;
        }
        currentRootIndex = newRootIndex;
        roots[newRootIndex] = currentHash;

        leafIndex = uint32(currentNextIndex);
        unchecked {
            nextIndex = currentNextIndex + 1;
        }
        newRoot = currentHash;
    }

    function isKnownRoot(uint256 root) public view returns (bool) {
        if (root == 0) {
            return false;
        }

        uint32 index = currentRootIndex;

        do {
            if (roots[index] == root) {
                return true;
            }

            if (index == 0) {
                index = ROOT_HISTORY_SIZE;
            }

            index -= 1;
        } while (index != currentRootIndex);

        return false;
    }

    function latestRoot() public view returns (uint256) {
        return roots[currentRootIndex];
    }
}
