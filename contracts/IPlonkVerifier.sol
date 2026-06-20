// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

interface IPlonkVerifier {
    function Verify(bytes calldata proof, uint256[] calldata public_inputs)
        external
        view
        returns (bool);
}
