// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "./FieldIncrementalMerkleTree.sol";
import "./IPlonkVerifier.sol";
import "./IPoseidon2.sol";

contract BraidRegistry is FieldIncrementalMerkleTree {
    uint256 public constant OP_REGISTER_IDENTIFIER = 1;
    uint256 public constant OP_ASSOCIATE_IDENTIFIERS = 2;
    uint256 public constant OP_APPEND_ASSOCIATION = 3;
    uint256 public constant OP_MERGE_ASSOCIATIONS = 4;
    uint256 public constant OP_REFRESH_ASSOCIATION = 5;
    uint256 public constant OP_PRESENT_CREDENTIAL = 6;
    uint256 public constant OP_RECOVER_KEY = 7;
    uint256 public constant OP_UPDATE_IDENTIFIER = 8;

    struct IdentifierRecord {
        bytes32 documentHash;
        bytes32 controllerKeyHash;
        uint256 tagCommitment;
    }

    struct CredentialRecord {
        uint256 commitment;
        bool revoked;
    }

    IPlonkVerifier private immutable verifierLeaf0;
    IPlonkVerifier private immutable verifierLeaf1;
    IPlonkVerifier private immutable verifierLeaf2;
    IPlonkVerifier private immutable verifierLeaf3;
    IPlonkVerifier private immutable verifierLeaf4;

    mapping(bytes32 => IdentifierRecord) public identifiers;
    mapping(bytes32 => uint256) public associations;
    mapping(bytes32 => CredentialRecord) public credentials;
    mapping(uint256 => bool) public nullifiers;

    error InvalidPublicInputCount();
    error InvalidOperation();
    error UnknownRoot();
    error NullifierAlreadyUsed();
    error InvalidProof();
    error IdentifierExists();
    error IdentifierUnknown();
    error AssociationExists();
    error AssociationUnknown();
    error CredentialExists();
    error CredentialUnknown();
    error CredentialAlreadyRevoked();
    error UnsupportedLeafCount();

    event IdentifierRegistered(
        bytes32 indexed didHash,
        uint256 indexed tagCommitment,
        uint32 leafIndex,
        uint256 merkleRoot
    );
    event IdentifierUpdated(
        bytes32 indexed didHash,
        uint256 indexed tagCommitment,
        uint32 leafIndex,
        uint256 merkleRoot
    );
    event AssociationRegistered(
        bytes32 indexed aidHash,
        uint256 indexed commitment,
        uint32 leafIndex,
        uint256 merkleRoot
    );
    event AssociationSuperseded(
        bytes32 indexed oldAidHash,
        bytes32 indexed newAidHash,
        uint256 indexed nullifier,
        uint256 merkleRoot
    );
    event CredentialRegistered(
        bytes32 indexed credentialHash,
        uint256 indexed commitment,
        uint32 leafIndex,
        uint256 merkleRoot
    );
    event CredentialRevoked(bytes32 indexed credentialHash, bytes32 reasonHash);
    event PresentationAccepted(
        bytes32 indexed aidHash,
        bytes32 indexed campaignHash,
        uint256 indexed nullifier,
        uint256 merkleRoot
    );

    constructor(
        uint32 treeLevels,
        IPoseidon2 poseidon,
        IPlonkVerifier[5] memory proofVerifiers
    ) FieldIncrementalMerkleTree(treeLevels, poseidon) {
        verifierLeaf0 = proofVerifiers[0];
        verifierLeaf1 = proofVerifiers[1];
        verifierLeaf2 = proofVerifiers[2];
        verifierLeaf3 = proofVerifiers[3];
        verifierLeaf4 = proofVerifiers[4];
    }

    function registerIdentifier(
        bytes32 didHash,
        bytes32 documentHash,
        bytes32 controllerKeyHash,
        bytes calldata proof,
        uint256[] calldata pubSignals
    ) external {
        if (identifiers[didHash].tagCommitment != 0) {
            revert IdentifierExists();
        }

        _verifyOperationProof(OP_REGISTER_IDENTIFIER, proof, pubSignals);

        uint256 tagCommitment = pubSignals[2];
        (uint32 leafIndex, uint256 root) = insert(tagCommitment);

        identifiers[didHash] = IdentifierRecord({
            documentHash: documentHash,
            controllerKeyHash: controllerKeyHash,
            tagCommitment: tagCommitment
        });

        emit IdentifierRegistered(didHash, tagCommitment, leafIndex, root);
    }

    function updateIdentifier(
        bytes32 didHash,
        bytes32 documentHash,
        bytes32 controllerKeyHash,
        bytes calldata proof,
        uint256[] calldata pubSignals
    ) external {
        IdentifierRecord storage record = _requireIdentifier(didHash);
        _verifyOperationProof(OP_UPDATE_IDENTIFIER, proof, pubSignals);
        _requireLeafCommitment(pubSignals, 0, record.tagCommitment);
        _recordIdentifierUpdate(
            didHash,
            record,
            documentHash,
            controllerKeyHash,
            pubSignals[2]
        );
    }

    function recoverIdentifierKey(
        bytes32 didHash,
        bytes32 aidHash,
        bytes32 documentHash,
        bytes32 controllerKeyHash,
        bytes calldata proof,
        uint256[] calldata pubSignals
    ) external {
        IdentifierRecord storage record = _requireIdentifier(didHash);
        uint256 associationCommitment = _requireActiveAssociation(aidHash);
        _verifyOperationProof(OP_RECOVER_KEY, proof, pubSignals);
        _requireLeafCommitment(pubSignals, 0, associationCommitment);
        _recordIdentifierUpdate(
            didHash,
            record,
            documentHash,
            controllerKeyHash,
            pubSignals[2]
        );
    }

    function registerAssociation(
        bytes32 aidHash,
        bytes calldata proof,
        uint256[] calldata pubSignals
    ) external {
        if (associations[aidHash] != 0) {
            revert AssociationExists();
        }

        _verifyOperationProof(OP_ASSOCIATE_IDENTIFIERS, proof, pubSignals);
        _recordAssociation(aidHash, pubSignals[2]);
    }

    function appendAssociation(
        bytes32 oldAidHash,
        bytes32 newAidHash,
        bytes calldata proof,
        uint256[] calldata pubSignals
    ) external {
        uint256 oldCommitment = _requireActiveAssociation(oldAidHash);
        _verifyOperationProof(OP_APPEND_ASSOCIATION, proof, pubSignals);
        _requireLeafCommitment(pubSignals, 0, oldCommitment);
        delete associations[oldAidHash];
        uint256 root = _recordAssociation(newAidHash, pubSignals[2]);
        emit AssociationSuperseded(oldAidHash, newAidHash, pubSignals[3], root);
    }

    function mergeAssociations(
        bytes32 leftAidHash,
        bytes32 rightAidHash,
        bytes32 newAidHash,
        bytes calldata proof,
        uint256[] calldata pubSignals
    ) external {
        uint256 leftCommitment = _requireActiveAssociation(leftAidHash);
        uint256 rightCommitment = _requireActiveAssociation(rightAidHash);
        _verifyOperationProof(OP_MERGE_ASSOCIATIONS, proof, pubSignals);
        _requireLeafCommitment(pubSignals, 0, leftCommitment);
        _requireLeafCommitment(pubSignals, 1, rightCommitment);
        delete associations[leftAidHash];
        delete associations[rightAidHash];
        uint256 root = _recordAssociation(newAidHash, pubSignals[2]);
        emit AssociationSuperseded(leftAidHash, newAidHash, pubSignals[3], root);
        emit AssociationSuperseded(rightAidHash, newAidHash, pubSignals[3], root);
    }

    function refreshAssociation(
        bytes32 oldAidHash,
        bytes32 newAidHash,
        bytes calldata proof,
        uint256[] calldata pubSignals
    ) external {
        uint256 oldCommitment = _requireActiveAssociation(oldAidHash);
        _verifyOperationProof(OP_REFRESH_ASSOCIATION, proof, pubSignals);
        _requireLeafCommitment(pubSignals, 0, oldCommitment);
        delete associations[oldAidHash];
        uint256 root = _recordAssociation(newAidHash, pubSignals[2]);
        emit AssociationSuperseded(oldAidHash, newAidHash, pubSignals[3], root);
    }

    function registerCredential(
        bytes32 credentialHash,
        bytes32 issuerDidHash,
        bytes32 holderDidHash,
        bytes32 statusHash,
        uint256 commitment
    ) external {
        if (credentials[credentialHash].commitment != 0) {
            revert CredentialExists();
        }

        (uint32 leafIndex, uint256 root) = insert(commitment);
        credentials[credentialHash] = CredentialRecord({
            commitment: commitment,
            revoked: false
        });

        emit CredentialRegistered(credentialHash, commitment, leafIndex, root);
    }

    function revokeCredential(bytes32 credentialHash, bytes32 reasonHash) external {
        CredentialRecord storage record = credentials[credentialHash];
        if (record.commitment == 0) {
            revert CredentialUnknown();
        }
        if (record.revoked) {
            revert CredentialAlreadyRevoked();
        }

        record.revoked = true;
        emit CredentialRevoked(credentialHash, reasonHash);
    }

    function presentCredential(
        bytes32 aidHash,
        bytes32 credentialHash,
        bytes32 campaignHash,
        bytes calldata proof,
        uint256[] calldata pubSignals
    ) external {
        uint256 associationCommitment = _requireActiveAssociation(aidHash);

        CredentialRecord storage credential = credentials[credentialHash];
        if (credential.commitment == 0) {
            revert CredentialUnknown();
        }
        if (credential.revoked) {
            revert CredentialAlreadyRevoked();
        }

        _verifyOperationProof(OP_PRESENT_CREDENTIAL, proof, pubSignals);
        _requireLeafCommitment(pubSignals, 0, associationCommitment);
        _requireLeafCommitment(pubSignals, 1, credential.commitment);

        emit PresentationAccepted(aidHash, campaignHash, pubSignals[3], pubSignals[1]);
    }

    function _recordIdentifierUpdate(
        bytes32 didHash,
        IdentifierRecord storage record,
        bytes32 documentHash,
        bytes32 controllerKeyHash,
        uint256 tagCommitment
    ) internal {
        (uint32 leafIndex, uint256 root) = insert(tagCommitment);
        record.documentHash = documentHash;
        record.controllerKeyHash = controllerKeyHash;
        record.tagCommitment = tagCommitment;

        emit IdentifierUpdated(
            didHash,
            tagCommitment,
            leafIndex,
            root
        );
    }

    function _recordAssociation(
        bytes32 aidHash,
        uint256 commitment
    ) internal returns (uint256 root) {
        if (associations[aidHash] != 0) {
            revert AssociationExists();
        }

        uint32 leafIndex;
        (leafIndex, root) = insert(commitment);
        associations[aidHash] = commitment;

        emit AssociationRegistered(aidHash, commitment, leafIndex, root);
    }

    function _verifyOperationProof(
        uint256 expectedOperation,
        bytes calldata proof,
        uint256[] calldata pubSignals
    ) internal {
        if (pubSignals.length < 4 || pubSignals.length > 8) {
            revert InvalidPublicInputCount();
        }
        if (pubSignals[0] != expectedOperation) {
            revert InvalidOperation();
        }
        if (pubSignals[1] != 0 && !isKnownRoot(pubSignals[1])) {
            revert UnknownRoot();
        }
        if (nullifiers[pubSignals[3]]) {
            revert NullifierAlreadyUsed();
        }
        uint256 leafCount = pubSignals.length - 4;
        IPlonkVerifier verifier = _verifierForLeafCount(leafCount);
        if (address(verifier) == address(0)) {
            revert UnsupportedLeafCount();
        }
        if (!verifier.Verify(proof, pubSignals)) {
            revert InvalidProof();
        }

        nullifiers[pubSignals[3]] = true;
    }

    function _verifierForLeafCount(uint256 leafCount) internal view returns (IPlonkVerifier) {
        if (leafCount == 0) {
            return verifierLeaf0;
        }
        if (leafCount == 1) {
            return verifierLeaf1;
        }
        if (leafCount == 2) {
            return verifierLeaf2;
        }
        if (leafCount == 3) {
            return verifierLeaf3;
        }
        return verifierLeaf4;
    }

    function _requireLeafCommitment(
        uint256[] calldata pubSignals,
        uint256 leafIndex,
        uint256 expectedCommitment
    ) internal pure {
        if (pubSignals[4 + leafIndex] != expectedCommitment) {
            revert InvalidProof();
        }
    }

    function _requireIdentifier(bytes32 didHash)
        internal
        view
        returns (IdentifierRecord storage record)
    {
        record = identifiers[didHash];
        if (record.tagCommitment == 0) {
            revert IdentifierUnknown();
        }
    }

    function _requireActiveAssociation(bytes32 aidHash)
        internal
        view
        returns (uint256 commitment)
    {
        commitment = associations[aidHash];
        if (commitment == 0) {
            revert AssociationUnknown();
        }
    }
}
