// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity ^0.8.30;

import "@eigenlayer-middleware/BLSSignatureChecker.sol";
import {IBLSSignatureCheckerTypes} from "@eigenlayer-middleware/interfaces/IBLSSignatureChecker.sol";
import {IOpacitySDK} from "./IOpacitySDK.sol";

/**
 * @title OpacitySDK
 * @notice Lightweight SDK for implementing opacity verification
 * @dev Inherit from this contract to add opacity verification capabilities to your contract
 */
abstract contract OpacitySDK is IOpacitySDK {
    // The BLS signature checker contract
    BLSSignatureChecker public immutable blsSignatureChecker;

    // Constants for stake threshold checking
    uint8 public constant THRESHOLD_DENOMINATOR = 100;
    uint8 public QUORUM_THRESHOLD = 66;
    uint32 public BLOCK_STALE_MEASURE = 300;

    /**
     * @notice Constructor for OpacitySDK
     * @param _blsSignatureChecker Address of the deployed BLS signature checker contract
     */
    constructor(address _blsSignatureChecker) {
        require(_blsSignatureChecker != address(0), "Invalid BLS signature checker address");
        blsSignatureChecker = BLSSignatureChecker(_blsSignatureChecker);
    }

    /**
     * @notice Compute the payload hash for signature verification
     * @dev Implements UID(ProtoTag, UserAddr, P) where P is the commitment payload
     * @param payload The commitment payload
     * @return The payload hash
     */
    function computePayloadHash(CommitmentPayload memory payload) public pure returns (bytes32) {
        // Protocol tag for versioning (commented out for now)
        // bytes32 protoTag = keccak256("OPACITY-v1");

        // Hash the entire payload structure
        bytes32 payloadHash =
            keccak256(abi.encode(payload.userAddr, payload.values, payload.compositions, payload.conditions));

        // return keccak256(abi.encode(protoTag, payload.userAddr, payloadHash));
        return payloadHash;
    }

    /**
     * @notice Function to verify if a signature is valid
     * @param params The verification parameters wrapped in a struct
     * @return success Whether the verification succeeded
     */
    function verify(VerificationParams calldata params) external view returns (bool success) {
        // Check block number validity
        require(params.referenceBlockNumber < block.number, FutureBlockNumber());
        require((params.referenceBlockNumber + BLOCK_STALE_MEASURE) >= uint32(block.number), StaleBlockNumber());

        // Calculate message hash from the commitment payload
        // Signature is over UID(ProtoTag, UserAddr, P)
        bytes32 msgHash = computePayloadHash(params.payload);

        // Verify the signatures using checkSignatures
        (IBLSSignatureCheckerTypes.QuorumStakeTotals memory stakeTotals,) = blsSignatureChecker.checkSignatures(
            msgHash, params.quorumNumbers, params.referenceBlockNumber, params.nonSignerStakesAndSignature
        );

        // Check that signatories own at least 66% of each quorum
        for (uint256 i = 0; i < params.quorumNumbers.length; i++) {
            require(
                stakeTotals.signedStakeForQuorum[i] * THRESHOLD_DENOMINATOR
                    >= stakeTotals.totalStakeForQuorum[i] * QUORUM_THRESHOLD,
                InsufficientQuorumThreshold()
            );
        }

        return true;
    }

    /**
     * @notice Get the current quorum threshold
     * @return The current quorum threshold percentage
     */
    function getQuorumThreshold() external view returns (uint8) {
        return QUORUM_THRESHOLD;
    }

    /**
     * @notice Get the block stale measure
     * @return The number of blocks after which a reference block is considered stale
     */
    function getBlockStaleMeasure() external view returns (uint32) {
        return BLOCK_STALE_MEASURE;
    }
}
