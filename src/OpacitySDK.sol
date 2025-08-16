// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity ^0.8.30;

import "@eigenlayer-middleware/BLSSignatureChecker.sol";
import {
    IBLSSignatureChecker, IBLSSignatureCheckerTypes
} from "@eigenlayer-middleware/interfaces/IBLSSignatureChecker.sol";

/**
 * @title OpacitySDK
 * @notice Lightweight SDK for implementing opacity verification
 * @dev Inherit from this contract to add opacity verification capabilities to your contract
 */
abstract contract OpacitySDK {
    /**
     * @notice Struct containing all parameters needed for verification
     * @param quorumNumbers The quorum numbers to check signatures for
     * @param referenceBlockNumber The block number to use as reference for operator set
     * @param nonSignerStakesAndSignature The non-signer stakes and signature data computed off-chain
     * @param userAddress The target address for the operation
     * @param platform The platform identifier
     * @param resource The resource identifier
     * @param value The value associated with the operation
     * @param operatorThreshold The operator threshold value for the operation
     * @param signature The signature string
     */
    struct VerificationParams {
        bytes quorumNumbers;
        uint32 referenceBlockNumber;
        IBLSSignatureCheckerTypes.NonSignerStakesAndSignature nonSignerStakesAndSignature;
        address userAddress;
        string platform;
        string resource;
        string value;
        uint256 operatorThreshold;
        string signature;
    }

    // The BLS signature checker contract
    BLSSignatureChecker public immutable blsSignatureChecker;

    // Constants for stake threshold checking
    uint8 public constant THRESHOLD_DENOMINATOR = 100;
    uint8 public QUORUM_THRESHOLD = 66;
    uint32 public BLOCK_STALE_MEASURE = 300;

    // Custom errors
    error InvalidSignature();
    error InsufficientQuorumThreshold();
    error StaleBlockNumber();
    error FutureBlockNumber();

    /**
     * @notice Constructor for OpacitySDK
     * @param _blsSignatureChecker Address of the deployed BLS signature checker contract
     */
    constructor(address _blsSignatureChecker) {
        require(_blsSignatureChecker != address(0), "Invalid BLS signature checker address");
        blsSignatureChecker = BLSSignatureChecker(_blsSignatureChecker);
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

        // Calculate message hash from parameters
        bytes32 msgHash = keccak256(
            abi.encode(
                params.userAddress,
                params.platform,
                params.resource,
                params.value,
                params.operatorThreshold,
                params.signature
            )
        );

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
