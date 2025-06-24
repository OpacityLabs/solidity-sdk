// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity ^0.8.0;

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
    // The BLS signature checker contract
    BLSSignatureChecker public immutable blsSignatureChecker;
    // The address of the BLS signature checker contract
    address public constant BLS_SIG_CHECKER = address(0x259eD6dA3455De487e2a143594A4BE6f4b915716); //TODO remove hardcoded address

    // Constants for stake threshold checking
    uint8 public constant THRESHOLD_DENOMINATOR = 100;
    uint8 public QUORUM_THRESHOLD = 1;
    uint32 public BLOCK_STALE_MEASURE = 300;

    // Custom errors
    error InvalidSignature();
    error InsufficientQuorumThreshold();
    error StaleBlockNumber();
    error FutureBlockNumber();

    constructor() {
        blsSignatureChecker = BLSSignatureChecker(BLS_SIG_CHECKER);
    }

    /**
     * @notice Function to verify if a signature is valid
     * @param quorumNumbers The quorum numbers to check signatures for
     * @param referenceBlockNumber The block number to use as reference for operator set
     * @param nonSignerStakesAndSignature The non-signer stakes and signature data computed off-chain
     * @param targetAddress The target address for the operation
     * @param platform The platform identifier
     * @param resource The resource identifier
     * @param value The value associated with the operation
     * @param threshold The threshold value for the operation
     * @param signature The signature string
     * @param operatorCount The number of operators
     * @return stakeTotals The stake totals for verification
     * @return signatoryRecordHash The hash of signatory record
     */
    function verify(
        bytes calldata quorumNumbers,
        uint32 referenceBlockNumber,
        IBLSSignatureCheckerTypes.NonSignerStakesAndSignature calldata nonSignerStakesAndSignature,
        address targetAddress,
        string calldata platform,
        string calldata resource,
        string calldata value,
        uint256 threshold,
        string calldata signature,
        uint256 operatorCount
    ) external view returns (
        IBLSSignatureCheckerTypes.QuorumStakeTotals memory stakeTotals,
        bytes32 signatoryRecordHash
    ) {
        // Check block number validity
        require(referenceBlockNumber < block.number, FutureBlockNumber());
        require((referenceBlockNumber + BLOCK_STALE_MEASURE) >= uint32(block.number), StaleBlockNumber());

        // Calculate message hash from parameters
        bytes32 msgHash = keccak256(abi.encode(
            targetAddress,
            platform,
            resource,
            value,
            threshold,
            signature,
            operatorCount
        ));

        // Verify the signatures using checkSignatures
        (stakeTotals, signatoryRecordHash) =
        blsSignatureChecker.checkSignatures(msgHash, quorumNumbers, referenceBlockNumber, nonSignerStakesAndSignature);

        // Check that signatories own at least 66% of each quorum
        for (uint256 i = 0; i < quorumNumbers.length; i++) {
            require(
                stakeTotals.signedStakeForQuorum[i] * THRESHOLD_DENOMINATOR
                    >= stakeTotals.totalStakeForQuorum[i] * QUORUM_THRESHOLD,
                InsufficientQuorumThreshold()
            );
        }
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