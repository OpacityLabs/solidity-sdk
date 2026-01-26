// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity ^0.8.30;

import "@eigenlayer-middleware/BLSSignatureChecker.sol";
import {IBLSSignatureCheckerTypes} from "@eigenlayer-middleware/interfaces/IBLSSignatureChecker.sol";
import {BN254} from "@eigenlayer-middleware/libraries/BN254.sol";

/**
 * @title OpacitySDK
 * @notice Lightweight SDK for implementing opacity verification
 * @dev Inherit from this contract to add opacity verification capabilities to your contract
 */
abstract contract OpacitySDK {
    // Sentinel value indicating watchtower signed (not in nonSignerPubkeys array)
    uint32 public constant WATCHTOWER_SIGNED = type(uint32).max;

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
     * @param watchtowerNonSignerIndex Index of watchtower in nonSignerPubkeys array, or WATCHTOWER_SIGNED if watchtower signed
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
        uint32 watchtowerNonSignerIndex;
    }

    // The BLS signature checker contract
    BLSSignatureChecker public immutable blsSignatureChecker;

    // Watchtower's BLS public key (G1 point on BN254 curve)
    BN254.G1Point public watchtowerPubkey;

    // Whether watchtower verification is enabled (default: true)
    bool public watchtowerEnabled = true;

    // Constants for stake threshold checking
    uint8 public constant THRESHOLD_DENOMINATOR = 100;
    uint8 public QUORUM_THRESHOLD = 1;
    uint32 public BLOCK_STALE_MEASURE = 300;

    // Events
    event WatchtowerPubkeyUpdated(uint256 oldX, uint256 oldY, uint256 newX, uint256 newY);
    event WatchtowerStatusChanged(bool enabled);

    // Custom errors
    error InvalidSignature();
    error InsufficientQuorumThreshold();
    error StaleBlockNumber();
    error FutureBlockNumber();
    error WatchtowerDidNotSign();
    error InvalidWatchtowerPubkey();
    error InvalidWatchtowerNonSignerIndex();

    /**
     * @notice Constructor for OpacitySDK
     * @param _blsSignatureChecker Address of the deployed BLS signature checker contract
     * @param _watchtowerPubkey The watchtower's BLS public key (G1 point)
     */
    constructor(address _blsSignatureChecker, BN254.G1Point memory _watchtowerPubkey) {
        require(_blsSignatureChecker != address(0), "Invalid BLS signature checker address");
        require(_watchtowerPubkey.X != 0 || _watchtowerPubkey.Y != 0, "Invalid watchtower pubkey");
        blsSignatureChecker = BLSSignatureChecker(_blsSignatureChecker);
        watchtowerPubkey = _watchtowerPubkey;
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

        // Verify operator quorum via BLS signature check
        (IBLSSignatureCheckerTypes.QuorumStakeTotals memory stakeTotals,) = blsSignatureChecker.checkSignatures(
            msgHash, params.quorumNumbers, params.referenceBlockNumber, params.nonSignerStakesAndSignature
        );

        // Check that signatories own at least the required threshold of each quorum
        for (uint256 i = 0; i < params.quorumNumbers.length; i++) {
            require(
                stakeTotals.signedStakeForQuorum[i] * THRESHOLD_DENOMINATOR
                    >= stakeTotals.totalStakeForQuorum[i] * QUORUM_THRESHOLD,
                InsufficientQuorumThreshold()
            );
        }

        // Verify watchtower signed if enabled (O(1) check using provided index)
        if (watchtowerEnabled) {
            _verifyWatchtowerSigned(
                params.nonSignerStakesAndSignature.nonSignerPubkeys,
                params.watchtowerNonSignerIndex
            );
        }

        return true;
    }

    /**
     * @notice Internal function to verify watchtower is one of the signers (O(1))
     * @param nonSignerPubkeys Array of BLS public keys of operators who did NOT sign
     * @param watchtowerIndex Index of watchtower in nonSignerPubkeys, or WATCHTOWER_SIGNED if they signed
     * @dev Reverts if watchtower pubkey is found at the specified index
     */
    function _verifyWatchtowerSigned(
        BN254.G1Point[] memory nonSignerPubkeys,
        uint32 watchtowerIndex
    ) internal view {
        // If index is WATCHTOWER_SIGNED, watchtower claims to have signed (not in non-signers array)
        if (watchtowerIndex == WATCHTOWER_SIGNED) {
            return; // Watchtower signed
        }

        // Validate index is within bounds
        require(watchtowerIndex < nonSignerPubkeys.length, InvalidWatchtowerNonSignerIndex());

        // Check if the pubkey at the given index matches watchtower's pubkey
        BN254.G1Point memory pubkeyAtIndex = nonSignerPubkeys[watchtowerIndex];

        if (pubkeyAtIndex.X == watchtowerPubkey.X && pubkeyAtIndex.Y == watchtowerPubkey.Y) {
            // Watchtower is in the non-signers list at this index - they didn't sign
            revert WatchtowerDidNotSign();
        }

        // If pubkey at index doesn't match watchtower, the index is invalid
        // (watchtower might be elsewhere in the array or not at all)
        revert InvalidWatchtowerNonSignerIndex();
    }

    /**
     * @notice Update the watchtower's BLS public key
     * @param _newPubkey The new watchtower BLS public key (G1 point)
     * @dev Can only be called by the contract owner/admin
     */
    function updateWatchtowerPubkey(BN254.G1Point memory _newPubkey) external virtual {
        require(_newPubkey.X != 0 || _newPubkey.Y != 0, InvalidWatchtowerPubkey());
        uint256 oldX = watchtowerPubkey.X;
        uint256 oldY = watchtowerPubkey.Y;
        watchtowerPubkey = _newPubkey;
        emit WatchtowerPubkeyUpdated(oldX, oldY, _newPubkey.X, _newPubkey.Y);
    }

    /**
     * @notice Enable or disable watchtower verification
     * @param enabled Whether to enable watchtower verification
     * @dev Can only be called by the contract owner/admin
     */
    function setWatchtowerStatus(bool enabled) external virtual {
        watchtowerEnabled = enabled;
        emit WatchtowerStatusChanged(enabled);
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
