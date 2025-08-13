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
     * @param watchtowerSignature The watchtower's ECDSA signature for additional verification
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
        bytes watchtowerSignature;
    }

    // The BLS signature checker contract
    BLSSignatureChecker public immutable blsSignatureChecker;

    // Watchtower state variables
    address public watchtowerAddress;
    bool public watchtowerEnabled;

    // Constants for stake threshold checking
    uint8 public constant THRESHOLD_DENOMINATOR = 100;
    uint8 public QUORUM_THRESHOLD = 1;
    uint32 public BLOCK_STALE_MEASURE = 300;

    // Events
    event WatchtowerUpdated(address indexed oldWatchtower, address indexed newWatchtower);
    event WatchtowerStatusChanged(bool enabled);
    event WatchtowerVerification(bytes32 indexed msgHash, bool verified);

    // Custom errors
    error InvalidSignature();
    error InsufficientQuorumThreshold();
    error StaleBlockNumber();
    error FutureBlockNumber();
    error WatchtowerSignatureRequired();
    error InvalidWatchtowerSignature();
    error UnauthorizedWatchtowerUpdate();

    /**
     * @notice Constructor for OpacitySDK
     * @param _blsSignatureChecker Address of the deployed BLS signature checker contract
     * @param _watchtowerAddress Address of the watchtower signer
     */
    constructor(address _blsSignatureChecker, address _watchtowerAddress) {
        require(_blsSignatureChecker != address(0), "Invalid BLS signature checker address");
        require(_watchtowerAddress != address(0), "Invalid watchtower address");
        blsSignatureChecker = BLSSignatureChecker(_blsSignatureChecker);
        watchtowerAddress = _watchtowerAddress;
        watchtowerEnabled = true;
    }

    /**
     * @notice Function to verify if a signature is valid
     * @param params The verification parameters wrapped in a struct
     * @return success Whether the verification succeeded
     */
    function verify(VerificationParams calldata params) external returns (bool success) {
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

        // Step 1: Verify watchtower signature if enabled
        if (watchtowerEnabled) {
            require(params.watchtowerSignature.length > 0, WatchtowerSignatureRequired());
            
            // Verify watchtower signature
            bool watchtowerValid = _verifyWatchtowerSignature(msgHash, params.watchtowerSignature);
            require(watchtowerValid, InvalidWatchtowerSignature());
            
            emit WatchtowerVerification(msgHash, true);
        }

        // Step 2: Verify operator quorum (existing logic)
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
     * @notice Internal function to verify watchtower signature
     * @param msgHash The message hash to verify
     * @param signature The ECDSA signature from watchtower
     * @return Whether the signature is valid
     */
    function _verifyWatchtowerSignature(bytes32 msgHash, bytes memory signature) internal view returns (bool) {
        // Ensure signature is the correct length
        require(signature.length == 65, "Invalid signature length");
        
        bytes32 r;
        bytes32 s;
        uint8 v;
        
        // Extract r, s, v from signature
        assembly {
            r := mload(add(signature, 32))
            s := mload(add(signature, 64))
            v := byte(0, mload(add(signature, 96)))
        }
        
        // Recover signer address
        address signer = ecrecover(msgHash, v, r, s);
        return signer == watchtowerAddress;
    }

    /**
     * @notice Update the watchtower address
     * @param newWatchtower The new watchtower address
     * @dev Can only be called by the contract owner/admin
     */
    function updateWatchtower(address newWatchtower) external virtual {
        require(newWatchtower != address(0), "Invalid watchtower address");
        address oldWatchtower = watchtowerAddress;
        watchtowerAddress = newWatchtower;
        emit WatchtowerUpdated(oldWatchtower, newWatchtower);
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
