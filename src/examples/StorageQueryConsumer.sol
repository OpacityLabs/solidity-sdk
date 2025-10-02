// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import "../OpacitySDK.sol";
import "../IOpacitySDK.sol";
import "@eigenlayer-middleware/interfaces/IBLSSignatureChecker.sol";

/**
 * @title StorageQueryConsumer
 * @notice Example contract demonstrating basic opacity verification using OpacitySDK
 * @dev This contract shows how to verify private data and retrieve the verified values
 */
contract StorageQueryConsumer is OpacitySDK {
    struct VerificationResult {
        bool isVerified;
        bytes32 payloadHash;
        uint256 timestamp;
    }

    mapping(address => VerificationResult) public userVerifications;
    mapping(address => IOpacitySDK.ValueReveal[]) public userValues;

    event DataVerified(address indexed user, bytes32 payloadHash, bool success);

    /**
     * @notice Constructor for StorageQueryConsumer
     * @param _blsSignatureChecker Address of the deployed BLS signature checker contract
     */
    constructor(address _blsSignatureChecker) OpacitySDK(_blsSignatureChecker) {}

    /**
     * @notice Verify commitment data using VerificationParams struct
     * @dev Primary interface that directly accepts the verification parameters struct
     * @param params The verification parameters wrapped in a struct
     * @return success Whether verification succeeded
     */
    function verifyCommitment(IOpacitySDK.VerificationParams calldata params) external returns (bool success) {
        try this.verify(params) returns (bool verified) {
            // Verification successful - store the commitment metadata
            bytes32 payloadHash = computePayloadHash(params.payload);

            userVerifications[params.payload.userAddr] =
                VerificationResult({isVerified: verified, payloadHash: payloadHash, timestamp: block.timestamp});

            // Store public value reveals if any
            delete userValues[params.payload.userAddr];
            for (uint256 i = 0; i < params.payload.values.length; i++) {
                userValues[params.payload.userAddr].push(params.payload.values[i]);
            }

            emit DataVerified(params.payload.userAddr, payloadHash, verified);
            return verified;
        } catch {
            return false;
        }
    }

    /**
     * @notice Get the verified values for a user (public reveals only)
     * @param user The user to check
     * @return values Array of public value reveals
     */
    function getUserValues(address user) external view returns (IOpacitySDK.ValueReveal[] memory values) {
        return userValues[user];
    }

    /**
     * @notice Check if a user has valid verification
     * @param user The user to check
     * @return isValid Whether the user has valid verification
     * @return payloadHash The hash of the commitment payload
     * @return timestamp When the verification was made
     */
    function getUserVerification(address user)
        external
        view
        returns (bool isValid, bytes32 payloadHash, uint256 timestamp)
    {
        VerificationResult memory result = userVerifications[user];
        return (result.isVerified, result.payloadHash, result.timestamp);
    }

    /**
     * @notice Check if a verification is still valid (not expired)
     * @param user The user to check
     * @param maxAge Maximum age of verification in seconds
     * @return isValid Whether the verification is still valid
     * @return payloadHash The hash of the commitment payload if still valid
     */
    function isVerificationValid(address user, uint256 maxAge)
        external
        view
        returns (bool isValid, bytes32 payloadHash)
    {
        VerificationResult memory result = userVerifications[user];
        bool stillValid = result.isVerified && (block.timestamp - result.timestamp) <= maxAge;
        return (stillValid, stillValid ? result.payloadHash : bytes32(0));
    }

    /**
     * @notice Get a specific value reveal for a user by index
     * @param user The user to check
     * @param index The index of the value reveal
     * @return value The value reveal at the specified index
     */
    function getUserValueByIndex(address user, uint256 index) external view returns (IOpacitySDK.ValueReveal memory value) {
        require(index < userValues[user].length, "Index out of bounds");
        return userValues[user][index];
    }
}
