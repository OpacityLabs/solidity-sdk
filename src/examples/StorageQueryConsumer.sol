// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import "../OpacitySDK.sol";
import "../IOpacitySDK.sol";
import "@eigenlayer-middleware/interfaces/IBLSSignatureChecker.sol";

/**
 * @title StorageQueryConsumer
 * @notice Example contract demonstrating stateful Opacity verification with data storage
 * @dev This contract shows a more advanced integration with OpacitySDK that:
 *      - Stores verification results persistently on-chain
 *      - Tracks publicly revealed values from attestations
 *      - Provides query functions for verification status and expiration checking
 *
 *      Use this as a template for applications that need to:
 *      - Remember past verifications
 *      - Access revealed values after verification
 *      - Implement verification expiration logic
 */
contract StorageQueryConsumer is OpacitySDK {
    /**
     * @notice Stores the result of a verification attempt for a user
     * @param isVerified Whether the verification succeeded
     * @param payloadHash The hash of the verified commitment payload
     * @param timestamp The block timestamp when verification occurred
     */
    struct VerificationResult {
        bool isVerified;
        bytes32 payloadHash;
        uint256 timestamp;
    }

    /**
     * @notice Maps user addresses to their most recent verification result
     * @dev Each user can only have one active verification at a time
     */
    mapping(address => VerificationResult) public userVerifications;

    /**
     * @notice Maps user addresses to their array of publicly revealed values
     * @dev Values are replaced entirely on each new verification
     */
    mapping(address => IOpacitySDK.ValueReveal[]) public userValues;

    /**
     * @notice Emitted when a verification attempt is made for a user
     * @param user The address of the user whose data was verified
     * @param payloadHash The hash of the commitment payload that was verified
     * @param success Whether the verification succeeded
     */
    event DataVerified(address indexed user, bytes32 payloadHash, bool success);

    /**
     * @notice Initializes the consumer with the BLS signature checker
     * @param _blsSignatureChecker Address of the deployed BLS signature checker contract
     */
    constructor(address _blsSignatureChecker) OpacitySDK(_blsSignatureChecker) {}

    /**
     * @notice Verifies a commitment and stores the result and revealed values
     * @dev This function:
     *      1. Attempts verification via OpacitySDK.verify()
     *      2. On success, stores the verification result with timestamp
     *      3. Replaces any existing revealed values with the new ones
     *      4. Emits a DataVerified event
     *
     *      Note: Any previous verification and values for this user are overwritten.
     * @param params The verification parameters containing quorum info, reference block,
     *               BLS signature data, and the commitment payload
     * @return success True if verification succeeded, false if it failed or reverted
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
     * @notice Retrieves all publicly revealed values for a user
     * @dev Returns an empty array if the user has no stored verification or no revealed values.
     *      These values were disclosed by the user as part of their attestation.
     * @param user The address of the user to query
     * @return values Array of ValueReveal structs containing resource and value pairs
     */
    function getUserValues(address user) external view returns (IOpacitySDK.ValueReveal[] memory values) {
        return userValues[user];
    }

    /**
     * @notice Retrieves the verification status and metadata for a user
     * @dev Returns default values (false, 0x0, 0) if the user has never been verified.
     *      Note: This does not check expiration - use isVerificationValid() for that.
     * @param user The address of the user to query
     * @return isValid Whether the user's most recent verification succeeded
     * @return payloadHash The keccak256 hash of the verified commitment payload
     * @return timestamp The block timestamp when verification occurred
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
     * @notice Checks if a user's verification is valid and not expired
     * @dev A verification is valid if:
     *      1. The user has a stored verification that succeeded (isVerified = true)
     *      2. The verification occurred within maxAge seconds of the current block
     *
     *      Returns bytes32(0) for payloadHash if the verification is expired or invalid.
     * @param user The address of the user to check
     * @param maxAge Maximum allowed age of the verification in seconds
     * @return isValid True if the user has a valid, non-expired verification
     * @return payloadHash The payload hash if valid, or bytes32(0) if expired/invalid
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
     * @notice Retrieves a specific revealed value by index
     * @dev Useful for iterating through values without loading the entire array.
     *      Reverts with "Index out of bounds" if the index exceeds the array length.
     * @param user The address of the user to query
     * @param index The zero-based index of the value reveal to retrieve
     * @return value The ValueReveal struct at the specified index
     */
    function getUserValueByIndex(address user, uint256 index)
        external
        view
        returns (IOpacitySDK.ValueReveal memory value)
    {
        require(index < userValues[user].length, "Index out of bounds");
        return userValues[user][index];
    }
}
