// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import "../OpacitySDK.sol";
import "@eigenlayer-middleware/interfaces/IBLSSignatureChecker.sol";

/**
 * @title StorageQueryConsumer
 * @notice Example contract demonstrating basic opacity verification using OpacitySDK
 * @dev This contract shows how to verify private data and retrieve the verified values
 */
contract StorageQueryConsumer is OpacitySDK {
    struct VerificationResult {
        bool isVerified;
        string verifiedValue;
        uint256 timestamp;
        bytes32 verificationHash;
        bool watchtowerVerified;
    }

    mapping(address => VerificationResult) public userVerifications;

    event DataVerified(address indexed user, string verifiedValue, bytes32 verificationHash, bool success, bool watchtowerVerified);

    /**
     * @notice Constructor for StorageQueryConsumer
     * @param _blsSignatureChecker Address of the deployed BLS signature checker contract
     * @param _watchtowerAddress Address of the watchtower signer
     */
    constructor(address _blsSignatureChecker, address _watchtowerAddress) 
        OpacitySDK(_blsSignatureChecker, _watchtowerAddress) {}

    /**
     * @notice Verify private data using VerificationParams struct
     * @dev Primary interface that directly accepts the verification parameters struct
     * @param params The verification parameters wrapped in a struct
     * @return success Whether verification succeeded
     * @return verifiedValue The verified value if successful
     */
    function verifyPrivateData(VerificationParams calldata params)
        external
        returns (bool success, string memory verifiedValue)
    {
        try this.verify(params) returns (bool verified) {
            // Verification successful - store the verified value
            bytes32 verificationHash = keccak256(
                abi.encodePacked(params.userAddress, params.platform, params.resource, params.value, block.timestamp)
            );

            userVerifications[params.userAddress] = VerificationResult({
                isVerified: verified,
                verifiedValue: params.value,
                timestamp: block.timestamp,
                verificationHash: verificationHash,
                watchtowerVerified: watchtowerEnabled
            });

            emit DataVerified(params.userAddress, params.value, verificationHash, verified, watchtowerEnabled);
            return (verified, params.value);
        } catch {
            return (false, "");
        }
    }

    /**
     * @notice Get the verified value for a user
     * @param user The user to check
     * @return verifiedValue The verified value, empty string if not verified
     */
    function getVerifiedValue(address user) external view returns (string memory verifiedValue) {
        VerificationResult memory result = userVerifications[user];
        return result.isVerified ? result.verifiedValue : "";
    }

    /**
     * @notice Check if a user has valid verification
     * @param user The user to check
     * @return isValid Whether the user has valid verification
     * @return verifiedValue The verified value
     * @return timestamp When the verification was made
     * @return verificationHash The hash of the verification
     * @return watchtowerVerified Whether watchtower was involved in verification
     */
    function getUserVerification(address user)
        external
        view
        returns (bool isValid, string memory verifiedValue, uint256 timestamp, bytes32 verificationHash, bool watchtowerVerified)
    {
        VerificationResult memory result = userVerifications[user];
        return (result.isVerified, result.verifiedValue, result.timestamp, result.verificationHash, result.watchtowerVerified);
    }

    /**
     * @notice Check if a verification is still valid (not expired) and get the value
     * @param user The user to check
     * @param maxAge Maximum age of verification in seconds
     * @return isValid Whether the verification is still valid
     * @return verifiedValue The verified value if still valid
     */
    function getValidVerificationValue(address user, uint256 maxAge)
        external
        view
        returns (bool isValid, string memory verifiedValue)
    {
        VerificationResult memory result = userVerifications[user];
        bool stillValid = result.isVerified && (block.timestamp - result.timestamp) <= maxAge;
        return (stillValid, stillValid ? result.verifiedValue : "");
    }
}
