// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "../OpacitySDK.sol";
import "@eigenlayer-middleware/interfaces/IBLSSignatureChecker.sol";

/**
 * @title OpacityVerificationExample
 * @notice Example contract demonstrating basic opacity verification using OpacitySDK
 * @dev This contract shows how to verify private data and retrieve the verified values
 */
contract OpacityVerificationExample is OpacitySDK {
    
    struct VerificationResult {
        bool isVerified;
        string verifiedValue;
        uint256 timestamp;
        bytes32 verificationHash;
    }
    
    mapping(address => VerificationResult) public userVerifications;
    
    event DataVerified(
        address indexed user, 
        string verifiedValue,
        bytes32 verificationHash, 
        bool success
    );

    constructor() OpacitySDK() {}

    /**
     * @notice Verify private data and store the verified value
     * @param quorumNumbers The quorum numbers to check signatures for
     * @param referenceBlockNumber The block number to use as reference for operator set
     * @param nonSignerStakesAndSignature The non-signer stakes and signature data computed off-chain
     * @param user The user whose data is being verified
     * @param platform The platform/source of the data
     * @param resource The specific resource or data type being verified
     * @param value The value being verified
     * @param threshold The threshold for validation
     * @param signature The operator's signature
     * @param operatorCount The number of operators participating
     * @return success Whether verification succeeded
     * @return verifiedValue The verified value if successful
     */
    function verifyPrivateData(
        bytes calldata quorumNumbers,
        uint32 referenceBlockNumber,
        IBLSSignatureCheckerTypes.NonSignerStakesAndSignature calldata nonSignerStakesAndSignature,
        address user,
        string calldata platform,
        string calldata resource,
        string calldata value,
        uint256 threshold,
        string calldata signature,
        uint256 operatorCount
    ) external returns (bool success, string memory verifiedValue) {
        try this.verify(
            quorumNumbers,
            referenceBlockNumber,
            nonSignerStakesAndSignature,
            user,
            platform,
            resource,
            value,
            threshold,
            signature,
            operatorCount
        ) returns (bool verified) {
            // Verification successful - store the verified value
            bytes32 verificationHash = keccak256(abi.encodePacked(
                user,
                platform,
                resource,
                value,
                block.timestamp
            ));
            
            userVerifications[user] = VerificationResult({
                isVerified: true,
                verifiedValue: value,
                timestamp: block.timestamp,
                verificationHash: verificationHash
            });
            
            emit DataVerified(user, value, verificationHash, true);
            return (true, value);
            
        } catch {
            // Verification failed
            emit DataVerified(user, "", bytes32(0), false);
            return (false, "");
        }
    }

    /**
     * @notice Get the verified value for a user
     * @param user The user to check
     * @return verifiedValue The verified value, empty string if not verified
     */
    function getVerifiedValue(
        address user
    ) external view returns (string memory verifiedValue) {
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
     */
    function getUserVerification(
        address user
    ) external view returns (
        bool isValid, 
        string memory verifiedValue,
        uint256 timestamp, 
        bytes32 verificationHash
    ) {
        VerificationResult memory result = userVerifications[user];
        return (result.isVerified, result.verifiedValue, result.timestamp, result.verificationHash);
    }

    /**
     * @notice Check if a verification is still valid (not expired) and get the value
     * @param user The user to check
     * @param maxAge Maximum age of verification in seconds
     * @return isValid Whether the verification is still valid
     * @return verifiedValue The verified value if still valid
     */
    function getValidVerificationValue(
        address user,
        uint256 maxAge
    ) external view returns (bool isValid, string memory verifiedValue) {
        VerificationResult memory result = userVerifications[user];
        bool stillValid = result.isVerified && (block.timestamp - result.timestamp) <= maxAge;
        return (stillValid, stillValid ? result.verifiedValue : "");
    }
} 