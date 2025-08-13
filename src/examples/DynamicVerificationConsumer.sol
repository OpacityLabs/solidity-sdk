// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import "../DynamicThresholdSDK.sol";
import "../libraries/RiskAssessment.sol";

/**
 * @title DynamicVerificationConsumer
 * @notice Example implementation of dynamic threshold verification
 */
contract DynamicVerificationConsumer is DynamicThresholdSDK {
    
    struct VerificationResult {
        bool verified;
        RiskAssessment.RiskLevel riskLevel;
        uint8 thresholdRequired;
        uint256 timestamp;
        string platform;
        string resource;
    }
    
    // Mapping from verification ID to result
    mapping(bytes32 => VerificationResult) public verificationHistory;
    
    // Mapping from user to their verification IDs
    mapping(address => bytes32[]) public userVerificationIds;
    
    // Statistics
    uint256 public totalVerifications;
    uint256 public successfulVerifications;
    mapping(RiskAssessment.RiskLevel => uint256) public verificationsByRiskLevel;
    
    event VerificationAttempt(
        address indexed user,
        bytes32 indexed verificationId,
        string platform,
        string resource,
        RiskAssessment.RiskLevel riskLevel,
        uint8 threshold,
        bool success
    );
    
    event RiskAnalysis(
        address indexed user,
        string platform,
        string resource,
        uint256 value,
        RiskAssessment.RiskLevel riskLevel,
        uint8 recommendedThreshold
    );
    
    /**
     * @notice Constructor for DynamicVerificationConsumer
     * @param _blsSignatureChecker Address of the deployed BLS signature checker contract
     */
    constructor(address _blsSignatureChecker) DynamicThresholdSDK(_blsSignatureChecker) {
        // Additional initialization for common platforms/resources if needed
        _initializeAdditionalSettings();
    }
    
    /**
     * @notice Verify user data with dynamic threshold
     * @param params The verification parameters
     * @return verified Whether verification succeeded
     * @return riskLevel The risk level determined
     * @return threshold The threshold that was required
     */
    function verifyWithDynamicThreshold(
        VerificationParams calldata params
    ) external returns (bool verified, RiskAssessment.RiskLevel riskLevel, uint8 threshold) {
        // Pre-calculate risk for transparency
        (riskLevel, threshold) = calculateDynamicThreshold(params);
        
        // Generate verification ID
        bytes32 verificationId = keccak256(
            abi.encode(
                params.userAddress,
                params.platform,
                params.resource,
                block.timestamp
            )
        );
        
        // Increment total verifications
        totalVerifications++;
        verificationsByRiskLevel[riskLevel]++;
        
        // Log the attempt
        emit VerificationAttempt(
            params.userAddress,
            verificationId,
            params.platform,
            params.resource,
            riskLevel,
            threshold,
            false // Will update if successful
        );
        
        try this.verify(params) returns (bool success) {
            if (success) {
                // Store successful verification
                verificationHistory[verificationId] = VerificationResult({
                    verified: true,
                    riskLevel: riskLevel,
                    thresholdRequired: threshold,
                    timestamp: block.timestamp,
                    platform: params.platform,
                    resource: params.resource
                });
                
                // Add to user's verification history
                userVerificationIds[params.userAddress].push(verificationId);
                
                // Increment successful verifications
                successfulVerifications++;
                
                emit VerificationAttempt(
                    params.userAddress,
                    verificationId,
                    params.platform,
                    params.resource,
                    riskLevel,
                    threshold,
                    true
                );
            }
            return (success, riskLevel, threshold);
        } catch Error(string memory) {
            // Verification failed
            verificationHistory[verificationId] = VerificationResult({
                verified: false,
                riskLevel: riskLevel,
                thresholdRequired: threshold,
                timestamp: block.timestamp,
                platform: params.platform,
                resource: params.resource
            });
            
            return (false, riskLevel, threshold);
        } catch {
            // Unknown error
            return (false, riskLevel, threshold);
        }
    }
    
    /**
     * @notice Get recommended threshold for given parameters
     * @param platform The platform identifier
     * @param resource The resource identifier
     * @param value The value/amount involved
     * @return riskLevel The calculated risk level
     * @return threshold The recommended threshold
     */
    function getRecommendedThreshold(
        string memory platform,
        string memory resource,
        uint256 value
    ) external view returns (RiskAssessment.RiskLevel riskLevel, uint8 threshold) {
        VerificationParams memory params;
        params.platform = platform;
        params.resource = resource;
        params.operatorThreshold = value;
        params.userAddress = msg.sender;
        
        (riskLevel, threshold) = calculateDynamicThreshold(params);
        
        return (riskLevel, threshold);
    }
    
    /**
     * @notice Analyze risk for specific parameters and emit event
     * @param platform The platform identifier
     * @param resource The resource identifier
     * @param value The value/amount involved
     */
    function analyzeRisk(
        string memory platform,
        string memory resource,
        uint256 value
    ) external {
        VerificationParams memory params;
        params.platform = platform;
        params.resource = resource;
        params.operatorThreshold = value;
        params.userAddress = msg.sender;
        
        (RiskAssessment.RiskLevel riskLevel, uint8 threshold) = calculateDynamicThreshold(params);
        
        emit RiskAnalysis(
            msg.sender,
            platform,
            resource,
            value,
            riskLevel,
            threshold
        );
    }
    
    /**
     * @notice Get user's verification history
     * @param user The user address
     * @return ids Array of verification IDs
     */
    function getUserVerificationHistory(address user) external view returns (bytes32[] memory) {
        return userVerificationIds[user];
    }
    
    /**
     * @notice Get detailed verification result
     * @param verificationId The verification ID
     * @return result The verification result
     */
    function getVerificationResult(bytes32 verificationId) external view returns (VerificationResult memory) {
        return verificationHistory[verificationId];
    }
    
    /**
     * @notice Get contract statistics
     * @return total Total verifications attempted
     * @return successful Successful verifications
     * @return successRate Success rate as percentage
     */
    function getStatistics() external view returns (
        uint256 total,
        uint256 successful,
        uint256 successRate
    ) {
        total = totalVerifications;
        successful = successfulVerifications;
        if (total > 0) {
            successRate = (successful * 100) / total;
        }
        return (total, successful, successRate);
    }
    
    /**
     * @notice Get verification count by risk level
     * @param level The risk level to query
     * @return count Number of verifications at this risk level
     */
    function getVerificationCountByRiskLevel(
        RiskAssessment.RiskLevel level
    ) external view returns (uint256) {
        return verificationsByRiskLevel[level];
    }
    
    /**
     * @notice Batch update platform trust levels
     * @param platforms Array of platform identifiers
     * @param trustLevels Array of trust levels
     */
    function batchUpdatePlatformTrust(
        string[] memory platforms,
        RiskAssessment.PlatformTrust[] memory trustLevels
    ) external onlyOwner {
        require(platforms.length == trustLevels.length, "Array length mismatch");
        
        for (uint256 i = 0; i < platforms.length; i++) {
            setPlatformTrust(platforms[i], trustLevels[i]);
        }
    }
    
    /**
     * @notice Batch update resource criticality levels
     * @param resources Array of resource identifiers
     * @param criticalityLevels Array of criticality levels
     */
    function batchUpdateResourceCriticality(
        string[] memory resources,
        RiskAssessment.ResourceCriticality[] memory criticalityLevels
    ) external onlyOwner {
        require(resources.length == criticalityLevels.length, "Array length mismatch");
        
        for (uint256 i = 0; i < resources.length; i++) {
            setResourceCriticality(resources[i], criticalityLevels[i]);
        }
    }
    
    /**
     * @notice Initialize additional settings for the consumer
     */
    function _initializeAdditionalSettings() private {
        // Add more platform trust levels
        platformTrustLevels["linkedin"] = RiskAssessment.PlatformTrust.VERIFIED;
        platformTrustLevels["facebook"] = RiskAssessment.PlatformTrust.BASIC;
        platformTrustLevels["instagram"] = RiskAssessment.PlatformTrust.BASIC;
        platformTrustLevels["tiktok"] = RiskAssessment.PlatformTrust.UNTRUSTED;
        
        // Add more resource criticality levels
        resourceCriticalityLevels["username"] = RiskAssessment.ResourceCriticality.TRIVIAL;
        resourceCriticalityLevels["age"] = RiskAssessment.ResourceCriticality.STANDARD;
        resourceCriticalityLevels["location"] = RiskAssessment.ResourceCriticality.STANDARD;
        resourceCriticalityLevels["private_key"] = RiskAssessment.ResourceCriticality.CRITICAL;
        resourceCriticalityLevels["password"] = RiskAssessment.ResourceCriticality.CRITICAL;
        resourceCriticalityLevels["phone"] = RiskAssessment.ResourceCriticality.SENSITIVE;
    }
}