// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity ^0.8.30;

import "@eigenlayer-middleware/BLSSignatureChecker.sol";
import {
    IBLSSignatureChecker, IBLSSignatureCheckerTypes
} from "@eigenlayer-middleware/interfaces/IBLSSignatureChecker.sol";
import "./libraries/RiskAssessment.sol";
import "@openzeppelin/contracts/access/Ownable.sol";

/**
 * @title DynamicThresholdSDK
 * @notice SDK with dynamic security thresholds based on risk assessment
 * @dev Extends OpacitySDK functionality with adaptive security
 */
abstract contract DynamicThresholdSDK is Ownable {
    using RiskAssessment for uint256;
    
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
    uint32 public BLOCK_STALE_MEASURE = 300;
    
    // Dynamic threshold configuration
    RiskAssessment.RiskConfig public riskConfig;
    mapping(string => RiskAssessment.PlatformTrust) public platformTrustLevels;
    mapping(string => RiskAssessment.ResourceCriticality) public resourceCriticalityLevels;
    mapping(address => uint256) public userVerificationCount;
    mapping(address => uint256) public userLastVerification;
    
    // Events
    event DynamicThresholdApplied(
        bytes32 indexed msgHash,
        RiskAssessment.RiskLevel riskLevel,
        uint8 requiredThreshold,
        uint8 actualThreshold
    );
    event RiskConfigUpdated(RiskAssessment.RiskConfig newConfig);
    event PlatformTrustUpdated(string platform, RiskAssessment.PlatformTrust trust);
    event ResourceCriticalityUpdated(string resource, RiskAssessment.ResourceCriticality criticality);
    event VerificationCompleted(
        address indexed user,
        string platform,
        string resource,
        bool success,
        uint8 threshold
    );
    
    // Custom errors
    error InsufficientDynamicThreshold(uint8 required, uint8 actual);
    error InvalidRiskConfiguration();
    error EmergencyModeActive();
    error StaleBlockNumber();
    error FutureBlockNumber();
    
    /**
     * @notice Constructor for DynamicThresholdSDK
     * @param _blsSignatureChecker Address of the deployed BLS signature checker contract
     */
    constructor(address _blsSignatureChecker) Ownable(msg.sender) {
        require(_blsSignatureChecker != address(0), "Invalid BLS checker");
        blsSignatureChecker = BLSSignatureChecker(_blsSignatureChecker);
        
        // Initialize default risk config
        riskConfig = RiskAssessment.RiskConfig({
            lowValueThreshold: 100 ether,
            mediumValueThreshold: 1000 ether,
            highValueThreshold: 10000 ether,
            platformMultiplier: 100,  // 100% = no change
            resourceMultiplier: 100,  // 100% = no change
            emergencyMode: false
        });
        
        // Initialize common platforms
        _initializeDefaultPlatforms();
        
        // Initialize common resources
        _initializeDefaultResources();
    }
    
    /**
     * @notice Verify with dynamic threshold based on risk assessment
     * @param params The verification parameters
     * @return success Whether the verification succeeded
     */
    function verify(VerificationParams calldata params) external returns (bool success) {
        // Emergency mode check
        if (riskConfig.emergencyMode) {
            revert EmergencyModeActive();
        }
        
        // Check block number validity
        require(params.referenceBlockNumber < block.number, FutureBlockNumber());
        require((params.referenceBlockNumber + BLOCK_STALE_MEASURE) >= uint32(block.number), StaleBlockNumber());
        
        // Calculate message hash
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
        
        // Calculate dynamic threshold based on risk assessment
        (RiskAssessment.RiskLevel riskLevel, uint8 requiredThreshold) = calculateDynamicThreshold(params);
        
        // Get signature verification results
        (IBLSSignatureCheckerTypes.QuorumStakeTotals memory stakeTotals,) = 
            blsSignatureChecker.checkSignatures(
                msgHash, 
                params.quorumNumbers, 
                params.referenceBlockNumber, 
                params.nonSignerStakesAndSignature
            );
        
        // Check against dynamic threshold
        uint8 actualThreshold = 0;
        for (uint256 i = 0; i < params.quorumNumbers.length; i++) {
            if (stakeTotals.totalStakeForQuorum[i] == 0) {
                revert InsufficientDynamicThreshold(requiredThreshold, 0);
            }
            
            uint256 signedPercentage = (stakeTotals.signedStakeForQuorum[i] * 100) / 
                                       stakeTotals.totalStakeForQuorum[i];
            
            if (signedPercentage < requiredThreshold) {
                revert InsufficientDynamicThreshold(requiredThreshold, uint8(signedPercentage));
            }
            actualThreshold = uint8(signedPercentage);
        }
        
        // Update user statistics
        userVerificationCount[params.userAddress]++;
        userLastVerification[params.userAddress] = block.timestamp;
        
        // Emit events
        emit DynamicThresholdApplied(msgHash, riskLevel, requiredThreshold, actualThreshold);
        emit VerificationCompleted(
            params.userAddress,
            params.platform,
            params.resource,
            true,
            requiredThreshold
        );
        
        return true;
    }
    
    /**
     * @notice Calculate dynamic threshold based on risk assessment
     * @param params The verification parameters
     * @return riskLevel The calculated risk level
     * @return threshold The required threshold percentage
     */
    function calculateDynamicThreshold(
        VerificationParams calldata params
    ) public view returns (RiskAssessment.RiskLevel riskLevel, uint8 threshold) {
        // Get risk factors
        RiskAssessment.PlatformTrust platformTrust = platformTrustLevels[params.platform];
        RiskAssessment.ResourceCriticality resourceCrit = resourceCriticalityLevels[params.resource];
        uint256 userVerifications = userVerificationCount[params.userAddress];
        
        // Calculate risk score
        uint256 riskScore = RiskAssessment.calculateRiskScore(
            params.operatorThreshold,
            platformTrust,
            resourceCrit,
            userVerifications,
            riskConfig
        );
        
        // Map to risk level
        riskLevel = RiskAssessment.scoreToRiskLevel(riskScore);
        
        // Get base threshold for risk level
        uint8 baseThreshold = RiskAssessment.getRiskLevelThreshold(riskLevel);
        
        // Apply multipliers
        threshold = RiskAssessment.applyMultipliers(
            baseThreshold,
            riskConfig.platformMultiplier,
            riskConfig.resourceMultiplier
        );
        
        return (riskLevel, threshold);
    }
    
    /**
     * @notice Update risk configuration
     * @param newConfig The new risk configuration
     */
    function updateRiskConfig(RiskAssessment.RiskConfig memory newConfig) external onlyOwner {
        require(newConfig.platformMultiplier <= 200, InvalidRiskConfiguration());
        require(newConfig.resourceMultiplier <= 200, InvalidRiskConfiguration());
        require(newConfig.lowValueThreshold < newConfig.mediumValueThreshold, InvalidRiskConfiguration());
        require(newConfig.mediumValueThreshold < newConfig.highValueThreshold, InvalidRiskConfiguration());
        
        riskConfig = newConfig;
        emit RiskConfigUpdated(newConfig);
    }
    
    /**
     * @notice Set platform trust level
     * @param platform The platform identifier
     * @param trust The trust level
     */
    function setPlatformTrust(
        string memory platform, 
        RiskAssessment.PlatformTrust trust
    ) public onlyOwner {
        platformTrustLevels[platform] = trust;
        emit PlatformTrustUpdated(platform, trust);
    }
    
    /**
     * @notice Set resource criticality level
     * @param resource The resource identifier
     * @param criticality The criticality level
     */
    function setResourceCriticality(
        string memory resource, 
        RiskAssessment.ResourceCriticality criticality
    ) public onlyOwner {
        resourceCriticalityLevels[resource] = criticality;
        emit ResourceCriticalityUpdated(resource, criticality);
    }
    
    /**
     * @notice Toggle emergency mode
     */
    function toggleEmergencyMode() external onlyOwner {
        riskConfig.emergencyMode = !riskConfig.emergencyMode;
    }
    
    /**
     * @notice Get the current risk configuration
     */
    function getRiskConfig() external view returns (RiskAssessment.RiskConfig memory) {
        return riskConfig;
    }
    
    /**
     * @notice Get user verification statistics
     */
    function getUserStats(address user) external view returns (uint256 count, uint256 lastVerification) {
        return (userVerificationCount[user], userLastVerification[user]);
    }
    
    /**
     * @notice Initialize default platform trust levels
     */
    function _initializeDefaultPlatforms() private {
        platformTrustLevels["twitter"] = RiskAssessment.PlatformTrust.VERIFIED;
        platformTrustLevels["github"] = RiskAssessment.PlatformTrust.VERIFIED;
        platformTrustLevels["discord"] = RiskAssessment.PlatformTrust.BASIC;
        platformTrustLevels["telegram"] = RiskAssessment.PlatformTrust.BASIC;
    }
    
    /**
     * @notice Initialize default resource criticality levels
     */
    function _initializeDefaultResources() private {
        resourceCriticalityLevels["followers"] = RiskAssessment.ResourceCriticality.TRIVIAL;
        resourceCriticalityLevels["likes"] = RiskAssessment.ResourceCriticality.TRIVIAL;
        resourceCriticalityLevels["balance"] = RiskAssessment.ResourceCriticality.CRITICAL;
        resourceCriticalityLevels["identity"] = RiskAssessment.ResourceCriticality.SENSITIVE;
        resourceCriticalityLevels["email"] = RiskAssessment.ResourceCriticality.SENSITIVE;
        resourceCriticalityLevels["score"] = RiskAssessment.ResourceCriticality.STANDARD;
    }
}