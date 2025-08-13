// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

/**
 * @title RiskAssessment
 * @notice Library for calculating risk scores and dynamic thresholds
 */
library RiskAssessment {
    enum RiskLevel {
        MINIMAL,    // 10% threshold
        LOW,        // 30% threshold
        MEDIUM,     // 50% threshold
        HIGH,       // 70% threshold
        CRITICAL    // 90% threshold
    }
    
    enum PlatformTrust {
        UNTRUSTED,  // New or suspicious platform
        BASIC,      // Some history, limited trust
        VERIFIED,   // Verified platform with good history
        TRUSTED     // Long-term trusted partner
    }
    
    enum ResourceCriticality {
        TRIVIAL,    // e.g., social media metrics
        STANDARD,   // e.g., user preferences
        SENSITIVE,  // e.g., personal data
        CRITICAL    // e.g., financial data, credentials
    }
    
    struct RiskConfig {
        uint256 lowValueThreshold;      // Below this = low risk
        uint256 mediumValueThreshold;   // Below this = medium risk
        uint256 highValueThreshold;     // Below this = high risk
        uint8 platformMultiplier;       // 0-200, affects threshold
        uint8 resourceMultiplier;       // 0-200, affects threshold
        bool emergencyMode;              // Force maximum threshold
    }
    
    /**
     * @notice Calculate risk score based on multiple factors
     * @param value The transaction value
     * @param platformTrust The trust level of the platform
     * @param resourceCriticality The criticality of the resource
     * @param userVerifications Number of previous verifications by user
     * @param config Risk configuration parameters
     * @return riskScore The calculated risk score (0-100)
     */
    function calculateRiskScore(
        uint256 value,
        PlatformTrust platformTrust,
        ResourceCriticality resourceCriticality,
        uint256 userVerifications,
        RiskConfig memory config
    ) internal pure returns (uint256 riskScore) {
        // 1. Value-based risk assessment (0-40 points)
        if (value <= config.lowValueThreshold) {
            riskScore += 10;
        } else if (value <= config.mediumValueThreshold) {
            riskScore += 20;
        } else if (value <= config.highValueThreshold) {
            riskScore += 30;
        } else {
            riskScore += 40;
        }
        
        // 2. Platform trust assessment (0-30 points)
        if (platformTrust == PlatformTrust.UNTRUSTED) {
            riskScore += 30;
        } else if (platformTrust == PlatformTrust.BASIC) {
            riskScore += 20;
        } else if (platformTrust == PlatformTrust.VERIFIED) {
            riskScore += 10;
        }
        // TRUSTED adds 0 points
        
        // 3. Resource criticality assessment (0-30 points)
        if (resourceCriticality == ResourceCriticality.CRITICAL) {
            riskScore += 30;
        } else if (resourceCriticality == ResourceCriticality.SENSITIVE) {
            riskScore += 20;
        } else if (resourceCriticality == ResourceCriticality.STANDARD) {
            riskScore += 10;
        }
        // TRIVIAL adds 0 points
        
        // 4. User history bonus (reduces risk)
        if (userVerifications > 100) {
            riskScore = riskScore > 10 ? riskScore - 10 : 0;
        } else if (userVerifications > 50) {
            riskScore = riskScore > 5 ? riskScore - 5 : 0;
        }
        
        return riskScore;
    }
    
    /**
     * @notice Map risk score to risk level
     * @param riskScore The calculated risk score
     * @return riskLevel The corresponding risk level
     */
    function scoreToRiskLevel(uint256 riskScore) internal pure returns (RiskLevel) {
        if (riskScore <= 20) {
            return RiskLevel.MINIMAL;
        } else if (riskScore <= 40) {
            return RiskLevel.LOW;
        } else if (riskScore <= 60) {
            return RiskLevel.MEDIUM;
        } else if (riskScore <= 80) {
            return RiskLevel.HIGH;
        } else {
            return RiskLevel.CRITICAL;
        }
    }
    
    /**
     * @notice Get threshold percentage for a risk level
     * @param level The risk level
     * @return threshold The threshold percentage
     */
    function getRiskLevelThreshold(RiskLevel level) internal pure returns (uint8) {
        if (level == RiskLevel.MINIMAL) return 10;
        if (level == RiskLevel.LOW) return 30;
        if (level == RiskLevel.MEDIUM) return 50;
        if (level == RiskLevel.HIGH) return 70;
        if (level == RiskLevel.CRITICAL) return 90;
        return 50; // Default to medium
    }
    
    /**
     * @notice Apply multipliers to threshold
     * @param baseThreshold The base threshold
     * @param platformMultiplier Platform risk multiplier (100 = no change)
     * @param resourceMultiplier Resource risk multiplier (100 = no change)
     * @return adjustedThreshold The adjusted threshold
     */
    function applyMultipliers(
        uint8 baseThreshold,
        uint8 platformMultiplier,
        uint8 resourceMultiplier
    ) internal pure returns (uint8) {
        uint256 threshold = baseThreshold;
        threshold = (threshold * platformMultiplier) / 100;
        threshold = (threshold * resourceMultiplier) / 100;
        
        // Ensure threshold is within valid range (5-95%)
        if (threshold > 95) return 95;
        if (threshold < 5) return 5;
        return uint8(threshold);
    }
}