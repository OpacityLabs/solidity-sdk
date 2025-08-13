// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.30;

import "forge-std/Script.sol";
import "@eigenlayer-middleware/BLSSignatureChecker.sol";
import "@eigenlayer-middleware/interfaces/IRegistryCoordinator.sol";
import "../src/examples/DynamicVerificationConsumer.sol";
import "../src/libraries/RiskAssessment.sol";

/**
 * @title DeployDynamicThreshold
 * @notice Deployment script for Dynamic Threshold verification system
 * @dev Deploys BLS signature checker and Dynamic Verification Consumer
 */
contract DeployDynamicThreshold is Script {
    // Registry Coordinator address (testnet holesky)
    address constant REGISTRY_COORDINATOR = 0x3e43AA225b5cB026C5E8a53f62572b10D526a50B;

    // Deployed contract addresses
    BLSSignatureChecker public blsSignatureChecker;
    DynamicVerificationConsumer public dynamicVerificationConsumer;

    function run() external {
        uint256 deployerPrivateKey = vm.envUint("PRIVATE_KEY");

        console.log("Starting Dynamic Threshold SDK deployment...");
        console.log("Deployer address:", vm.addr(deployerPrivateKey));
        console.log("Registry Coordinator:", REGISTRY_COORDINATOR);

        vm.startBroadcast(deployerPrivateKey);

        // Step 1: Deploy BLS Signature Checker (or reuse existing)
        console.log("\n=== Step 1: Deploying BLS Signature Checker ===");
        
        // Check if we should reuse existing BLS checker
        address existingBLS = vm.envOr("EXISTING_BLS_CHECKER", address(0));
        
        if (existingBLS != address(0)) {
            console.log("Using existing BLS Signature Checker at:", existingBLS);
            blsSignatureChecker = BLSSignatureChecker(existingBLS);
        } else {
            blsSignatureChecker = new BLSSignatureChecker(IRegistryCoordinator(REGISTRY_COORDINATOR));
            console.log("BLS Signature Checker deployed at:", address(blsSignatureChecker));
        }

        // Step 2: Deploy Dynamic Verification Consumer
        console.log("\n=== Step 2: Deploying Dynamic Verification Consumer ===");
        dynamicVerificationConsumer = new DynamicVerificationConsumer(address(blsSignatureChecker));
        console.log("Dynamic Verification Consumer deployed at:", address(dynamicVerificationConsumer));

        // Step 3: Configure initial risk settings
        console.log("\n=== Step 3: Configuring Risk Settings ===");
        configureInitialRiskSettings();

        vm.stopBroadcast();

        // Print deployment summary
        printDeploymentSummary();
    }

    /**
     * @notice Configure initial risk settings for the deployed contract
     */
    function configureInitialRiskSettings() internal {
        // Set up additional platform trust levels
        console.log("Setting up platform trust levels...");
        
        string[] memory platforms = new string[](5);
        RiskAssessment.PlatformTrust[] memory trustLevels = new RiskAssessment.PlatformTrust[](5);
        
        platforms[0] = "ethereum";
        trustLevels[0] = RiskAssessment.PlatformTrust.VERIFIED;
        
        platforms[1] = "polygon";
        trustLevels[1] = RiskAssessment.PlatformTrust.VERIFIED;
        
        platforms[2] = "arbitrum";
        trustLevels[2] = RiskAssessment.PlatformTrust.VERIFIED;
        
        platforms[3] = "optimism";
        trustLevels[3] = RiskAssessment.PlatformTrust.VERIFIED;
        
        platforms[4] = "unknown_chain";
        trustLevels[4] = RiskAssessment.PlatformTrust.UNTRUSTED;
        
        dynamicVerificationConsumer.batchUpdatePlatformTrust(platforms, trustLevels);
        
        // Set up additional resource criticality levels
        console.log("Setting up resource criticality levels...");
        
        string[] memory resources = new string[](5);
        RiskAssessment.ResourceCriticality[] memory criticalityLevels = new RiskAssessment.ResourceCriticality[](5);
        
        resources[0] = "transaction";
        criticalityLevels[0] = RiskAssessment.ResourceCriticality.CRITICAL;
        
        resources[1] = "signature";
        criticalityLevels[1] = RiskAssessment.ResourceCriticality.CRITICAL;
        
        resources[2] = "nonce";
        criticalityLevels[2] = RiskAssessment.ResourceCriticality.SENSITIVE;
        
        resources[3] = "metadata";
        criticalityLevels[3] = RiskAssessment.ResourceCriticality.STANDARD;
        
        resources[4] = "timestamp";
        criticalityLevels[4] = RiskAssessment.ResourceCriticality.TRIVIAL;
        
        dynamicVerificationConsumer.batchUpdateResourceCriticality(resources, criticalityLevels);
        
        console.log("Risk settings configured successfully!");
    }

    /**
     * @notice Print a comprehensive deployment summary
     */
    function printDeploymentSummary() internal view {
        console.log("\n" "========================================");
        console.log("    DYNAMIC THRESHOLD DEPLOYMENT SUMMARY");
        console.log("========================================");
        console.log("Registry Coordinator:           ", REGISTRY_COORDINATOR);
        console.log("BLS Signature Checker:          ", address(blsSignatureChecker));
        console.log("Dynamic Verification Consumer:  ", address(dynamicVerificationConsumer));
        console.log("========================================");

        // Verify the contracts are properly linked
        console.log("\n=== Verification Checks ===");
        console.log("Consumer BLS Address:           ", address(dynamicVerificationConsumer.blsSignatureChecker()));
        
        bool properlyLinked = address(dynamicVerificationConsumer.blsSignatureChecker()) == address(blsSignatureChecker);
        console.log("Consumer properly linked:       ", properlyLinked);

        // Display risk configuration
        console.log("\n=== Risk Configuration ===");
        RiskAssessment.RiskConfig memory config = dynamicVerificationConsumer.getRiskConfig();
        console.log("Low Value Threshold:            ", config.lowValueThreshold / 1e18, "ETH");
        console.log("Medium Value Threshold:         ", config.mediumValueThreshold / 1e18, "ETH");
        console.log("High Value Threshold:           ", config.highValueThreshold / 1e18, "ETH");
        console.log("Platform Multiplier:            ", config.platformMultiplier, "%");
        console.log("Resource Multiplier:            ", config.resourceMultiplier, "%");
        console.log("Emergency Mode:                 ", config.emergencyMode);

        // Display example thresholds
        console.log("\n=== Example Risk Thresholds ===");
        console.log("MINIMAL Risk (e.g., social metrics):  10%");
        console.log("LOW Risk (e.g., preferences):         30%");
        console.log("MEDIUM Risk (e.g., user data):        50%");
        console.log("HIGH Risk (e.g., sensitive data):     70%");
        console.log("CRITICAL Risk (e.g., financial):      90%");

        if (properlyLinked) {
            console.log("\nDynamic Threshold system deployed successfully!");
            console.log("The system will now automatically adjust verification thresholds based on risk assessment.");
        } else {
            console.log("\nContract linking verification failed!");
        }
    }
}