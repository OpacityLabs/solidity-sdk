// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.30;

import "forge-std/Script.sol";
import "@eigenlayer-middleware/BLSSignatureChecker.sol";
import "@eigenlayer-middleware/interfaces/IRegistryCoordinator.sol";
import "../src/examples/SimpleVerificationConsumer.sol";

/**
 * @title Deploy
 * @notice Main deployment script for OpacitySDK contracts
 */
contract Deploy is Script {
    // Deployed contracts
    BLSSignatureChecker public blsSignatureChecker;
    SimpleVerificationConsumer public simpleVerificationConsumer;

    /**
     * @notice Deploy SimpleVerificationConsumer with new BLS signature checker
     * @param registryCoordinator Registry coordinator address for new BLS deployment
     */
    function run(address registryCoordinator) external {
        require(registryCoordinator != address(0), "Invalid registry coordinator address");
        uint256 deployerPrivateKey = vm.envUint("PRIVATE_KEY");

        console.log("Starting OpacitySDK deployment...");
        console.log("Deployer address:", vm.addr(deployerPrivateKey));
        console.log("Registry Coordinator:", registryCoordinator);

        vm.startBroadcast(deployerPrivateKey);

        // Deploy BLS Signature Checker
        console.log("\n=== Deploying BLS Signature Checker ===");
        blsSignatureChecker = new BLSSignatureChecker(IRegistryCoordinator(registryCoordinator));
        console.log("BLS Signature Checker deployed at:", address(blsSignatureChecker));

        // Deploy Simple Verification Consumer
        console.log("\n=== Deploying Simple Verification Consumer ===");
        simpleVerificationConsumer = new SimpleVerificationConsumer(address(blsSignatureChecker));
        console.log("Simple Verification Consumer deployed at:", address(simpleVerificationConsumer));

        vm.stopBroadcast();

        writeDeploymentJson(registryCoordinator, false);
        printDeploymentSummary();
    }

    /**
     * @notice Deploy SimpleVerificationConsumer with existing BLS signature checker
     * @param blsSignatureCheckerAddress Existing BLS signature checker address
     * @param registryCoordinator Registry coordinator address (for reference only)
     */
    function run(address blsSignatureCheckerAddress, address registryCoordinator) external {
        require(blsSignatureCheckerAddress != address(0), "Invalid BLS address");
        require(registryCoordinator != address(0), "Invalid registry coordinator address");

        uint256 deployerPrivateKey = vm.envUint("PRIVATE_KEY");
        blsSignatureChecker = BLSSignatureChecker(blsSignatureCheckerAddress);

        console.log("Starting OpacitySDK deployment with existing BLS...");
        console.log("Deployer address:", vm.addr(deployerPrivateKey));
        console.log("Registry Coordinator:", registryCoordinator);
        console.log("Using BLS Signature Checker:", blsSignatureCheckerAddress);

        vm.startBroadcast(deployerPrivateKey);

        // Deploy Simple Verification Consumer
        console.log("\n=== Deploying Simple Verification Consumer ===");
        simpleVerificationConsumer = new SimpleVerificationConsumer(blsSignatureCheckerAddress);
        console.log("Simple Verification Consumer deployed at:", address(simpleVerificationConsumer));

        vm.stopBroadcast();

        writeDeploymentJson(registryCoordinator, true);
        printDeploymentSummary();
    }

    /**
     * @notice Write deployment addresses to JSON file
     * @param registryCoordinator Registry coordinator address
     * @param blsExisted Whether BLS was pre-existing
     */
    function writeDeploymentJson(address registryCoordinator, bool blsExisted) internal {
        string memory json = "deployment";

        vm.serializeAddress(json, "blsSignatureChecker", address(blsSignatureChecker));
        vm.serializeString(json, "blsSignatureCheckerStatus", blsExisted ? "existing" : "deployed");
        vm.serializeAddress(json, "registryCoordinator", registryCoordinator);
        vm.serializeAddress(json, "simpleVerificationConsumer", address(simpleVerificationConsumer));

        string memory finalJson = vm.serializeUint(json, "timestamp", block.timestamp);

        vm.writeJson(finalJson, "./deployments/latest.json");
        console.log("\nDeployment addresses written to deployments/latest.json");
    }

    /**
     * @notice Print deployment summary
     */
    function printDeploymentSummary() internal view {
        console.log("\n========================================");
        console.log("       DEPLOYMENT SUMMARY");
        console.log("========================================");
        console.log("BLS Signature Checker:       ", address(blsSignatureChecker));
        console.log("Simple Verification Consumer:", address(simpleVerificationConsumer));
        console.log("========================================");

        console.log("\n=== Verification Check ===");
        console.log("Simple Consumer BLS Address: ", address(simpleVerificationConsumer.blsSignatureChecker()));

        bool linked = address(simpleVerificationConsumer.blsSignatureChecker()) == address(blsSignatureChecker);
        console.log("Simple Consumer properly linked: ", linked);

        if (linked) {
            console.log("\nAll contracts deployed and linked successfully!");
        } else {
            console.log("\nContract linking verification failed!");
        }
    }
}
