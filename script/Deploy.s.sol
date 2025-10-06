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
     * @notice Deploy SimpleVerificationConsumer
     * @param blsSignatureCheckerAddress BLS signature checker address
     * @param registryCoordinator Registry coordinator address
     */
    function run(address blsSignatureCheckerAddress, address registryCoordinator) external {
        require(blsSignatureCheckerAddress != address(0), "Invalid BLS address");
        require(registryCoordinator != address(0), "Invalid registry coordinator address");

        uint256 deployerPrivateKey = vm.envUint("PRIVATE_KEY");
        blsSignatureChecker = BLSSignatureChecker(blsSignatureCheckerAddress);

        console.log("Starting OpacitySDK deployment...");
        console.log("Deployer address:", vm.addr(deployerPrivateKey));
        console.log("BLS Signature Checker:", blsSignatureCheckerAddress);
        console.log("Registry Coordinator:", registryCoordinator);

        vm.startBroadcast(deployerPrivateKey);

        // Deploy Simple Verification Consumer
        console.log("\n=== Deploying Simple Verification Consumer ===");
        simpleVerificationConsumer = new SimpleVerificationConsumer(blsSignatureCheckerAddress);
        console.log("Simple Verification Consumer deployed at:", address(simpleVerificationConsumer));

        vm.stopBroadcast();

        writeDeploymentJson(registryCoordinator);
        printDeploymentSummary();
    }

    /**
     * @notice Write deployment addresses to JSON file
     * @param registryCoordinator Registry coordinator address
     */
    function writeDeploymentJson(address registryCoordinator) internal {
        string memory json = "deployment";

        vm.serializeAddress(json, "blsSignatureChecker", address(blsSignatureChecker));
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
