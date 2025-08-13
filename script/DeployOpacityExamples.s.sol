// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.30;

import "forge-std/Script.sol";
import "@eigenlayer-middleware/BLSSignatureChecker.sol";
import "@eigenlayer-middleware/interfaces/IRegistryCoordinator.sol";
import "../src/examples/SimpleVerificationConsumer.sol";
import "../src/examples/StorageQueryConsumer.sol";

/**
 * @title DeployOpacityExamples
 * @notice Comprehensive deployment script for OpacitySDK and example contracts
 * @dev Deploys BLS signature checker and both example contracts
 */
contract DeployOpacityExamples is Script {

    // Deployed contract addresses
    BLSSignatureChecker public blsSignatureChecker;
    SimpleVerificationConsumer public simpleVerificationConsumer;
    StorageQueryConsumer public storageQueryConsumer;

    function run(address registryCoordinator) external {
        uint256 deployerPrivateKey = vm.envUint("PRIVATE_KEY");

        console.log("Starting OpacitySDK deployment...");
        console.log("Deployer address:", vm.addr(deployerPrivateKey));
        console.log("Registry Coordinator:", registryCoordinator);

        vm.startBroadcast(deployerPrivateKey);

        // Step 1: Deploy BLS Signature Checker
        console.log("\n=== Step 1: Deploying BLS Signature Checker ===");
        blsSignatureChecker = new BLSSignatureChecker(IRegistryCoordinator(registryCoordinator));
        console.log("BLS Signature Checker deployed at:", address(blsSignatureChecker));

        // Step 2: Deploy Simple Verification Consumer
        console.log("\n=== Step 2: Deploying Simple Verification Consumer ===");
        simpleVerificationConsumer = new SimpleVerificationConsumer(address(blsSignatureChecker));
        console.log("Simple Verification Consumer deployed at:", address(simpleVerificationConsumer));

        // Step 3: Deploy Storage Query Consumer
        console.log("\n=== Step 3: Deploying Storage Query Consumer ===");
        storageQueryConsumer = new StorageQueryConsumer(address(blsSignatureChecker));
        console.log("Storage Query Consumer deployed at:", address(storageQueryConsumer));

        vm.stopBroadcast();

        // Print deployment summary
        printDeploymentSummary(registryCoordinator);
    }

    /**
     * @notice Print a comprehensive deployment summary
     * @param registryCoordinator The registry coordinator address used for deployment
     */
    function printDeploymentSummary(address registryCoordinator) internal view {
        console.log("\n" "========================================");
        console.log("       DEPLOYMENT SUMMARY");
        console.log("========================================");
        console.log("Registry Coordinator:        ", registryCoordinator);
        console.log("BLS Signature Checker:       ", address(blsSignatureChecker));
        console.log("Simple Verification Consumer:", address(simpleVerificationConsumer));
        console.log("Storage Query Consumer:      ", address(storageQueryConsumer));
        console.log("========================================");

        // Verify the contracts are properly linked
        console.log("\n=== Verification Checks ===");
        console.log("Simple Consumer BLS Address: ", address(simpleVerificationConsumer.blsSignatureChecker()));
        console.log("Storage Consumer BLS Address:", address(storageQueryConsumer.blsSignatureChecker()));

        bool simpleLinked = address(simpleVerificationConsumer.blsSignatureChecker()) == address(blsSignatureChecker);
        bool storageLinked = address(storageQueryConsumer.blsSignatureChecker()) == address(blsSignatureChecker);

        console.log("Simple Consumer properly linked: ", simpleLinked);
        console.log("Storage Consumer properly linked:", storageLinked);

        if (simpleLinked && storageLinked) {
            console.log("All contracts deployed and linked successfully!");
        } else {
            console.log("Contract linking verification failed!");
        }
    }
}
