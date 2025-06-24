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
    // Registry Coordinator address (testnet holesky)
    address constant REGISTRY_COORDINATOR = 0x3e43AA225b5cB026C5E8a53f62572b10D526a50B;

    // Deployed contract addresses
    BLSSignatureChecker public blsSignatureChecker;
    SimpleVerificationConsumer public simpleVerificationConsumer;
    OpacityVerificationExample public opacityVerificationExample;

    function run() external {
        uint256 deployerPrivateKey = vm.envUint("PRIVATE_KEY");

        console.log("Starting OpacitySDK deployment...");
        console.log("Deployer address:", vm.addr(deployerPrivateKey));
        console.log("Registry Coordinator:", REGISTRY_COORDINATOR);

        vm.startBroadcast(deployerPrivateKey);

        // Step 1: Deploy BLS Signature Checker
        console.log("\n=== Step 1: Deploying BLS Signature Checker ===");
        blsSignatureChecker = new BLSSignatureChecker(IRegistryCoordinator(REGISTRY_COORDINATOR));
        console.log("BLS Signature Checker deployed at:", address(blsSignatureChecker));

        // Step 2: Deploy Simple Verification Consumer
        console.log("\n=== Step 2: Deploying Simple Verification Consumer ===");
        simpleVerificationConsumer = new SimpleVerificationConsumer(address(blsSignatureChecker));
        console.log("Simple Verification Consumer deployed at:", address(simpleVerificationConsumer));

        // Step 3: Deploy Opacity Verification Example (Storage Query Consumer)
        console.log("\n=== Step 3: Deploying Opacity Verification Example ===");
        opacityVerificationExample = new OpacityVerificationExample(address(blsSignatureChecker));
        console.log("Opacity Verification Example deployed at:", address(opacityVerificationExample));

        vm.stopBroadcast();

        // Print deployment summary
        printDeploymentSummary();
    }

    /**
     * @notice Print a comprehensive deployment summary
     */
    function printDeploymentSummary() internal view {
        console.log("\n" "========================================");
        console.log("       DEPLOYMENT SUMMARY");
        console.log("========================================");
        console.log("Registry Coordinator:        ", REGISTRY_COORDINATOR);
        console.log("BLS Signature Checker:       ", address(blsSignatureChecker));
        console.log("Simple Verification Consumer:", address(simpleVerificationConsumer));
        console.log("Opacity Verification Example:", address(opacityVerificationExample));
        console.log("========================================");

        // Verify the contracts are properly linked
        console.log("\n=== Verification Checks ===");
        console.log("Simple Consumer BLS Address: ", address(simpleVerificationConsumer.blsSignatureChecker()));
        console.log("Storage Consumer BLS Address:", address(opacityVerificationExample.blsSignatureChecker()));

        bool simpleLinked = address(simpleVerificationConsumer.blsSignatureChecker()) == address(blsSignatureChecker);
        bool storageLinked = address(opacityVerificationExample.blsSignatureChecker()) == address(blsSignatureChecker);

        console.log("Simple Consumer properly linked: ", simpleLinked);
        console.log("Storage Consumer properly linked:", storageLinked);

        if (simpleLinked && storageLinked) {
            console.log("All contracts deployed and linked successfully!");
        } else {
            console.log("Contract linking verification failed!");
        }
    }
}
