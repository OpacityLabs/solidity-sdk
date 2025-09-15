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
    
    // Watchtower address (can be set via environment variable or hardcoded)
    address public watchtowerAddress;

    // Deployed contract addresses
    BLSSignatureChecker public blsSignatureChecker;
    SimpleVerificationConsumer public simpleVerificationConsumer;
    StorageQueryConsumer public storageQueryConsumer;

    function run() external {
        uint256 deployerPrivateKey = vm.envUint("PRIVATE_KEY");
        
        // Try to get watchtower address from environment, otherwise use a default
        try vm.envAddress("WATCHTOWER_ADDRESS") returns (address _watchtower) {
            watchtowerAddress = _watchtower;
        } catch {
            // Default watchtower address for testing (should be replaced in production)
            watchtowerAddress = 0x70997970C51812dc3A010C7d01b50e0d17dc79C8;
            console.log("WARNING: Using default watchtower address. Set WATCHTOWER_ADDRESS env var for production.");
        }

        console.log("Starting OpacitySDK deployment...");
        console.log("Deployer address:", vm.addr(deployerPrivateKey));
        console.log("Registry Coordinator:", REGISTRY_COORDINATOR);
        console.log("Watchtower address:", watchtowerAddress);

        vm.startBroadcast(deployerPrivateKey);

        // Step 1: Deploy BLS Signature Checker
        console.log("\n=== Step 1: Deploying BLS Signature Checker ===");
        blsSignatureChecker = new BLSSignatureChecker(IRegistryCoordinator(REGISTRY_COORDINATOR));
        console.log("BLS Signature Checker deployed at:", address(blsSignatureChecker));

        // Step 2: Deploy Simple Verification Consumer
        console.log("\n=== Step 2: Deploying Simple Verification Consumer ===");
        simpleVerificationConsumer = new SimpleVerificationConsumer(address(blsSignatureChecker), watchtowerAddress);
        console.log("Simple Verification Consumer deployed at:", address(simpleVerificationConsumer));

        // Step 3: Deploy Storage Query Consumer
        console.log("\n=== Step 3: Deploying Storage Query Consumer ===");
        storageQueryConsumer = new StorageQueryConsumer(address(blsSignatureChecker), watchtowerAddress);
        console.log("Storage Query Consumer deployed at:", address(storageQueryConsumer));

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
        console.log("Watchtower Address:          ", watchtowerAddress);
        console.log("BLS Signature Checker:       ", address(blsSignatureChecker));
        console.log("Simple Verification Consumer:", address(simpleVerificationConsumer));
        console.log("Storage Query Consumer:      ", address(storageQueryConsumer));
        console.log("========================================");

        // Verify the contracts are properly linked
        console.log("\n=== Verification Checks ===");
        console.log("Simple Consumer BLS Address: ", address(simpleVerificationConsumer.blsSignatureChecker()));
        console.log("Storage Consumer BLS Address:", address(storageQueryConsumer.blsSignatureChecker()));
        console.log("Simple Consumer Watchtower:  ", simpleVerificationConsumer.watchtowerAddress());
        console.log("Storage Consumer Watchtower: ", storageQueryConsumer.watchtowerAddress());

        bool simpleLinked = address(simpleVerificationConsumer.blsSignatureChecker()) == address(blsSignatureChecker);
        bool storageLinked = address(storageQueryConsumer.blsSignatureChecker()) == address(blsSignatureChecker);
        bool simpleWatchtowerSet = simpleVerificationConsumer.watchtowerAddress() == watchtowerAddress;
        bool storageWatchtowerSet = storageQueryConsumer.watchtowerAddress() == watchtowerAddress;

        console.log("Simple Consumer properly linked: ", simpleLinked);
        console.log("Storage Consumer properly linked:", storageLinked);
        console.log("Simple Consumer watchtower set: ", simpleWatchtowerSet);
        console.log("Storage Consumer watchtower set:", storageWatchtowerSet);

        if (simpleLinked && storageLinked && simpleWatchtowerSet && storageWatchtowerSet) {
            console.log("\nAll contracts deployed and configured successfully!");
        } else {
            console.log("\nWARNING: Contract configuration verification failed!");
        }
    }
}
