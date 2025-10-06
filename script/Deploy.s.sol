// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.30;

import "forge-std/Script.sol";
import "@eigenlayer-middleware/BLSSignatureChecker.sol";
import "@eigenlayer-middleware/interfaces/IRegistryCoordinator.sol";
import "../src/examples/SimpleVerificationConsumer.sol";
import "../src/examples/StorageQueryConsumer.sol";

/**
 * @title Deploy
 * @notice Main deployment script for OpacitySDK contracts
 * @dev Supports deploying with existing or new BLS signature checker
 */
contract Deploy is Script {
    // Default Registry Coordinator address (testnet holesky)
    address constant DEFAULT_REGISTRY_COORDINATOR = 0x3e43AA225b5cB026C5E8a53f62572b10D526a50B;

    // Deployed contracts
    BLSSignatureChecker public blsSignatureChecker;
    SimpleVerificationConsumer public simpleVerificationConsumer;
    StorageQueryConsumer public storageQueryConsumer;

    /**
     * @notice Default deployment - deploys BLS + SimpleVerificationConsumer with default registry coordinator
     */
    function run() external {
        run(DEFAULT_REGISTRY_COORDINATOR);
    }

    /**
     * @notice Deploy BLS + SimpleVerificationConsumer with custom registry coordinator
     * @param registryCoordinator Registry coordinator address
     */
    function run(address registryCoordinator) public {
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

        writeDeploymentJson(registryCoordinator, address(0));
        printDeploymentSummary(registryCoordinator);
    }

    /**
     * @notice Deploy with existing BLS signature checker
     * @param blsSignatureCheckerAddress Existing BLS signature checker address
     */
    function runWithBLS(address blsSignatureCheckerAddress) external {
        require(blsSignatureCheckerAddress != address(0), "Invalid BLS address");

        uint256 deployerPrivateKey = vm.envUint("PRIVATE_KEY");
        blsSignatureChecker = BLSSignatureChecker(blsSignatureCheckerAddress);

        console.log("Starting OpacitySDK deployment with existing BLS...");
        console.log("Deployer address:", vm.addr(deployerPrivateKey));
        console.log("Using BLS Signature Checker:", blsSignatureCheckerAddress);

        vm.startBroadcast(deployerPrivateKey);

        // Deploy Simple Verification Consumer
        console.log("\n=== Deploying Simple Verification Consumer ===");
        simpleVerificationConsumer = new SimpleVerificationConsumer(blsSignatureCheckerAddress);
        console.log("Simple Verification Consumer deployed at:", address(simpleVerificationConsumer));

        vm.stopBroadcast();

        writeDeploymentJson(address(0), blsSignatureCheckerAddress);
        printDeploymentSummary(address(0));
    }

    /**
     * @notice Deploy all contracts including StorageQueryConsumer with default registry coordinator
     */
    function runFull() external {
        runFull(DEFAULT_REGISTRY_COORDINATOR);
    }

    /**
     * @notice Deploy all contracts including StorageQueryConsumer with custom registry coordinator
     * @param registryCoordinator Registry coordinator address
     */
    function runFull(address registryCoordinator) public {
        require(registryCoordinator != address(0), "Invalid registry coordinator address");
        uint256 deployerPrivateKey = vm.envUint("PRIVATE_KEY");

        console.log("Starting full OpacitySDK deployment...");
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

        // Deploy Storage Query Consumer
        console.log("\n=== Deploying Storage Query Consumer ===");
        storageQueryConsumer = new StorageQueryConsumer(address(blsSignatureChecker));
        console.log("Storage Query Consumer deployed at:", address(storageQueryConsumer));

        vm.stopBroadcast();

        writeDeploymentJson(registryCoordinator, address(0));
        printDeploymentSummary(registryCoordinator);
    }

    /**
     * @notice Write deployment addresses to JSON file
     * @param registryCoordinator Registry coordinator used (0x0 if not deployed)
     * @param existingBLS Existing BLS address if used (0x0 if newly deployed)
     */
    function writeDeploymentJson(address registryCoordinator, address existingBLS) internal {
        string memory json = "deployment";

        if (existingBLS != address(0)) {
            vm.serializeAddress(json, "blsSignatureChecker", existingBLS);
            vm.serializeString(json, "blsSignatureCheckerStatus", "existing");
        } else {
            vm.serializeAddress(json, "blsSignatureChecker", address(blsSignatureChecker));
            vm.serializeString(json, "blsSignatureCheckerStatus", "deployed");
        }

        if (registryCoordinator != address(0)) {
            vm.serializeAddress(json, "registryCoordinator", registryCoordinator);
        }

        vm.serializeAddress(json, "simpleVerificationConsumer", address(simpleVerificationConsumer));

        if (address(storageQueryConsumer) != address(0)) {
            vm.serializeAddress(json, "storageQueryConsumer", address(storageQueryConsumer));
        }

        string memory finalJson = vm.serializeUint(json, "timestamp", block.timestamp);

        vm.writeJson(finalJson, "./deployments/latest.json");
        console.log("\nDeployment addresses written to deployments/latest.json");
    }

    /**
     * @notice Print deployment summary
     */
    function printDeploymentSummary(address registryCoordinator) internal view {
        console.log("\n========================================");
        console.log("       DEPLOYMENT SUMMARY");
        console.log("========================================");

        if (registryCoordinator != address(0)) {
            console.log("Registry Coordinator:        ", registryCoordinator);
        }

        console.log("BLS Signature Checker:       ", address(blsSignatureChecker));
        console.log("Simple Verification Consumer:", address(simpleVerificationConsumer));

        if (address(storageQueryConsumer) != address(0)) {
            console.log("Storage Query Consumer:      ", address(storageQueryConsumer));
        }

        console.log("========================================");

        console.log("\n=== Verification Check ===");
        console.log("Simple Consumer BLS Address: ", address(simpleVerificationConsumer.blsSignatureChecker()));

        bool simpleLinked = address(simpleVerificationConsumer.blsSignatureChecker()) == address(blsSignatureChecker);
        console.log("Simple Consumer properly linked: ", simpleLinked);

        if (address(storageQueryConsumer) != address(0)) {
            console.log("Storage Consumer BLS Address:", address(storageQueryConsumer.blsSignatureChecker()));
            bool storageLinked = address(storageQueryConsumer.blsSignatureChecker()) == address(blsSignatureChecker);
            console.log("Storage Consumer properly linked:", storageLinked);

            if (simpleLinked && storageLinked) {
                console.log("\nAll contracts deployed and linked successfully!");
            }
        } else if (simpleLinked) {
            console.log("\nAll contracts deployed and linked successfully!");
        }
    }
}
