// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.30;

import "forge-std/Script.sol";
import "@eigenlayer-middleware/BLSSignatureChecker.sol";
import "@eigenlayer-middleware/interfaces/IRegistryCoordinator.sol";
import "../src/examples/SimpleVerificationConsumer.sol";
import "./DeployOpacityExamples.s.sol";
import "./DeployBLSSignatureChecker.s.sol";

/**
 * @title Deploy
 * @notice Helper contract for deployment with configurable or default registry coordinator
 * @dev Provides convenience functions with default Holesky testnet address
 */
contract Deploy is Script {
    // Default Registry Coordinator address (testnet holesky)
    address constant DEFAULT_REGISTRY_COORDINATOR = 0x3e43AA225b5cB026C5E8a53f62572b10D526a50B;

    // Deployed contracts
    BLSSignatureChecker public blsSignatureChecker;
    SimpleVerificationConsumer public simpleVerificationConsumer;

    /**
     * @notice Get registry coordinator address from env or use default
     * @return address The registry coordinator address
     */
    function getRegistryCoordinator() internal view returns (address) {
        try vm.envAddress("REGISTRY_COORDINATOR") returns (address envAddress) {
            return envAddress;
        } catch {
            return DEFAULT_REGISTRY_COORDINATOR;
        }
    }

    /**
     * @notice Deploy BLS + SimpleVerificationConsumer only (default deployment)
     */
    function run() external {
        address registryCoordinator = getRegistryCoordinator();
        uint256 deployerPrivateKey = vm.envUint("PRIVATE_KEY");

        console.log("Starting default OpacitySDK deployment...");
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

        printDeploymentSummary(registryCoordinator);
    }

    /**
     * @notice Print deployment summary
     */
    function printDeploymentSummary(address registryCoordinator) internal view {
        console.log("\n========================================");
        console.log("       DEPLOYMENT SUMMARY");
        console.log("========================================");
        console.log("Registry Coordinator:        ", registryCoordinator);
        console.log("BLS Signature Checker:       ", address(blsSignatureChecker));
        console.log("Simple Verification Consumer:", address(simpleVerificationConsumer));
        console.log("========================================");

        console.log("\n=== Verification Check ===");
        console.log("Simple Consumer BLS Address: ", address(simpleVerificationConsumer.blsSignatureChecker()));

        bool linked = address(simpleVerificationConsumer.blsSignatureChecker()) == address(blsSignatureChecker);
        console.log("Simple Consumer properly linked: ", linked);

        if (linked) {
            console.log("All contracts deployed and linked successfully!");
        } else {
            console.log("Contract linking verification failed!");
        }
    }

    /**
     * @notice Deploy all Opacity examples with default registry coordinator
     */
    function deployExamplesDefault() external {
        DeployOpacityExamples deployer = new DeployOpacityExamples();
        deployer.run(DEFAULT_REGISTRY_COORDINATOR);
    }

    /**
     * @notice Deploy all Opacity examples with custom registry coordinator
     * @param registryCoordinator The registry coordinator address to use
     */
    function deployExamplesCustom(address registryCoordinator) external {
        DeployOpacityExamples deployer = new DeployOpacityExamples();
        deployer.run(registryCoordinator);
    }

    /**
     * @notice Deploy BLS Signature Checker with default registry coordinator
     */
    function deployBLSDefault() external {
        DeployBLSSignatureChecker deployer = new DeployBLSSignatureChecker();
        deployer.run(DEFAULT_REGISTRY_COORDINATOR);
    }

    /**
     * @notice Deploy BLS Signature Checker with custom registry coordinator
     * @param registryCoordinator The registry coordinator address to use
     */
    function deployBLSCustom(address registryCoordinator) external {
        DeployBLSSignatureChecker deployer = new DeployBLSSignatureChecker();
        deployer.run(registryCoordinator);
    }
}
