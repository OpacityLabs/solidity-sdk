// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.30;

import "forge-std/Script.sol";
import "@eigenlayer-middleware/BLSSignatureChecker.sol";
import "@eigenlayer-middleware/interfaces/IRegistryCoordinator.sol";
import "../src/examples/SimpleVerificationConsumer.sol";

/**
 * @title Deploy
 * @notice Foundry deployment script for OpacitySDK example contracts
 * @dev This script deploys the SimpleVerificationConsumer contract using an existing
 *      BLS signature checker. It requires:
 *      - PRIVATE_KEY environment variable set with the deployer's private key
 *      - A deployed BLS signature checker address
 *      - A deployed registry coordinator address
 *
 *      Usage:
 *      ```bash
 *      forge script script/Deploy.s.sol:Deploy \
 *        --sig "run(address,address)" <blsCheckerAddr> <registryCoordAddr> \
 *        --rpc-url $RPC_URL --broadcast
 *      ```
 */
contract Deploy is Script {
    /**
     * @notice Reference to the BLS signature checker contract
     */
    BLSSignatureChecker public blsSignatureChecker;

    /**
     * @notice The deployed SimpleVerificationConsumer instance
     */
    SimpleVerificationConsumer public simpleVerificationConsumer;

    /**
     * @notice Main deployment entrypoint
     * @dev Deploys a SimpleVerificationConsumer linked to the provided BLS signature checker.
     *      Reads PRIVATE_KEY from environment variables for transaction signing.
     *      Logs deployment progress and final addresses to console.
     * @param blsSignatureCheckerAddress Address of an already-deployed BLS signature checker (must be non-zero)
     * @param registryCoordinator Address of the EigenLayer registry coordinator (must be non-zero, used for logging)
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

        printDeploymentSummary();
    }

    /**
     * @notice Prints a summary of all deployed contracts and verifies linkage
     * @dev Internal helper function called after deployment completes.
     *      Verifies that the SimpleVerificationConsumer is correctly linked
     *      to the BLS signature checker by comparing stored addresses.
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
