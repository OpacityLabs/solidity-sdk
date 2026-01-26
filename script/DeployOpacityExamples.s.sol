// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.30;

import "forge-std/Script.sol";
import "@eigenlayer-middleware/BLSSignatureChecker.sol";
import "@eigenlayer-middleware/interfaces/IRegistryCoordinator.sol";
import {BN254} from "@eigenlayer-middleware/libraries/BN254.sol";
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

    // Watchtower BLS public key coordinates (can be set via environment variables)
    uint256 public watchtowerPubkeyX;
    uint256 public watchtowerPubkeyY;

    // Deployed contract addresses
    BLSSignatureChecker public blsSignatureChecker;
    SimpleVerificationConsumer public simpleVerificationConsumer;
    StorageQueryConsumer public storageQueryConsumer;

    function run() external {
        uint256 deployerPrivateKey = vm.envUint("PRIVATE_KEY");

        // Try to get watchtower pubkey from environment, otherwise use defaults for testing
        try vm.envUint("WATCHTOWER_PUBKEY_X") returns (uint256 _x) {
            watchtowerPubkeyX = _x;
        } catch {
            // Default watchtower pubkey for testing (should be replaced in production)
            watchtowerPubkeyX = 0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef;
            console.log("WARNING: Using default watchtower pubkey X. Set WATCHTOWER_PUBKEY_X env var for production.");
        }

        try vm.envUint("WATCHTOWER_PUBKEY_Y") returns (uint256 _y) {
            watchtowerPubkeyY = _y;
        } catch {
            // Default watchtower pubkey for testing (should be replaced in production)
            watchtowerPubkeyY = 0xfedcba0987654321fedcba0987654321fedcba0987654321fedcba0987654321;
            console.log("WARNING: Using default watchtower pubkey Y. Set WATCHTOWER_PUBKEY_Y env var for production.");
        }

        console.log("Starting OpacitySDK deployment...");
        console.log("Deployer address:", vm.addr(deployerPrivateKey));
        console.log("Registry Coordinator:", REGISTRY_COORDINATOR);
        console.log("Watchtower Pubkey X:", watchtowerPubkeyX);
        console.log("Watchtower Pubkey Y:", watchtowerPubkeyY);

        BN254.G1Point memory watchtowerPubkey = BN254.G1Point({X: watchtowerPubkeyX, Y: watchtowerPubkeyY});

        vm.startBroadcast(deployerPrivateKey);

        // Step 1: Deploy BLS Signature Checker
        console.log("\n=== Step 1: Deploying BLS Signature Checker ===");
        blsSignatureChecker = new BLSSignatureChecker(IRegistryCoordinator(REGISTRY_COORDINATOR));
        console.log("BLS Signature Checker deployed at:", address(blsSignatureChecker));

        // Step 2: Deploy Simple Verification Consumer
        console.log("\n=== Step 2: Deploying Simple Verification Consumer ===");
        simpleVerificationConsumer = new SimpleVerificationConsumer(
            address(blsSignatureChecker),
            watchtowerPubkey
        );
        console.log("Simple Verification Consumer deployed at:", address(simpleVerificationConsumer));

        // Step 3: Deploy Storage Query Consumer
        console.log("\n=== Step 3: Deploying Storage Query Consumer ===");
        storageQueryConsumer = new StorageQueryConsumer(
            address(blsSignatureChecker),
            watchtowerPubkey
        );
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
        console.log("Watchtower Pubkey X:         ", watchtowerPubkeyX);
        console.log("Watchtower Pubkey Y:         ", watchtowerPubkeyY);
        console.log("BLS Signature Checker:       ", address(blsSignatureChecker));
        console.log("Simple Verification Consumer:", address(simpleVerificationConsumer));
        console.log("Storage Query Consumer:      ", address(storageQueryConsumer));
        console.log("========================================");

        // Verify the contracts are properly linked
        console.log("\n=== Verification Checks ===");
        console.log("Simple Consumer BLS Address:", address(simpleVerificationConsumer.blsSignatureChecker()));
        console.log("Storage Consumer BLS Address:", address(storageQueryConsumer.blsSignatureChecker()));

        (uint256 simpleX, uint256 simpleY) = simpleVerificationConsumer.watchtowerPubkey();
        (uint256 storageX, uint256 storageY) = storageQueryConsumer.watchtowerPubkey();
        console.log("Simple Consumer Watchtower X:", simpleX);
        console.log("Simple Consumer Watchtower Y:", simpleY);
        console.log("Storage Consumer Watchtower X:", storageX);
        console.log("Storage Consumer Watchtower Y:", storageY);

        bool simpleLinked = address(simpleVerificationConsumer.blsSignatureChecker()) == address(blsSignatureChecker);
        bool storageLinked = address(storageQueryConsumer.blsSignatureChecker()) == address(blsSignatureChecker);
        bool simpleWatchtowerSet = simpleX == watchtowerPubkeyX && simpleY == watchtowerPubkeyY;
        bool storageWatchtowerSet = storageX == watchtowerPubkeyX && storageY == watchtowerPubkeyY;

        console.log("Simple Consumer properly linked:", simpleLinked);
        console.log("Storage Consumer properly linked:", storageLinked);
        console.log("Simple Consumer watchtower set:", simpleWatchtowerSet);
        console.log("Storage Consumer watchtower set:", storageWatchtowerSet);

        if (simpleLinked && storageLinked && simpleWatchtowerSet && storageWatchtowerSet) {
            console.log("\nAll contracts deployed and configured successfully!");
        } else {
            console.log("\nWARNING: Contract configuration verification failed!");
        }
    }
}
