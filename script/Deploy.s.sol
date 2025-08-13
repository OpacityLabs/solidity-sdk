// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.30;

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