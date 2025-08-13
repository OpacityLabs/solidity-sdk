// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

import "forge-std/Script.sol";
import "@eigenlayer-middleware/BLSSignatureChecker.sol";
import "@eigenlayer-middleware/interfaces/IRegistryCoordinator.sol";

contract DeployBLSSignatureChecker is Script {
    function run(address registryCoordinator) external {
        uint256 deployerPrivateKey = vm.envUint("PRIVATE_KEY");

        vm.startBroadcast(deployerPrivateKey);

        // Deploy BLS signature checker with registry coordinator address
        BLSSignatureChecker blsSignatureChecker = new BLSSignatureChecker(IRegistryCoordinator(registryCoordinator));

        vm.stopBroadcast();

        console.log("BLS Signature Checker deployed at:", address(blsSignatureChecker));
        console.log("Registry Coordinator:", registryCoordinator);
    }
}
