// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

import "forge-std/Script.sol";
import "@eigenlayer-middleware/BLSSignatureChecker.sol";
import "@eigenlayer-middleware/interfaces/IRegistryCoordinator.sol";

contract DeployBLSSignatureChecker is Script {
    address constant REGISTRY_COORDINATOR = 0x3e43AA225b5cB026C5E8a53f62572b10D526a50B;
    
    function run() external {
        uint256 deployerPrivateKey = vm.envUint("PRIVATE_KEY");
        
        vm.startBroadcast(deployerPrivateKey);
        
        // Deploy BLS signature checker with registry coordinator address
        BLSSignatureChecker blsSignatureChecker = new BLSSignatureChecker(
            IRegistryCoordinator(REGISTRY_COORDINATOR)
        );
        
        vm.stopBroadcast();
        
        console.log("BLS Signature Checker deployed at:", address(blsSignatureChecker));
        console.log("Registry Coordinator:", REGISTRY_COORDINATOR);
    }
} 