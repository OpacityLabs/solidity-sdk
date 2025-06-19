// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

import "forge-std/Script.sol";
import "@eigenlayer-middleware/BLSSignatureChecker.sol";
import "@eigenlayer-middleware/interfaces/IRegistryCoordinator.sol";

contract DeployBLSSignatureChecker is Script {
    address constant REGISTRY_COORDINATOR = 0x2E5f76f1fF6347319C0FbE821F0F11afDf37DcCe;
    
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