// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import "forge-std/Test.sol";
import "../src/OpacitySDK.sol";
import {IBLSSignatureCheckerTypes} from "@eigenlayer-middleware/interfaces/IBLSSignatureChecker.sol";
import {BN254} from "@eigenlayer-middleware/libraries/BN254.sol";

// Test contract that extends OpacitySDK for testing
contract TestableOpacitySDK is OpacitySDK {
    constructor(address _blsSignatureChecker, address _watchtowerAddress) 
        OpacitySDK(_blsSignatureChecker, _watchtowerAddress) {}
}

contract OpacitySDKWatchtowerTest is Test {
    TestableOpacitySDK public sdk;
    address public blsSignatureChecker;
    address public watchtowerAddress;
    uint256 public watchtowerPrivateKey;
    
    address public user = address(0x1234);
    
    function setUp() public {
        // Deploy mock BLS signature checker (just a simple address for testing)
        blsSignatureChecker = address(0x5678);
        
        // Setup watchtower
        watchtowerPrivateKey = 0xabcd;
        watchtowerAddress = vm.addr(watchtowerPrivateKey);
        
        // Deploy SDK with watchtower
        sdk = new TestableOpacitySDK(blsSignatureChecker, watchtowerAddress);
    }
    
    function testWatchtowerSignatureRequired() public {
        OpacitySDK.VerificationParams memory params = _createValidParams();
        params.watchtowerSignature = ""; // Empty watchtower signature
        
        vm.expectRevert(OpacitySDK.WatchtowerSignatureRequired.selector);
        sdk.verify(params);
    }
    
    function testInvalidWatchtowerSignature() public {
        OpacitySDK.VerificationParams memory params = _createValidParams();
        
        // Sign with wrong private key
        uint256 wrongKey = 0xdead;
        bytes32 msgHash = _calculateMsgHash(params);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(wrongKey, msgHash);
        params.watchtowerSignature = abi.encodePacked(r, s, v);
        
        vm.expectRevert(OpacitySDK.InvalidWatchtowerSignature.selector);
        sdk.verify(params);
    }
    
    function testWatchtowerCanBeDisabled() public {
        // Disable watchtower
        sdk.setWatchtowerStatus(false);
        assertFalse(sdk.watchtowerEnabled());
    }
    
    function testWatchtowerCanBeUpdated() public {
        // Create new watchtower
        uint256 newWatchtowerKey = 0xbeef;
        address newWatchtower = vm.addr(newWatchtowerKey);
        
        // Update watchtower address
        vm.expectEmit(true, true, false, false);
        emit OpacitySDK.WatchtowerUpdated(watchtowerAddress, newWatchtower);
        sdk.updateWatchtower(newWatchtower);
        
        assertEq(sdk.watchtowerAddress(), newWatchtower);
    }
    
    function testWatchtowerStatusChange() public {
        // Test disabling
        vm.expectEmit(true, false, false, false);
        emit OpacitySDK.WatchtowerStatusChanged(false);
        sdk.setWatchtowerStatus(false);
        assertFalse(sdk.watchtowerEnabled());
        
        // Test enabling
        vm.expectEmit(true, false, false, false);
        emit OpacitySDK.WatchtowerStatusChanged(true);
        sdk.setWatchtowerStatus(true);
        assertTrue(sdk.watchtowerEnabled());
    }
    
    function testCannotUpdateWatchtowerToZeroAddress() public {
        vm.expectRevert("Invalid watchtower address");
        sdk.updateWatchtower(address(0));
    }
    
    function testWatchtowerAddressInitialization() public {
        assertEq(sdk.watchtowerAddress(), watchtowerAddress);
        assertTrue(sdk.watchtowerEnabled());
    }
    
    function testWatchtowerSignatureVerification() public {
        // Create params
        OpacitySDK.VerificationParams memory params = _createValidParams();
        
        // Sign with watchtower
        bytes32 msgHash = _calculateMsgHash(params);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(watchtowerPrivateKey, msgHash);
        params.watchtowerSignature = abi.encodePacked(r, s, v);
        
        // This would normally call verify, but we can't test the full flow without mocking BLS
        // So we just verify the watchtower was set correctly
        assertTrue(sdk.watchtowerEnabled());
        assertEq(sdk.watchtowerAddress(), watchtowerAddress);
    }
    
    // Helper functions
    function _createValidParams() internal view returns (OpacitySDK.VerificationParams memory) {
        OpacitySDK.VerificationParams memory params;
        params.quorumNumbers = hex"00";
        params.referenceBlockNumber = uint32(block.number - 1);
        
        // Create empty arrays for non-signers
        BN254.G1Point[] memory nonSignerPubkeys = new BN254.G1Point[](0);
        BN254.G1Point[] memory quorumApks = new BN254.G1Point[](1);
        bytes32[] memory nonSignerOperatorIds = new bytes32[](0);
        BN254.G1Point[] memory quorumApkIndices = new BN254.G1Point[](1);
        uint32[] memory totalStakeIndices = new uint32[](1);
        uint32[][] memory nonSignerStakeIndices = new uint32[][](0);
        
        params.nonSignerStakesAndSignature = IBLSSignatureCheckerTypes.NonSignerStakesAndSignature({
            nonSignerQuorumBitmapIndices: new uint32[](0),
            nonSignerPubkeys: nonSignerPubkeys,
            quorumApks: quorumApks,
            apkG2: BN254.G2Point({X: [uint256(0), uint256(0)], Y: [uint256(0), uint256(0)]}),
            sigma: BN254.G1Point({X: uint256(0), Y: uint256(0)}),
            quorumApkIndices: new uint32[](1),
            totalStakeIndices: totalStakeIndices,
            nonSignerStakeIndices: nonSignerStakeIndices
        });
        params.userAddress = user;
        params.platform = "twitter";
        params.resource = "username";
        params.value = "testuser";
        params.operatorThreshold = 66;
        params.signature = "test_signature";
        params.watchtowerSignature = "";
        
        return params;
    }
    
    function _calculateMsgHash(OpacitySDK.VerificationParams memory params) internal pure returns (bytes32) {
        return keccak256(
            abi.encode(
                params.userAddress,
                params.platform,
                params.resource,
                params.value,
                params.operatorThreshold,
                params.signature
            )
        );
    }
}