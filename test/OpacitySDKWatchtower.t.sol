// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import "forge-std/Test.sol";
import "../src/OpacitySDK.sol";
import {IBLSSignatureCheckerTypes} from "@eigenlayer-middleware/interfaces/IBLSSignatureChecker.sol";
import {BN254} from "@eigenlayer-middleware/libraries/BN254.sol";

// Test contract that extends OpacitySDK for testing
contract TestableOpacitySDK is OpacitySDK {
    constructor(address _blsSignatureChecker, BN254.G1Point memory _watchtowerPubkey)
        OpacitySDK(_blsSignatureChecker, _watchtowerPubkey) {}
}

contract OpacitySDKWatchtowerTest is Test {
    TestableOpacitySDK public sdk;
    address public blsSignatureChecker;

    // Watchtower BLS pubkey (example values for testing)
    uint256 public watchtowerPubkeyX = 0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef;
    uint256 public watchtowerPubkeyY = 0xfedcba0987654321fedcba0987654321fedcba0987654321fedcba0987654321;

    address public user = address(0x1234);

    function setUp() public {
        // Deploy mock BLS signature checker (just a simple address for testing)
        blsSignatureChecker = address(0x5678);

        // Deploy SDK with watchtower BLS pubkey
        BN254.G1Point memory watchtowerPubkey = BN254.G1Point({X: watchtowerPubkeyX, Y: watchtowerPubkeyY});
        sdk = new TestableOpacitySDK(blsSignatureChecker, watchtowerPubkey);
    }

    function testWatchtowerCanBeDisabled() public {
        // Disable watchtower
        sdk.setWatchtowerStatus(false);
        assertFalse(sdk.watchtowerEnabled());
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

    function testWatchtowerEnabledByDefault() public view {
        assertTrue(sdk.watchtowerEnabled());
    }

    function testWatchtowerPubkeyInitialization() public view {
        (uint256 x, uint256 y) = sdk.watchtowerPubkey();
        assertEq(x, watchtowerPubkeyX);
        assertEq(y, watchtowerPubkeyY);
    }

    function testCannotDeployWithZeroWatchtowerPubkey() public {
        BN254.G1Point memory zeroPubkey = BN254.G1Point({X: 0, Y: 0});
        vm.expectRevert("Invalid watchtower pubkey");
        new TestableOpacitySDK(blsSignatureChecker, zeroPubkey);
    }

    function testCannotDeployWithZeroBlsSignatureChecker() public {
        BN254.G1Point memory watchtowerPubkey = BN254.G1Point({X: watchtowerPubkeyX, Y: watchtowerPubkeyY});
        vm.expectRevert("Invalid BLS signature checker address");
        new TestableOpacitySDK(address(0), watchtowerPubkey);
    }

    function testUpdateWatchtowerPubkey() public {
        uint256 newX = 0xaaaa;
        uint256 newY = 0xbbbb;

        vm.expectEmit(true, true, true, true);
        emit OpacitySDK.WatchtowerPubkeyUpdated(watchtowerPubkeyX, watchtowerPubkeyY, newX, newY);

        BN254.G1Point memory newPubkey = BN254.G1Point({X: newX, Y: newY});
        sdk.updateWatchtowerPubkey(newPubkey);

        (uint256 x, uint256 y) = sdk.watchtowerPubkey();
        assertEq(x, newX);
        assertEq(y, newY);
    }

    function testCannotUpdateWatchtowerPubkeyToZero() public {
        BN254.G1Point memory zeroPubkey = BN254.G1Point({X: 0, Y: 0});
        vm.expectRevert(OpacitySDK.InvalidWatchtowerPubkey.selector);
        sdk.updateWatchtowerPubkey(zeroPubkey);
    }

    function testWatchtowerSignedSentinel() public view {
        // WATCHTOWER_SIGNED should be max uint32
        assertEq(sdk.WATCHTOWER_SIGNED(), type(uint32).max);
    }

    function testVerificationParamsWithWatchtowerSignedIndex() public view {
        // Create params where watchtower signed (index = WATCHTOWER_SIGNED)
        OpacitySDK.VerificationParams memory params = _createValidParams();
        params.watchtowerNonSignerIndex = sdk.WATCHTOWER_SIGNED();

        // Verify the params are correctly set
        assertEq(params.watchtowerNonSignerIndex, type(uint32).max);
    }

    function testVerificationParamsWithWatchtowerDidNotSign() public view {
        // Create params where watchtower did not sign (index points to watchtower in non-signers)
        OpacitySDK.VerificationParams memory params = _createValidParams();

        // Add watchtower pubkey to nonSignerPubkeys at index 0
        BN254.G1Point[] memory nonSigners = new BN254.G1Point[](1);
        nonSigners[0] = BN254.G1Point({X: watchtowerPubkeyX, Y: watchtowerPubkeyY});
        params.nonSignerStakesAndSignature.nonSignerPubkeys = nonSigners;
        params.watchtowerNonSignerIndex = 0; // Points to watchtower

        // Verify the setup
        assertEq(params.nonSignerStakesAndSignature.nonSignerPubkeys.length, 1);
        assertEq(params.nonSignerStakesAndSignature.nonSignerPubkeys[0].X, watchtowerPubkeyX);
        assertEq(params.watchtowerNonSignerIndex, 0);
    }

    // Helper functions
    function _createValidParams() internal view returns (OpacitySDK.VerificationParams memory) {
        OpacitySDK.VerificationParams memory params;
        params.quorumNumbers = hex"00";
        params.referenceBlockNumber = uint32(block.number - 1);

        // Create empty arrays for non-signers (watchtower signed in this case)
        BN254.G1Point[] memory nonSignerPubkeys = new BN254.G1Point[](0);
        BN254.G1Point[] memory quorumApks = new BN254.G1Point[](1);
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
        params.watchtowerNonSignerIndex = sdk.WATCHTOWER_SIGNED(); // Default: watchtower signed

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
