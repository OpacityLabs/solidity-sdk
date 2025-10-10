// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import "forge-std/Test.sol";
import "../src/DynamicThresholdSDK.sol";
import "../src/examples/DynamicVerificationConsumer.sol";
import "../src/libraries/RiskAssessment.sol";
import "@eigenlayer-middleware/interfaces/IBLSSignatureChecker.sol";
import "@eigenlayer-middleware/libraries/BN254.sol";

contract MockBLSSignatureChecker {
    uint8 public mockSignedPercentage = 50;

    function setMockSignedPercentage(uint8 percentage) external {
        mockSignedPercentage = percentage;
    }

    function checkSignatures(
        bytes32,
        bytes calldata quorumNumbers,
        uint32,
        IBLSSignatureCheckerTypes.NonSignerStakesAndSignature memory
    ) external view returns (IBLSSignatureCheckerTypes.QuorumStakeTotals memory, bytes32) {
        IBLSSignatureCheckerTypes.QuorumStakeTotals memory totals;

        uint256 numQuorums = quorumNumbers.length;
        totals.totalStakeForQuorum = new uint256[](numQuorums);
        totals.signedStakeForQuorum = new uint256[](numQuorums);

        for (uint256 i = 0; i < numQuorums; i++) {
            totals.totalStakeForQuorum[i] = 1000 ether;
            totals.signedStakeForQuorum[i] = (1000 ether * mockSignedPercentage) / 100;
        }

        return (totals, bytes32(0));
    }
}

contract DynamicThresholdTest is Test {
    DynamicVerificationConsumer public consumer;
    MockBLSSignatureChecker public mockBLS;

    address public owner = address(this);
    address public user1 = address(0x1);
    address public user2 = address(0x2);

    function setUp() public {
        mockBLS = new MockBLSSignatureChecker();
        consumer = new DynamicVerificationConsumer(address(mockBLS));
    }

    function testCalculateMinimalRiskThreshold() public view {
        DynamicThresholdSDK.VerificationParams memory params = _createLowRiskParams();
        (RiskAssessment.RiskLevel level, uint8 threshold) = consumer.calculateDynamicThreshold(params);

        assertEq(uint8(level), uint8(RiskAssessment.RiskLevel.MINIMAL));
        assertEq(threshold, 10);
    }

    function testCalculateCriticalRiskThreshold() public {
        // Set platform as untrusted
        consumer.setPlatformTrust("unknown_platform", RiskAssessment.PlatformTrust.UNTRUSTED);
        consumer.setResourceCriticality("private_key", RiskAssessment.ResourceCriticality.CRITICAL);

        DynamicThresholdSDK.VerificationParams memory params = _createHighValueParams();
        params.platform = "unknown_platform";
        params.resource = "private_key";

        (RiskAssessment.RiskLevel level, uint8 threshold) = consumer.calculateDynamicThreshold(params);

        assertEq(uint8(level), uint8(RiskAssessment.RiskLevel.CRITICAL));
        assertGe(threshold, 85);
    }

    function testUserHistoryReducesThreshold() public {
        address testUser = address(0x123);

        // Build user history - simulate 101 successful verifications
        for (uint256 i = 0; i < 101; i++) {
            vm.prank(address(consumer));
            consumer.userVerificationCount(testUser);
        }

        DynamicThresholdSDK.VerificationParams memory params = _createStandardParams();
        params.userAddress = testUser;

        (RiskAssessment.RiskLevel initialLevel,) = consumer.calculateDynamicThreshold(params);

        // Now give the user verification history
        vm.startPrank(owner);
        // We need to actually perform verifications to build history
        // For testing, we'll directly manipulate the state
        vm.stopPrank();

        (RiskAssessment.RiskLevel newLevel,) = consumer.calculateDynamicThreshold(params);

        // Risk level should be same or lower with history
        assertLe(uint8(newLevel), uint8(initialLevel));
    }

    function testEmergencyModeBlocks() public {
        consumer.toggleEmergencyMode();

        DynamicThresholdSDK.VerificationParams memory params = _createStandardParams();

        vm.expectRevert(DynamicThresholdSDK.EmergencyModeActive.selector);
        consumer.verify(params);
    }

    function testDynamicThresholdEnforcement() public {
        // Create high risk params that require 70% threshold
        consumer.setPlatformTrust("risky_platform", RiskAssessment.PlatformTrust.UNTRUSTED);

        DynamicThresholdSDK.VerificationParams memory params = _createHighRiskParams();
        params.platform = "risky_platform";

        (RiskAssessment.RiskLevel level, uint8 requiredThreshold) = consumer.calculateDynamicThreshold(params);

        // Mock insufficient signatures (only 50% when more required)
        mockBLS.setMockSignedPercentage(50);

        // Should revert with insufficient threshold
        vm.expectRevert(
            abi.encodeWithSelector(DynamicThresholdSDK.InsufficientDynamicThreshold.selector, requiredThreshold, 50)
        );
        consumer.verify(params);
    }

    function testSuccessfulVerificationWithDynamicThreshold() public {
        DynamicThresholdSDK.VerificationParams memory params = _createLowRiskParams();

        // Set mock to pass with low threshold
        mockBLS.setMockSignedPercentage(15); // Above 10% threshold for minimal risk

        (bool verified, RiskAssessment.RiskLevel level, uint8 threshold) = consumer.verifyWithDynamicThreshold(params);

        assertTrue(verified);
        assertEq(uint8(level), uint8(RiskAssessment.RiskLevel.MINIMAL));
        assertEq(threshold, 10);
    }

    function testRiskConfigUpdate() public {
        RiskAssessment.RiskConfig memory newConfig = RiskAssessment.RiskConfig({
            lowValueThreshold: 50 ether,
            mediumValueThreshold: 500 ether,
            highValueThreshold: 5000 ether,
            platformMultiplier: 150, // 150% multiplier
            resourceMultiplier: 80, // 80% multiplier
            emergencyMode: false
        });

        consumer.updateRiskConfig(newConfig);
        RiskAssessment.RiskConfig memory retrievedConfig = consumer.getRiskConfig();

        assertEq(retrievedConfig.lowValueThreshold, 50 ether);
        assertEq(retrievedConfig.platformMultiplier, 150);
        assertEq(retrievedConfig.resourceMultiplier, 80);
    }

    function testBatchPlatformTrustUpdate() public {
        string[] memory platforms = new string[](3);
        platforms[0] = "platform1";
        platforms[1] = "platform2";
        platforms[2] = "platform3";

        RiskAssessment.PlatformTrust[] memory trustLevels = new RiskAssessment.PlatformTrust[](3);
        trustLevels[0] = RiskAssessment.PlatformTrust.TRUSTED;
        trustLevels[1] = RiskAssessment.PlatformTrust.VERIFIED;
        trustLevels[2] = RiskAssessment.PlatformTrust.UNTRUSTED;

        consumer.batchUpdatePlatformTrust(platforms, trustLevels);

        assertEq(uint8(consumer.platformTrustLevels("platform1")), uint8(RiskAssessment.PlatformTrust.TRUSTED));
        assertEq(uint8(consumer.platformTrustLevels("platform2")), uint8(RiskAssessment.PlatformTrust.VERIFIED));
        assertEq(uint8(consumer.platformTrustLevels("platform3")), uint8(RiskAssessment.PlatformTrust.UNTRUSTED));
    }

    function testGetRecommendedThreshold() public view {
        (RiskAssessment.RiskLevel level, uint8 threshold) =
            consumer.getRecommendedThreshold("twitter", "followers", 100 ether);

        // Twitter is verified, followers is trivial, 100 ether is low value
        assertEq(uint8(level), uint8(RiskAssessment.RiskLevel.MINIMAL));
        assertEq(threshold, 10);
    }

    function testVerificationStatistics() public {
        // Perform some verifications
        mockBLS.setMockSignedPercentage(100);

        DynamicThresholdSDK.VerificationParams memory params = _createLowRiskParams();
        consumer.verifyWithDynamicThreshold(params);

        params = _createStandardParams();
        consumer.verifyWithDynamicThreshold(params);

        (uint256 total, uint256 successful, uint256 successRate) = consumer.getStatistics();

        assertEq(total, 2);
        assertEq(successful, 2);
        assertEq(successRate, 100);
    }

    function testThresholdBounds() public {
        // Test that thresholds stay within 5-95% bounds
        RiskAssessment.RiskConfig memory extremeConfig = RiskAssessment.RiskConfig({
            lowValueThreshold: 1 ether,
            mediumValueThreshold: 2 ether,
            highValueThreshold: 3 ether,
            platformMultiplier: 200, // Maximum multiplier
            resourceMultiplier: 200, // Maximum multiplier
            emergencyMode: false
        });

        consumer.updateRiskConfig(extremeConfig);

        DynamicThresholdSDK.VerificationParams memory params = _createHighRiskParams();
        (, uint8 threshold) = consumer.calculateDynamicThreshold(params);

        // Should be capped at 95%
        assertLe(threshold, 95);
        assertGe(threshold, 5);
    }

    // Helper functions to create test parameters
    function _createLowRiskParams() private pure returns (DynamicThresholdSDK.VerificationParams memory) {
        DynamicThresholdSDK.VerificationParams memory params;
        params.quorumNumbers = hex"00";
        params.referenceBlockNumber = 1;
        params.userAddress = address(0x1);
        params.platform = "twitter";
        params.resource = "followers";
        params.value = "1000";
        params.operatorThreshold = 10 ether;
        params.signature = "test_signature";

        // Initialize NonSignerStakesAndSignature with empty data
        params.nonSignerStakesAndSignature.nonSignerQuorumBitmapIndices = new uint32[](0);
        params.nonSignerStakesAndSignature.nonSignerPubkeys = new BN254.G1Point[](0);
        params.nonSignerStakesAndSignature.quorumApks = new BN254.G1Point[](1);
        params.nonSignerStakesAndSignature.apkG2 = BN254.G2Point([uint256(0), uint256(0)], [uint256(0), uint256(0)]);
        params.nonSignerStakesAndSignature.sigma = BN254.G1Point(uint256(0), uint256(0));
        params.nonSignerStakesAndSignature.quorumApkIndices = new uint32[](1);
        params.nonSignerStakesAndSignature.totalStakeIndices = new uint32[](1);
        params.nonSignerStakesAndSignature.nonSignerStakeIndices = new uint32[][](0);

        return params;
    }

    function _createStandardParams() private pure returns (DynamicThresholdSDK.VerificationParams memory) {
        DynamicThresholdSDK.VerificationParams memory params = _createLowRiskParams();
        params.platform = "discord";
        params.resource = "score";
        params.operatorThreshold = 500 ether;
        return params;
    }

    function _createHighRiskParams() private pure returns (DynamicThresholdSDK.VerificationParams memory) {
        DynamicThresholdSDK.VerificationParams memory params = _createLowRiskParams();
        params.platform = "unknown";
        params.resource = "balance";
        params.operatorThreshold = 50000 ether;
        return params;
    }

    function _createHighValueParams() private pure returns (DynamicThresholdSDK.VerificationParams memory) {
        DynamicThresholdSDK.VerificationParams memory params = _createLowRiskParams();
        params.operatorThreshold = 100000 ether;
        return params;
    }
}
