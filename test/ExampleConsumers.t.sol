// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import "forge-std/Test.sol";
import "../src/OpacitySDK.sol";
import "../src/IOpacitySDK.sol";
import "../src/examples/SimpleVerificationConsumer.sol";
import "../src/examples/StorageQueryConsumer.sol";

/**
 * @title ExampleConsumersTest
 * @notice Tests for the example consumer contracts (SimpleVerificationConsumer and StorageQueryConsumer)
 */
contract ExampleConsumersTest is Test {
    SimpleVerificationConsumer public simpleConsumer;
    StorageQueryConsumer public storageConsumer;
    address public blsSignatureChecker;
    address public testUser;

    function setUp() public {
        // Mock BLS signature checker address
        blsSignatureChecker = address(0x1234);
        testUser = address(0x5678);

        // Deploy contracts with mocked BLS signature checker
        vm.etch(blsSignatureChecker, hex"00");
        simpleConsumer = new SimpleVerificationConsumer(blsSignatureChecker);
        storageConsumer = new StorageQueryConsumer(blsSignatureChecker);
    }

    function testSimpleConsumerGetQuorumThreshold() public {
        uint8 threshold = simpleConsumer.getQuorumThreshold();
        assertEq(threshold, 66, "Quorum threshold should be 66%");
    }

    function testSimpleConsumerGetBlockStaleMeasure() public {
        uint32 staleMeasure = simpleConsumer.getBlockStaleMeasure();
        assertEq(staleMeasure, 300, "Block stale measure should be 300 blocks");
    }

    function testStorageConsumerGetQuorumThreshold() public {
        uint8 threshold = storageConsumer.getQuorumThreshold();
        assertEq(threshold, 66, "Quorum threshold should be 66%");
    }

    function testStorageConsumerGetBlockStaleMeasure() public {
        uint32 staleMeasure = storageConsumer.getBlockStaleMeasure();
        assertEq(staleMeasure, 300, "Block stale measure should be 300 blocks");
    }

    function testStorageQueryConsumerValueStorage() public {
        // Create a simple commitment with value reveals
        IOpacitySDK.Resource memory resource =
            IOpacitySDK.Resource({platformUrl: "https://api.bank.com", resourceName: "balance", param: "A1"});

        IOpacitySDK.ValueReveal[] memory values = new IOpacitySDK.ValueReveal[](1);
        values[0] = IOpacitySDK.ValueReveal({resource: resource, value: "1000.00"});

        IOpacitySDK.Composition[] memory compositions = new IOpacitySDK.Composition[](0);
        IOpacitySDK.ConditionGroup[] memory conditions = new IOpacitySDK.ConditionGroup[](0);

        IOpacitySDK.CommitmentPayload memory payload = IOpacitySDK.CommitmentPayload({
            userAddr: testUser,
            values: values,
            compositions: compositions,
            conditions: conditions,
            sig: hex""
        });

        // Get stored values (should be empty initially)
        IOpacitySDK.ValueReveal[] memory storedValues = storageConsumer.getUserValues(testUser);
        assertEq(storedValues.length, 0, "Should have no stored values initially");

        // Note: We can't actually verify the commitment without a real BLS signature checker
        // But we can test the data structures and storage
    }

    function testStorageConsumerPayloadHashing() public {
        // Test that the storage consumer can compute payload hashes correctly
        IOpacitySDK.Resource memory resource =
            IOpacitySDK.Resource({platformUrl: "https://api.example.com", resourceName: "data", param: "user1"});

        IOpacitySDK.ValueReveal[] memory values = new IOpacitySDK.ValueReveal[](1);
        values[0] = IOpacitySDK.ValueReveal({resource: resource, value: "test_value"});

        IOpacitySDK.Composition[] memory compositions = new IOpacitySDK.Composition[](0);
        IOpacitySDK.ConditionGroup[] memory conditions = new IOpacitySDK.ConditionGroup[](0);

        IOpacitySDK.CommitmentPayload memory payload = IOpacitySDK.CommitmentPayload({
            userAddr: testUser,
            values: values,
            compositions: compositions,
            conditions: conditions,
            sig: hex""
        });

        bytes32 hash = storageConsumer.computePayloadHash(payload);
        assertNotEq(hash, bytes32(0), "Payload hash should not be zero");
    }
}
