// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import "forge-std/Test.sol";
import "../src/OpacitySDK.sol";
import "../src/IOpacitySDK.sol";
import "../src/examples/SimpleVerificationConsumer.sol";
import "../src/examples/StorageQueryConsumer.sol";

/**
 * @title ExampleConsumersTest
 * @notice Unit tests for the example consumer contracts
 * @dev Tests both SimpleVerificationConsumer and StorageQueryConsumer to verify:
 *      - Correct OpacitySDK configuration inheritance
 *      - Default parameter values (quorum threshold, block stale measure)
 *      - Payload hash computation functionality
 *      - Storage mechanisms for verified data
 *
 *      Note: These tests use a mocked BLS signature checker and focus on
 *      contract configuration and data handling, not actual BLS verification.
 */
contract ExampleConsumersTest is Test {
    /// @notice Instance of the simple verification consumer for testing
    SimpleVerificationConsumer public simpleConsumer;

    /// @notice Instance of the storage query consumer for testing
    StorageQueryConsumer public storageConsumer;

    /// @notice Mock address for the BLS signature checker
    address public blsSignatureChecker;

    /// @notice Test user address for payload construction
    address public testUser;

    /**
     * @notice Sets up the test environment before each test
     * @dev Deploys both consumer contracts with a mocked BLS signature checker.
     *      The mock has minimal bytecode (0x00) to satisfy the constructor check.
     */
    function setUp() public {
        // Mock BLS signature checker address
        blsSignatureChecker = address(0x1234);
        testUser = address(0x5678);

        // Deploy contracts with mocked BLS signature checker
        vm.etch(blsSignatureChecker, hex"00");
        simpleConsumer = new SimpleVerificationConsumer(blsSignatureChecker);
        storageConsumer = new StorageQueryConsumer(blsSignatureChecker);
    }

    /**
     * @notice Tests that SimpleVerificationConsumer inherits the correct quorum threshold
     * @dev Verifies the default 66% threshold is inherited from OpacitySDK
     */
    function testSimpleConsumerGetQuorumThreshold() public {
        uint8 threshold = simpleConsumer.getQuorumThreshold();
        assertEq(threshold, 66, "Quorum threshold should be 66%");
    }

    /**
     * @notice Tests that SimpleVerificationConsumer inherits the correct block stale measure
     * @dev Verifies the default 300 block limit is inherited from OpacitySDK
     */
    function testSimpleConsumerGetBlockStaleMeasure() public {
        uint32 staleMeasure = simpleConsumer.getBlockStaleMeasure();
        assertEq(staleMeasure, 300, "Block stale measure should be 300 blocks");
    }

    /**
     * @notice Tests that StorageQueryConsumer inherits the correct quorum threshold
     * @dev Verifies the default 66% threshold is inherited from OpacitySDK
     */
    function testStorageConsumerGetQuorumThreshold() public {
        uint8 threshold = storageConsumer.getQuorumThreshold();
        assertEq(threshold, 66, "Quorum threshold should be 66%");
    }

    /**
     * @notice Tests that StorageQueryConsumer inherits the correct block stale measure
     * @dev Verifies the default 300 block limit is inherited from OpacitySDK
     */
    function testStorageConsumerGetBlockStaleMeasure() public {
        uint32 staleMeasure = storageConsumer.getBlockStaleMeasure();
        assertEq(staleMeasure, 300, "Block stale measure should be 300 blocks");
    }

    /**
     * @notice Tests that StorageQueryConsumer correctly initializes with empty user data
     * @dev Verifies that getUserValues returns an empty array for a user with no stored values.
     *      Note: Actual verification cannot be tested without a real BLS signature checker.
     */
    function testStorageQueryConsumerValueStorage() public {
        // Create a simple commitment with value reveals
        IOpacitySDK.Resource memory resource =
            IOpacitySDK.Resource({platformUrl: "https://api.bank.com", resourceName: "balance", param: "A1"});

        IOpacitySDK.ValueReveal[] memory values = new IOpacitySDK.ValueReveal[](1);
        values[0] = IOpacitySDK.ValueReveal({resource: resource, value: "1000.00"});

        IOpacitySDK.Composition[] memory compositions = new IOpacitySDK.Composition[](0);
        IOpacitySDK.ConditionGroup[] memory conditions = new IOpacitySDK.ConditionGroup[](0);

        IOpacitySDK.CommitmentPayload memory payload = IOpacitySDK.CommitmentPayload({
            userAddr: testUser, values: values, compositions: compositions, conditions: conditions, sig: hex""
        });

        // Get stored values (should be empty initially)
        IOpacitySDK.ValueReveal[] memory storedValues = storageConsumer.getUserValues(testUser);
        assertEq(storedValues.length, 0, "Should have no stored values initially");

        // Note: We can't actually verify the commitment without a real BLS signature checker
        // But we can test the data structures and storage
    }

    /**
     * @notice Tests that StorageQueryConsumer correctly computes payload hashes
     * @dev Verifies the inherited computePayloadHash function produces non-zero hashes
     */
    function testStorageConsumerPayloadHashing() public {
        // Test that the storage consumer can compute payload hashes correctly
        IOpacitySDK.Resource memory resource =
            IOpacitySDK.Resource({platformUrl: "https://api.example.com", resourceName: "data", param: "user1"});

        IOpacitySDK.ValueReveal[] memory values = new IOpacitySDK.ValueReveal[](1);
        values[0] = IOpacitySDK.ValueReveal({resource: resource, value: "test_value"});

        IOpacitySDK.Composition[] memory compositions = new IOpacitySDK.Composition[](0);
        IOpacitySDK.ConditionGroup[] memory conditions = new IOpacitySDK.ConditionGroup[](0);

        IOpacitySDK.CommitmentPayload memory payload = IOpacitySDK.CommitmentPayload({
            userAddr: testUser, values: values, compositions: compositions, conditions: conditions, sig: hex""
        });

        bytes32 hash = storageConsumer.computePayloadHash(payload);
        assertNotEq(hash, bytes32(0), "Payload hash should not be zero");
    }
}
