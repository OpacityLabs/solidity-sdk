// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import "forge-std/Test.sol";
import "../src/OpacitySDK.sol";
import "../src/IOpacitySDK.sol";
import "../src/examples/SimpleVerificationConsumer.sol";

/**
 * @title OpacitySDKTest
 * @notice Unit tests for OpacitySDK payload hash computation and data structures
 * @dev Tests the core functionality of the OpacitySDK, specifically:
 *      - Payload hash computation for various payload configurations
 *      - Data structure encoding (Resources, ValueReveals, Compositions, Conditions)
 *      - Hash determinism and uniqueness properties
 *
 *      Note: These tests use a mocked BLS signature checker and do not test
 *      actual BLS signature verification. See integration tests for full verification testing.
 */
contract OpacitySDKTest is Test {
    /// @notice The consumer contract instance used for testing
    SimpleVerificationConsumer public consumer;

    /// @notice Mock address for the BLS signature checker
    address public blsSignatureChecker;

    /// @notice Test user address used in payload construction
    address public testUser;

    /**
     * @notice Sets up the test environment before each test
     * @dev Deploys a SimpleVerificationConsumer with a mocked BLS signature checker.
     *      The mock checker has minimal bytecode (0x00) to allow deployment.
     */
    function setUp() public {
        // Mock BLS signature checker address
        blsSignatureChecker = address(0x1234);
        testUser = address(0x5678);

        // Deploy consumer contract with mocked BLS signature checker
        vm.etch(blsSignatureChecker, hex"00");
        consumer = new SimpleVerificationConsumer(blsSignatureChecker);
    }

    /**
     * @notice Tests basic payload hash computation with empty arrays
     * @dev Verifies that a minimal payload with no values, compositions, or conditions
     *      produces a non-zero hash
     */
    function testComputePayloadHashBasic() public {
        IOpacitySDK.ValueReveal[] memory values = new IOpacitySDK.ValueReveal[](0);
        IOpacitySDK.Composition[] memory compositions = new IOpacitySDK.Composition[](0);
        IOpacitySDK.ConditionGroup[] memory conditions = new IOpacitySDK.ConditionGroup[](0);

        IOpacitySDK.CommitmentPayload memory payload = IOpacitySDK.CommitmentPayload({
            userAddr: testUser,
            values: values,
            compositions: compositions,
            conditions: conditions,
            sig: hex""
        });

        bytes32 hash = consumer.computePayloadHash(payload);
        assertNotEq(hash, bytes32(0), "Payload hash should not be zero");
    }

    /**
     * @notice Tests payload hash computation with value reveals
     * @dev Creates two bank balance resources with numeric values and verifies
     *      the resulting hash is non-zero
     */
    function testComputePayloadHashWithValues() public {
        // Create resources
        IOpacitySDK.Resource memory resource1 =
            IOpacitySDK.Resource({platformUrl: "https://api.bank.com", resourceName: "balance", param: "A1"});

        IOpacitySDK.Resource memory resource2 =
            IOpacitySDK.Resource({platformUrl: "https://api.bank.com", resourceName: "balance", param: "A2"});

        // Create value reveals
        IOpacitySDK.ValueReveal[] memory values = new IOpacitySDK.ValueReveal[](2);
        values[0] = IOpacitySDK.ValueReveal({resource: resource1, value: "730.25"});
        values[1] = IOpacitySDK.ValueReveal({resource: resource2, value: "1450.00"});

        IOpacitySDK.Composition[] memory compositions = new IOpacitySDK.Composition[](0);
        IOpacitySDK.ConditionGroup[] memory conditions = new IOpacitySDK.ConditionGroup[](0);

        IOpacitySDK.CommitmentPayload memory payload = IOpacitySDK.CommitmentPayload({
            userAddr: testUser,
            values: values,
            compositions: compositions,
            conditions: conditions,
            sig: hex""
        });

        bytes32 hash = consumer.computePayloadHash(payload);
        assertNotEq(hash, bytes32(0), "Payload hash with values should not be zero");
    }

    /**
     * @notice Tests payload hash computation with a sum composition
     * @dev Creates a composition that sums two bank balance resources
     *      and verifies the hash is non-zero
     */
    function testComputePayloadHashWithCompositions() public {
        // Create resources
        IOpacitySDK.Resource memory resource1 =
            IOpacitySDK.Resource({platformUrl: "https://api.bank.com", resourceName: "balance", param: "A1"});

        IOpacitySDK.Resource memory resource2 =
            IOpacitySDK.Resource({platformUrl: "https://api.bank.com", resourceName: "balance", param: "A2"});

        // Create composition
        IOpacitySDK.Resource[] memory compResources = new IOpacitySDK.Resource[](2);
        compResources[0] = resource1;
        compResources[1] = resource2;

        IOpacitySDK.Composition[] memory compositions = new IOpacitySDK.Composition[](1);
        compositions[0] = IOpacitySDK.Composition({op: "sum", resources: compResources});

        IOpacitySDK.ValueReveal[] memory values = new IOpacitySDK.ValueReveal[](0);
        IOpacitySDK.ConditionGroup[] memory conditions = new IOpacitySDK.ConditionGroup[](0);

        IOpacitySDK.CommitmentPayload memory payload = IOpacitySDK.CommitmentPayload({
            userAddr: testUser,
            values: values,
            compositions: compositions,
            conditions: conditions,
            sig: hex""
        });

        bytes32 hash = consumer.computePayloadHash(payload);
        assertNotEq(hash, bytes32(0), "Payload hash with compositions should not be zero");
    }

    /**
     * @notice Tests payload hash computation with a greater-than condition
     * @dev Creates a condition requiring balance > 500 and verifies the hash is non-zero
     */
    function testComputePayloadHashWithConditions() public {
        // Create resource
        IOpacitySDK.Resource memory resource =
            IOpacitySDK.Resource({platformUrl: "https://api.bank.com", resourceName: "balance", param: "A1"});

        // Create condition atoms
        IOpacitySDK.CondAtom[] memory atoms = new IOpacitySDK.CondAtom[](1);
        atoms[0] = IOpacitySDK.CondAtom({atomType: "gt", value: "500"});

        // Create condition group
        IOpacitySDK.Resource[] memory targets = new IOpacitySDK.Resource[](1);
        targets[0] = resource;

        IOpacitySDK.ConditionGroup[] memory conditions = new IOpacitySDK.ConditionGroup[](1);
        conditions[0] = IOpacitySDK.ConditionGroup({targets: targets, allOf: atoms});

        IOpacitySDK.ValueReveal[] memory values = new IOpacitySDK.ValueReveal[](0);
        IOpacitySDK.Composition[] memory compositions = new IOpacitySDK.Composition[](0);

        IOpacitySDK.CommitmentPayload memory payload = IOpacitySDK.CommitmentPayload({
            userAddr: testUser,
            values: values,
            compositions: compositions,
            conditions: conditions,
            sig: hex""
        });

        bytes32 hash = consumer.computePayloadHash(payload);
        assertNotEq(hash, bytes32(0), "Payload hash with conditions should not be zero");
    }

    /**
     * @notice Tests payload hash computation with a comprehensive payload
     * @dev Creates a complete payload with:
     *      - 3 value reveals (2 bank balances + 1 employer)
     *      - 1 sum composition
     *      - 3 conditions (balance thresholds + substring check)
     *      - A mock signature
     *      Verifies all components hash correctly together
     */
    function testFullCommitmentPayload() public {
        // Create resources
        IOpacitySDK.Resource memory bankResource1 =
            IOpacitySDK.Resource({platformUrl: "https://api.bank.com", resourceName: "balance", param: "A1"});

        IOpacitySDK.Resource memory bankResource2 =
            IOpacitySDK.Resource({platformUrl: "https://api.bank.com", resourceName: "balance", param: "A2"});

        IOpacitySDK.Resource memory hrResource =
            IOpacitySDK.Resource({platformUrl: "https://hr.example.com", resourceName: "employer", param: "USER123"});

        // Create value reveals (public commitment)
        IOpacitySDK.ValueReveal[] memory values = new IOpacitySDK.ValueReveal[](3);
        values[0] = IOpacitySDK.ValueReveal({resource: bankResource1, value: "730.25"});
        values[1] = IOpacitySDK.ValueReveal({resource: bankResource2, value: "1450.00"});
        values[2] = IOpacitySDK.ValueReveal({resource: hrResource, value: "Acme Inc"});

        // Create composition (sum of balances)
        IOpacitySDK.Resource[] memory sumResources = new IOpacitySDK.Resource[](2);
        sumResources[0] = bankResource1;
        sumResources[1] = bankResource2;

        IOpacitySDK.Composition[] memory compositions = new IOpacitySDK.Composition[](1);
        compositions[0] = IOpacitySDK.Composition({op: "sum", resources: sumResources});

        // Create conditions
        // Condition 1: Both balances > 100
        IOpacitySDK.Resource[] memory bothBalances = new IOpacitySDK.Resource[](2);
        bothBalances[0] = bankResource1;
        bothBalances[1] = bankResource2;

        IOpacitySDK.CondAtom[] memory atoms1 = new IOpacitySDK.CondAtom[](1);
        atoms1[0] = IOpacitySDK.CondAtom({atomType: "gt", value: "100"});

        // Condition 2: First balance > 500
        IOpacitySDK.Resource[] memory firstBalance = new IOpacitySDK.Resource[](1);
        firstBalance[0] = bankResource1;

        IOpacitySDK.CondAtom[] memory atoms2 = new IOpacitySDK.CondAtom[](1);
        atoms2[0] = IOpacitySDK.CondAtom({atomType: "gt", value: "500"});

        // Condition 3: Employer contains "Inc"
        IOpacitySDK.Resource[] memory employer = new IOpacitySDK.Resource[](1);
        employer[0] = hrResource;

        IOpacitySDK.CondAtom[] memory atoms3 = new IOpacitySDK.CondAtom[](1);
        atoms3[0] = IOpacitySDK.CondAtom({atomType: "substr", value: "Inc"});

        IOpacitySDK.ConditionGroup[] memory conditions = new IOpacitySDK.ConditionGroup[](3);
        conditions[0] = IOpacitySDK.ConditionGroup({targets: bothBalances, allOf: atoms1});
        conditions[1] = IOpacitySDK.ConditionGroup({targets: firstBalance, allOf: atoms2});
        conditions[2] = IOpacitySDK.ConditionGroup({targets: employer, allOf: atoms3});

        // Create full commitment payload
        IOpacitySDK.CommitmentPayload memory payload = IOpacitySDK.CommitmentPayload({
            userAddr: testUser,
            values: values,
            compositions: compositions,
            conditions: conditions,
            sig: hex"1234567890abcdef"
        });

        bytes32 hash = consumer.computePayloadHash(payload);
        assertNotEq(hash, bytes32(0), "Full commitment payload hash should not be zero");
    }

    /**
     * @notice Tests payload hash with multiple condition atoms in a single group
     * @dev Creates a condition group with two gt conditions (> 100 AND > 500)
     *      applied to the same resource, verifying AND logic encoding
     */
    function testMultipleConditionAtoms() public {
        // Test multiple condition atoms in one group
        IOpacitySDK.Resource memory resource =
            IOpacitySDK.Resource({platformUrl: "https://api.bank.com", resourceName: "balance", param: "A1"});

        IOpacitySDK.CondAtom[] memory atoms = new IOpacitySDK.CondAtom[](2);
        atoms[0] = IOpacitySDK.CondAtom({atomType: "gt", value: "100"});
        atoms[1] = IOpacitySDK.CondAtom({atomType: "gt", value: "500"});

        IOpacitySDK.Resource[] memory targets = new IOpacitySDK.Resource[](1);
        targets[0] = resource;

        IOpacitySDK.ConditionGroup[] memory conditions = new IOpacitySDK.ConditionGroup[](1);
        conditions[0] = IOpacitySDK.ConditionGroup({targets: targets, allOf: atoms});

        IOpacitySDK.ValueReveal[] memory values = new IOpacitySDK.ValueReveal[](0);
        IOpacitySDK.Composition[] memory compositions = new IOpacitySDK.Composition[](0);

        IOpacitySDK.CommitmentPayload memory payload = IOpacitySDK.CommitmentPayload({
            userAddr: testUser,
            values: values,
            compositions: compositions,
            conditions: conditions,
            sig: hex""
        });

        bytes32 hash = consumer.computePayloadHash(payload);
        assertNotEq(hash, bytes32(0), "Payload with multiple condition atoms should hash correctly");
    }

    /**
     * @notice Tests payload hash with a concat composition
     * @dev Creates a composition that concatenates firstName and lastName resources,
     *      verifying string composition encoding
     */
    function testConcatComposition() public {
        // Test concat operation
        IOpacitySDK.Resource memory resource1 =
            IOpacitySDK.Resource({platformUrl: "https://api.example.com", resourceName: "firstName", param: "USER123"});

        IOpacitySDK.Resource memory resource2 =
            IOpacitySDK.Resource({platformUrl: "https://api.example.com", resourceName: "lastName", param: "USER123"});

        IOpacitySDK.Resource[] memory concatResources = new IOpacitySDK.Resource[](2);
        concatResources[0] = resource1;
        concatResources[1] = resource2;

        IOpacitySDK.Composition[] memory compositions = new IOpacitySDK.Composition[](1);
        compositions[0] = IOpacitySDK.Composition({op: "concat", resources: concatResources});

        IOpacitySDK.ValueReveal[] memory values = new IOpacitySDK.ValueReveal[](0);
        IOpacitySDK.ConditionGroup[] memory conditions = new IOpacitySDK.ConditionGroup[](0);

        IOpacitySDK.CommitmentPayload memory payload = IOpacitySDK.CommitmentPayload({
            userAddr: testUser,
            values: values,
            compositions: compositions,
            conditions: conditions,
            sig: hex""
        });

        bytes32 hash = consumer.computePayloadHash(payload);
        assertNotEq(hash, bytes32(0), "Concat composition should hash correctly");
    }

    /**
     * @notice Tests that different user addresses produce different hashes
     * @dev Creates two identical payloads differing only in userAddr,
     *      verifying that the hash is sensitive to the user address
     */
    function testEmptyPayloadDifferentUsers() public {
        // Test that same payload structure with different users produces different hashes
        IOpacitySDK.ValueReveal[] memory values = new IOpacitySDK.ValueReveal[](0);
        IOpacitySDK.Composition[] memory compositions = new IOpacitySDK.Composition[](0);
        IOpacitySDK.ConditionGroup[] memory conditions = new IOpacitySDK.ConditionGroup[](0);

        IOpacitySDK.CommitmentPayload memory payload1 = IOpacitySDK.CommitmentPayload({
            userAddr: testUser,
            values: values,
            compositions: compositions,
            conditions: conditions,
            sig: hex""
        });

        IOpacitySDK.CommitmentPayload memory payload2 = IOpacitySDK.CommitmentPayload({
            userAddr: address(0x9999),
            values: values,
            compositions: compositions,
            conditions: conditions,
            sig: hex""
        });

        bytes32 hash1 = consumer.computePayloadHash(payload1);
        bytes32 hash2 = consumer.computePayloadHash(payload2);

        assertNotEq(hash1, hash2, "Different users should produce different payload hashes");
    }

    /**
     * @notice Tests payload hash determinism with a known expected value
     * @dev Uses hardcoded inputs and expected output to verify:
     *      1. Hash computation is deterministic across runs
     *      2. Hash matches off-chain computed value
     *      3. Any changes to encoding would be detected as test failures
     *
     *      Expected hash: 0xa3f9c50a7b411f721324549daa11a23f82fc9defd756075a3f76edbbf667aef2
     */
    function testHardcodedPayloadHashWithValueReveals() public {
        // This test uses a fixed example with hardcoded expected hash
        // to ensure the payload hash computation remains consistent

        // Create a specific user address
        address specificUser = address(0x742D35cC6634c0532925a3B844BC9E7595F0beBB);

        // Create specific resources with known values
        IOpacitySDK.Resource memory resource1 =
            IOpacitySDK.Resource({platformUrl: "https://api.bank.com", resourceName: "balance", param: "account123"});

        IOpacitySDK.Resource memory resource2 =
            IOpacitySDK.Resource({platformUrl: "https://api.bank.com", resourceName: "balance", param: "account456"});

        // Create value reveals
        IOpacitySDK.ValueReveal[] memory values = new IOpacitySDK.ValueReveal[](2);
        values[0] = IOpacitySDK.ValueReveal({resource: resource1, value: "1000.50"});
        values[1] = IOpacitySDK.ValueReveal({resource: resource2, value: "2500.75"});

        // No compositions or conditions
        IOpacitySDK.Composition[] memory compositions = new IOpacitySDK.Composition[](0);
        IOpacitySDK.ConditionGroup[] memory conditions = new IOpacitySDK.ConditionGroup[](0);

        // Create the commitment payload
        IOpacitySDK.CommitmentPayload memory payload = IOpacitySDK.CommitmentPayload({
            userAddr: specificUser,
            values: values,
            compositions: compositions,
            conditions: conditions,
            sig: hex""
        });

        // Compute the hash
        bytes32 computedHash = consumer.computePayloadHash(payload);

        // Expected hash computed off-chain (keccak256(abi.encode(userAddr, values, compositions, conditions)))
        // This hash should remain constant for this exact payload
        bytes32 expectedHash = 0xa3f9c50a7b411f721324549daa11a23f82fc9defd756075a3f76edbbf667aef2;

        assertEq(computedHash, expectedHash, "Payload hash should match the expected hardcoded value");
    }
}
