// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import "forge-std/Test.sol";
import "../src/OpacitySDK.sol";
import "../src/examples/SimpleVerificationConsumer.sol";
import "../src/examples/StorageQueryConsumer.sol";
import "@eigenlayer-middleware/BLSSignatureChecker.sol";

contract OpacitySDKTest is Test {
    SimpleVerificationConsumer public simpleConsumer;
    StorageQueryConsumer public storageConsumer;
    address public blsSignatureChecker;
    address public testUser;

    function setUp() public {
        // Mock BLS signature checker address (we'll use a simple address for unit testing)
        blsSignatureChecker = address(0x1234);
        testUser = address(0x5678);

        // Deploy contracts with mocked BLS signature checker
        vm.etch(blsSignatureChecker, hex"00");
        simpleConsumer = new SimpleVerificationConsumer(blsSignatureChecker);
        storageConsumer = new StorageQueryConsumer(blsSignatureChecker);
    }

    function testComputePayloadHashBasic() public {
        OpacitySDK.ValueReveal[] memory values = new OpacitySDK.ValueReveal[](0);
        OpacitySDK.Composition[] memory compositions = new OpacitySDK.Composition[](0);
        OpacitySDK.ConditionGroup[] memory conditions = new OpacitySDK.ConditionGroup[](0);

        OpacitySDK.CommitmentPayload memory payload = OpacitySDK.CommitmentPayload({
            userAddr: testUser,
            values: values,
            compositions: compositions,
            conditions: conditions,
            sig: hex""
        });

        bytes32 hash = simpleConsumer.computePayloadHash(payload);
        assertNotEq(hash, bytes32(0), "Payload hash should not be zero");
    }

    function testComputePayloadHashWithValues() public {
        // Create resources
        OpacitySDK.Resource memory resource1 =
            OpacitySDK.Resource({platformUrl: "https://api.bank.com", resourceName: "balance", param: "A1"});

        OpacitySDK.Resource memory resource2 =
            OpacitySDK.Resource({platformUrl: "https://api.bank.com", resourceName: "balance", param: "A2"});

        // Create value reveals
        OpacitySDK.ValueReveal[] memory values = new OpacitySDK.ValueReveal[](2);
        values[0] = OpacitySDK.ValueReveal({resource: resource1, value: "730.25"});
        values[1] = OpacitySDK.ValueReveal({resource: resource2, value: "1450.00"});

        OpacitySDK.Composition[] memory compositions = new OpacitySDK.Composition[](0);
        OpacitySDK.ConditionGroup[] memory conditions = new OpacitySDK.ConditionGroup[](0);

        OpacitySDK.CommitmentPayload memory payload = OpacitySDK.CommitmentPayload({
            userAddr: testUser,
            values: values,
            compositions: compositions,
            conditions: conditions,
            sig: hex""
        });

        bytes32 hash = simpleConsumer.computePayloadHash(payload);
        assertNotEq(hash, bytes32(0), "Payload hash with values should not be zero");
    }

    function testComputePayloadHashWithCompositions() public {
        // Create resources
        OpacitySDK.Resource memory resource1 =
            OpacitySDK.Resource({platformUrl: "https://api.bank.com", resourceName: "balance", param: "A1"});

        OpacitySDK.Resource memory resource2 =
            OpacitySDK.Resource({platformUrl: "https://api.bank.com", resourceName: "balance", param: "A2"});

        // Create composition
        OpacitySDK.Resource[] memory compResources = new OpacitySDK.Resource[](2);
        compResources[0] = resource1;
        compResources[1] = resource2;

        OpacitySDK.Composition[] memory compositions = new OpacitySDK.Composition[](1);
        compositions[0] = OpacitySDK.Composition({op: "sum", resources: compResources});

        OpacitySDK.ValueReveal[] memory values = new OpacitySDK.ValueReveal[](0);
        OpacitySDK.ConditionGroup[] memory conditions = new OpacitySDK.ConditionGroup[](0);

        OpacitySDK.CommitmentPayload memory payload = OpacitySDK.CommitmentPayload({
            userAddr: testUser,
            values: values,
            compositions: compositions,
            conditions: conditions,
            sig: hex""
        });

        bytes32 hash = simpleConsumer.computePayloadHash(payload);
        assertNotEq(hash, bytes32(0), "Payload hash with compositions should not be zero");
    }

    function testComputePayloadHashWithConditions() public {
        // Create resource
        OpacitySDK.Resource memory resource =
            OpacitySDK.Resource({platformUrl: "https://api.bank.com", resourceName: "balance", param: "A1"});

        // Create condition atoms
        OpacitySDK.CondAtom[] memory atoms = new OpacitySDK.CondAtom[](1);
        atoms[0] = OpacitySDK.CondAtom({atomType: "gt", value: "500"});

        // Create condition group
        OpacitySDK.Resource[] memory targets = new OpacitySDK.Resource[](1);
        targets[0] = resource;

        OpacitySDK.ConditionGroup[] memory conditions = new OpacitySDK.ConditionGroup[](1);
        conditions[0] = OpacitySDK.ConditionGroup({targets: targets, allOf: atoms});

        OpacitySDK.ValueReveal[] memory values = new OpacitySDK.ValueReveal[](0);
        OpacitySDK.Composition[] memory compositions = new OpacitySDK.Composition[](0);

        OpacitySDK.CommitmentPayload memory payload = OpacitySDK.CommitmentPayload({
            userAddr: testUser,
            values: values,
            compositions: compositions,
            conditions: conditions,
            sig: hex""
        });

        bytes32 hash = simpleConsumer.computePayloadHash(payload);
        assertNotEq(hash, bytes32(0), "Payload hash with conditions should not be zero");
    }

    function testFullCommitmentPayload() public {
        // Create resources
        OpacitySDK.Resource memory bankResource1 =
            OpacitySDK.Resource({platformUrl: "https://api.bank.com", resourceName: "balance", param: "A1"});

        OpacitySDK.Resource memory bankResource2 =
            OpacitySDK.Resource({platformUrl: "https://api.bank.com", resourceName: "balance", param: "A2"});

        OpacitySDK.Resource memory hrResource =
            OpacitySDK.Resource({platformUrl: "https://hr.example.com", resourceName: "employer", param: "USER123"});

        // Create value reveals (public commitment)
        OpacitySDK.ValueReveal[] memory values = new OpacitySDK.ValueReveal[](3);
        values[0] = OpacitySDK.ValueReveal({resource: bankResource1, value: "730.25"});
        values[1] = OpacitySDK.ValueReveal({resource: bankResource2, value: "1450.00"});
        values[2] = OpacitySDK.ValueReveal({resource: hrResource, value: "Acme Inc"});

        // Create composition (sum of balances)
        OpacitySDK.Resource[] memory sumResources = new OpacitySDK.Resource[](2);
        sumResources[0] = bankResource1;
        sumResources[1] = bankResource2;

        OpacitySDK.Composition[] memory compositions = new OpacitySDK.Composition[](1);
        compositions[0] = OpacitySDK.Composition({op: "sum", resources: sumResources});

        // Create conditions
        // Condition 1: Both balances > 100
        OpacitySDK.Resource[] memory bothBalances = new OpacitySDK.Resource[](2);
        bothBalances[0] = bankResource1;
        bothBalances[1] = bankResource2;

        OpacitySDK.CondAtom[] memory atoms1 = new OpacitySDK.CondAtom[](1);
        atoms1[0] = OpacitySDK.CondAtom({atomType: "gt", value: "100"});

        // Condition 2: First balance > 500
        OpacitySDK.Resource[] memory firstBalance = new OpacitySDK.Resource[](1);
        firstBalance[0] = bankResource1;

        OpacitySDK.CondAtom[] memory atoms2 = new OpacitySDK.CondAtom[](1);
        atoms2[0] = OpacitySDK.CondAtom({atomType: "gt", value: "500"});

        // Condition 3: Employer contains "Inc"
        OpacitySDK.Resource[] memory employer = new OpacitySDK.Resource[](1);
        employer[0] = hrResource;

        OpacitySDK.CondAtom[] memory atoms3 = new OpacitySDK.CondAtom[](1);
        atoms3[0] = OpacitySDK.CondAtom({atomType: "substr", value: "Inc"});

        OpacitySDK.ConditionGroup[] memory conditions = new OpacitySDK.ConditionGroup[](3);
        conditions[0] = OpacitySDK.ConditionGroup({targets: bothBalances, allOf: atoms1});
        conditions[1] = OpacitySDK.ConditionGroup({targets: firstBalance, allOf: atoms2});
        conditions[2] = OpacitySDK.ConditionGroup({targets: employer, allOf: atoms3});

        // Create full commitment payload
        OpacitySDK.CommitmentPayload memory payload = OpacitySDK.CommitmentPayload({
            userAddr: testUser,
            values: values,
            compositions: compositions,
            conditions: conditions,
            sig: hex"1234567890abcdef"
        });

        bytes32 hash = simpleConsumer.computePayloadHash(payload);
        assertNotEq(hash, bytes32(0), "Full commitment payload hash should not be zero");
    }

    function testStorageQueryConsumerValueStorage() public {
        // Create a simple commitment with value reveals
        OpacitySDK.Resource memory resource =
            OpacitySDK.Resource({platformUrl: "https://api.bank.com", resourceName: "balance", param: "A1"});

        OpacitySDK.ValueReveal[] memory values = new OpacitySDK.ValueReveal[](1);
        values[0] = OpacitySDK.ValueReveal({resource: resource, value: "1000.00"});

        OpacitySDK.Composition[] memory compositions = new OpacitySDK.Composition[](0);
        OpacitySDK.ConditionGroup[] memory conditions = new OpacitySDK.ConditionGroup[](0);

        OpacitySDK.CommitmentPayload memory payload = OpacitySDK.CommitmentPayload({
            userAddr: testUser,
            values: values,
            compositions: compositions,
            conditions: conditions,
            sig: hex""
        });

        // Get stored values (should be empty initially)
        OpacitySDK.ValueReveal[] memory storedValues = storageConsumer.getUserValues(testUser);
        assertEq(storedValues.length, 0, "Should have no stored values initially");

        // Note: We can't actually verify the commitment without a real BLS signature checker
        // But we can test the data structures
    }

    function testGetQuorumThreshold() public {
        uint8 threshold = simpleConsumer.getQuorumThreshold();
        assertEq(threshold, 66, "Quorum threshold should be 66%");
    }

    function testGetBlockStaleMeasure() public {
        uint32 staleMeasure = simpleConsumer.getBlockStaleMeasure();
        assertEq(staleMeasure, 300, "Block stale measure should be 300 blocks");
    }

    function testMultipleConditionAtoms() public {
        // Test multiple condition atoms in one group
        OpacitySDK.Resource memory resource =
            OpacitySDK.Resource({platformUrl: "https://api.bank.com", resourceName: "balance", param: "A1"});

        OpacitySDK.CondAtom[] memory atoms = new OpacitySDK.CondAtom[](2);
        atoms[0] = OpacitySDK.CondAtom({atomType: "gt", value: "100"});
        atoms[1] = OpacitySDK.CondAtom({atomType: "gt", value: "500"});

        OpacitySDK.Resource[] memory targets = new OpacitySDK.Resource[](1);
        targets[0] = resource;

        OpacitySDK.ConditionGroup[] memory conditions = new OpacitySDK.ConditionGroup[](1);
        conditions[0] = OpacitySDK.ConditionGroup({targets: targets, allOf: atoms});

        OpacitySDK.ValueReveal[] memory values = new OpacitySDK.ValueReveal[](0);
        OpacitySDK.Composition[] memory compositions = new OpacitySDK.Composition[](0);

        OpacitySDK.CommitmentPayload memory payload = OpacitySDK.CommitmentPayload({
            userAddr: testUser,
            values: values,
            compositions: compositions,
            conditions: conditions,
            sig: hex""
        });

        bytes32 hash = simpleConsumer.computePayloadHash(payload);
        assertNotEq(hash, bytes32(0), "Payload with multiple condition atoms should hash correctly");
    }

    function testConcatComposition() public {
        // Test concat operation
        OpacitySDK.Resource memory resource1 =
            OpacitySDK.Resource({platformUrl: "https://api.example.com", resourceName: "firstName", param: "USER123"});

        OpacitySDK.Resource memory resource2 =
            OpacitySDK.Resource({platformUrl: "https://api.example.com", resourceName: "lastName", param: "USER123"});

        OpacitySDK.Resource[] memory concatResources = new OpacitySDK.Resource[](2);
        concatResources[0] = resource1;
        concatResources[1] = resource2;

        OpacitySDK.Composition[] memory compositions = new OpacitySDK.Composition[](1);
        compositions[0] = OpacitySDK.Composition({op: "concat", resources: concatResources});

        OpacitySDK.ValueReveal[] memory values = new OpacitySDK.ValueReveal[](0);
        OpacitySDK.ConditionGroup[] memory conditions = new OpacitySDK.ConditionGroup[](0);

        OpacitySDK.CommitmentPayload memory payload = OpacitySDK.CommitmentPayload({
            userAddr: testUser,
            values: values,
            compositions: compositions,
            conditions: conditions,
            sig: hex""
        });

        bytes32 hash = simpleConsumer.computePayloadHash(payload);
        assertNotEq(hash, bytes32(0), "Concat composition should hash correctly");
    }

    function testEmptyPayloadDifferentUsers() public {
        // Test that same payload structure with different users produces different hashes
        OpacitySDK.ValueReveal[] memory values = new OpacitySDK.ValueReveal[](0);
        OpacitySDK.Composition[] memory compositions = new OpacitySDK.Composition[](0);
        OpacitySDK.ConditionGroup[] memory conditions = new OpacitySDK.ConditionGroup[](0);

        OpacitySDK.CommitmentPayload memory payload1 = OpacitySDK.CommitmentPayload({
            userAddr: testUser,
            values: values,
            compositions: compositions,
            conditions: conditions,
            sig: hex""
        });

        OpacitySDK.CommitmentPayload memory payload2 = OpacitySDK.CommitmentPayload({
            userAddr: address(0x9999),
            values: values,
            compositions: compositions,
            conditions: conditions,
            sig: hex""
        });

        bytes32 hash1 = simpleConsumer.computePayloadHash(payload1);
        bytes32 hash2 = simpleConsumer.computePayloadHash(payload2);

        assertNotEq(hash1, hash2, "Different users should produce different payload hashes");
    }
}
