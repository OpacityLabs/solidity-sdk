// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity ^0.8.30;

import "@eigenlayer-middleware/BLSSignatureChecker.sol";
import {
    IBLSSignatureChecker, IBLSSignatureCheckerTypes
} from "@eigenlayer-middleware/interfaces/IBLSSignatureChecker.sol";

/**
 * @title OpacitySDK
 * @notice Lightweight SDK for implementing opacity verification
 * @dev Inherit from this contract to add opacity verification capabilities to your contract
 */
abstract contract OpacitySDK {
    /**
     * @notice Resource tuple (PU, r, PA) representing a resource from a platform
     * @param platformUrl Platform URL (e.g., "https://api.bank.com")
     * @param resourceName Resource name (e.g., "balance")
     * @param param Resource-specific parameter (e.g., "A1")
     */
    struct Resource {
        string platformUrl;
        string resourceName;
        string param;
    }

    /**
     * @notice Public reveal pair (Resource, value)
     * @param resource The resource being revealed
     * @param value The primitive value (string, number as string, bool as string, or bytes)
     */
    struct ValueReveal {
        Resource resource;
        string value;
    }

    /**
     * @notice Composition operation
     * @param op Operation type: "sum" or "concat"
     * @param resources Array of resources to apply the operation to
     */
    struct Composition {
        string op;
        Resource[] resources;
    }

    /**
     * @notice Conditional atom for conditions
     * @param atomType Type of condition: "substr" or "gt"
     * @param value The value for the condition (needle for substr, threshold for gt)
     */
    struct CondAtom {
        string atomType;
        string value;
    }

    /**
     * @notice Condition group
     * @param targets Array of resources that must satisfy all conditions
     * @param allOf Array of conditional atoms that all targets must satisfy
     */
    struct ConditionGroup {
        Resource[] targets;
        CondAtom[] allOf;
    }

    /**
     * @notice Unified Commitment Payload (P) as defined in the schema
     * @param userAddr Signer's address
     * @param values Optional public reveals as (R, v) pairs
     * @param compositions Optional list of composition items
     * @param conditions Optional list of condition groups
     * @param sig Signature over UID(ProtoTag, UserAddr, P)
     */
    struct CommitmentPayload {
        address userAddr;
        ValueReveal[] values;
        Composition[] compositions;
        ConditionGroup[] conditions;
        bytes sig;
    }

    /**
     * @notice Struct containing all parameters needed for verification
     * @param quorumNumbers The quorum numbers to check signatures for
     * @param referenceBlockNumber The block number to use as reference for operator set
     * @param nonSignerStakesAndSignature The non-signer stakes and signature data computed off-chain
     * @param payload The unified commitment payload
     */
    struct VerificationParams {
        bytes quorumNumbers;
        uint32 referenceBlockNumber;
        IBLSSignatureCheckerTypes.NonSignerStakesAndSignature nonSignerStakesAndSignature;
        CommitmentPayload payload;
    }

    // The BLS signature checker contract
    BLSSignatureChecker public immutable blsSignatureChecker;

    // Constants for stake threshold checking
    uint8 public constant THRESHOLD_DENOMINATOR = 100;
    uint8 public QUORUM_THRESHOLD = 66;
    uint32 public BLOCK_STALE_MEASURE = 300;

    // Custom errors
    error InvalidSignature();
    error InsufficientQuorumThreshold();
    error StaleBlockNumber();
    error FutureBlockNumber();

    /**
     * @notice Constructor for OpacitySDK
     * @param _blsSignatureChecker Address of the deployed BLS signature checker contract
     */
    constructor(address _blsSignatureChecker) {
        require(_blsSignatureChecker != address(0), "Invalid BLS signature checker address");
        blsSignatureChecker = BLSSignatureChecker(_blsSignatureChecker);
    }

    /**
     * @notice Compute the Resource ID (RID) as UID(platformUrl, resourceName, param)
     * @param resource The resource to compute the RID for
     * @return The RID as a bytes32 hash
     */
    function computeRID(Resource memory resource) public pure returns (bytes32) {
        return keccak256(abi.encode(resource.platformUrl, resource.resourceName, resource.param));
    }

    /**
     * @notice Compute the payload hash for signature verification
     * @dev Implements UID(ProtoTag, UserAddr, P) where P is the commitment payload
     * @param payload The commitment payload
     * @return The payload hash
     */
    function computePayloadHash(CommitmentPayload memory payload) public pure returns (bytes32) {
        // Protocol tag for versioning
        bytes32 protoTag = keccak256("OPACITY-v1");

        // Hash the entire payload structure
        bytes32 payloadHash = keccak256(
            abi.encode(
                payload.userAddr,
                payload.values,
                payload.compositions,
                payload.conditions
            )
        );

        return keccak256(abi.encode(protoTag, payload.userAddr, payloadHash));
    }

    /**
     * @notice Function to verify if a signature is valid
     * @param params The verification parameters wrapped in a struct
     * @return success Whether the verification succeeded
     */
    function verify(VerificationParams calldata params) external view returns (bool success) {
        // Check block number validity
        require(params.referenceBlockNumber < block.number, FutureBlockNumber());
        require((params.referenceBlockNumber + BLOCK_STALE_MEASURE) >= uint32(block.number), StaleBlockNumber());

        // Calculate message hash from the commitment payload
        // Signature is over UID(ProtoTag, UserAddr, P)
        bytes32 msgHash = computePayloadHash(params.payload);

        // Verify the signatures using checkSignatures
        (IBLSSignatureCheckerTypes.QuorumStakeTotals memory stakeTotals,) = blsSignatureChecker.checkSignatures(
            msgHash, params.quorumNumbers, params.referenceBlockNumber, params.nonSignerStakesAndSignature
        );

        // Check that signatories own at least 66% of each quorum
        for (uint256 i = 0; i < params.quorumNumbers.length; i++) {
            require(
                stakeTotals.signedStakeForQuorum[i] * THRESHOLD_DENOMINATOR
                    >= stakeTotals.totalStakeForQuorum[i] * QUORUM_THRESHOLD,
                InsufficientQuorumThreshold()
            );
        }

        return true;
    }

    /**
     * @notice Get the current quorum threshold
     * @return The current quorum threshold percentage
     */
    function getQuorumThreshold() external view returns (uint8) {
        return QUORUM_THRESHOLD;
    }

    /**
     * @notice Get the block stale measure
     * @return The number of blocks after which a reference block is considered stale
     */
    function getBlockStaleMeasure() external view returns (uint32) {
        return BLOCK_STALE_MEASURE;
    }
}
