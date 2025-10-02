// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity ^0.8.30;

import {IBLSSignatureCheckerTypes} from "@eigenlayer-middleware/interfaces/IBLSSignatureChecker.sol";

/**
 * @title IOpacitySDK
 * @notice Interface for OpacitySDK containing all structs, events, and errors
 */
interface IOpacitySDK {
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

    /// @notice Thrown when the BLS signature verification fails
    error InvalidSignature();

    /// @notice Thrown when the quorum threshold is not met (signatories own less than required percentage)
    error InsufficientQuorumThreshold();

    /// @notice Thrown when the reference block number is too old (beyond BLOCK_STALE_MEASURE)
    error StaleBlockNumber();

    /// @notice Thrown when the reference block number is in the future
    error FutureBlockNumber();

    /**
     * @notice Compute the payload hash for signature verification
     * @dev Implements UID(ProtoTag, UserAddr, P) where P is the commitment payload
     * @param payload The commitment payload
     * @return The payload hash
     */
    function computePayloadHash(CommitmentPayload memory payload) external pure returns (bytes32);

    /**
     * @notice Function to verify if a signature is valid
     * @param params The verification parameters wrapped in a struct
     * @return success Whether the verification succeeded
     */
    function verify(VerificationParams calldata params) external view returns (bool success);

    /**
     * @notice Get the current quorum threshold
     * @return The current quorum threshold percentage
     */
    function getQuorumThreshold() external view returns (uint8);

    /**
     * @notice Get the block stale measure
     * @return The number of blocks after which a reference block is considered stale
     */
    function getBlockStaleMeasure() external view returns (uint32);
}
