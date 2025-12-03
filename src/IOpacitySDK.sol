// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity ^0.8.30;

import {IBLSSignatureCheckerTypes} from "@eigenlayer-middleware/interfaces/IBLSSignatureChecker.sol";

/**
 * @title IOpacitySDK
 * @notice Interface for the Opacity SDK, providing verifiable private data attestations on-chain
 * @dev This interface defines all structs, events, errors, and function signatures for the OpacitySDK.
 *      The SDK enables verification of BLS-signed commitments from an operator network, allowing
 *      smart contracts to validate private data attestations without exposing the underlying data.
 */
interface IOpacitySDK {
    /**
     * @notice Resource tuple (PU, r, PA) representing a resource from a platform
     * @dev Resources are the fundamental building blocks of the Opacity protocol, representing
     *      data fetched from external platforms. Each resource is uniquely identified by the
     *      combination of platform URL, resource name, and parameter.
     * @param platformUrl The base URL of the platform API (e.g., "https://api.bank.com")
     * @param resourceName The name of the resource endpoint (e.g., "balance")
     * @param param A resource-specific parameter for the query (e.g., account ID "A1")
     */
    struct Resource {
        string platformUrl;
        string resourceName;
        string param;
    }

    /**
     * @notice Public reveal pair (Resource, value) for publicly committed data
     * @dev ValueReveal structures contain data that the user has chosen to reveal publicly
     *      as part of their attestation. Values are always encoded as strings regardless
     *      of their underlying type (numbers, booleans, etc.).
     * @param resource The resource being revealed
     * @param value The revealed value encoded as a string (e.g., "730.25", "true", "Acme Inc")
     */
    struct ValueReveal {
        Resource resource;
        string value;
    }

    /**
     * @notice Composition operation for combining multiple resource values
     * @dev Compositions allow aggregating multiple resources into a single derived value.
     *      Supported operations:
     *      - "sum": Adds numeric values from all resources together
     *      - "concat": Concatenates string values from all resources
     * @param op The operation type to perform ("sum" or "concat")
     * @param resources Array of resources whose values will be combined by the operation
     */
    struct Composition {
        string op;
        Resource[] resources;
    }

    /**
     * @notice Conditional atom representing a single condition check
     * @dev CondAtom structures define individual conditions that can be applied to resources.
     * @param atomType The type of condition to evaluate
     * @param value The condition parameter
     */
    struct CondAtom {
        string atomType;
        string value;
    }

    /**
     * @notice Condition group representing a set of conditions applied to target resources
     * @dev A ConditionGroup defines that ALL specified conditions (allOf) must be satisfied
     *      by ALL specified target resources. This enables complex validation logic such as
     *      "both account balances must be greater than $100" or "employer name must contain 'Inc'".
     * @param targets Array of resources that must all satisfy the conditions
     * @param allOf Array of conditional atoms that all targets must satisfy (AND logic)
     */
    struct ConditionGroup {
        Resource[] targets;
        CondAtom[] allOf;
    }

    /**
     * @notice Unified Commitment Payload (P) containing all attestation data
     * @dev The CommitmentPayload is the core data structure signed by the operator network.
     *      It contains the user's address, any publicly revealed values, composition operations,
     *      and condition groups. The signature field contains the user's signature over the
     *      unique identifier UID(ProtoTag, UserAddr, P).
     * @param userAddr The address of the user making the attestation
     * @param values Optional array of publicly revealed (Resource, value) pairs
     * @param compositions Optional array of composition operations on resources
     * @param conditions Optional array of condition groups that must be satisfied
     * @param sig User's signature over the payload identifier
     */
    struct CommitmentPayload {
        address userAddr;
        ValueReveal[] values;
        Composition[] compositions;
        ConditionGroup[] conditions;
        bytes sig;
    }

    /**
     * @notice Struct containing all parameters needed for BLS signature verification
     * @dev This struct bundles all verification inputs required by the verify() function.
     *      The referenceBlockNumber must be recent (within BLOCK_STALE_MEASURE blocks) to ensure
     *      the operator set hasn't changed significantly since the attestation was created.
     * @param quorumNumbers The quorum numbers to check signatures against (encoded as bytes)
     * @param referenceBlockNumber The block number used to determine the operator set composition
     * @param nonSignerStakesAndSignature BLS signature data and non-signer information computed off-chain
     * @param payload The unified commitment payload containing the attested data
     */
    struct VerificationParams {
        bytes quorumNumbers;
        uint32 referenceBlockNumber;
        IBLSSignatureCheckerTypes.NonSignerStakesAndSignature nonSignerStakesAndSignature;
        CommitmentPayload payload;
    }

    /**
     * @notice Thrown when the BLS signature verification fails
     * @dev This error indicates that the aggregated BLS signature does not match the expected signers
     */
    error InvalidSignature();

    /**
     * @notice Thrown when the quorum threshold is not met
     * @dev Signatories must own at least QUORUM_THRESHOLD percent of the stake for each quorum
     */
    error InsufficientQuorumThreshold();

    /**
     * @notice Thrown when the reference block number is too old
     * @dev The reference block must be within BLOCK_STALE_MEASURE blocks of the current block
     */
    error StaleBlockNumber();

    /**
     * @notice Thrown when the reference block number is in the future
     * @dev The reference block must be less than the current block number
     */
    error FutureBlockNumber();

    /**
     * @notice Computes the unique payload hash used for signature verification
     * @dev Implements the UID(ProtoTag, UserAddr, P) computation where P is the commitment payload.
     *      This hash is what the operator network signs to attest to the validity of the payload data.
     * @param payload The commitment payload to hash
     * @return The keccak256 hash of the encoded payload
     */
    function computePayloadHash(CommitmentPayload memory payload) external pure returns (bytes32);

    /**
     * @notice Verifies a BLS-signed attestation from the operator network
     * @dev Checks that:
     *      1. The reference block is not in the future
     *      2. The reference block is not stale (within BLOCK_STALE_MEASURE blocks)
     *      3. The BLS signature is valid
     *      4. The signing operators meet the quorum threshold for all specified quorums
     * @param params The verification parameters containing quorum info, block reference, and payload
     * @return success True if the attestation is valid, reverts otherwise
     */
    function verify(VerificationParams calldata params) external view returns (bool success);

    /**
     * @notice Returns the current quorum threshold percentage
     * @dev Signatories must control at least this percentage of stake for verification to succeed
     * @return The quorum threshold as a percentage (e.g., 66 means 66%)
     */
    function getQuorumThreshold() external view returns (uint8);

    /**
     * @notice Returns the maximum age of a reference block in blocks
     * @dev Reference blocks older than this value will cause verification to fail with StaleBlockNumber
     * @return The number of blocks after which a reference block is considered stale
     */
    function getBlockStaleMeasure() external view returns (uint32);
}
