// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity ^0.8.30;

import "@eigenlayer-middleware/BLSSignatureChecker.sol";
import {IBLSSignatureCheckerTypes} from "@eigenlayer-middleware/interfaces/IBLSSignatureChecker.sol";
import {IOpacitySDK} from "./IOpacitySDK.sol";

/**
 * @title OpacitySDK
 * @notice Abstract contract providing BLS signature verification for Opacity attestations
 * @dev Inherit from this contract to add Opacity verification capabilities to your contract.
 *      The SDK integrates with EigenLayer's BLS signature infrastructure to verify that
 *      a quorum of operators have attested to the validity of private data commitments.
 *
 *      Example usage:
 *      ```solidity
 *      contract MyConsumer is OpacitySDK {
 *          constructor(address _blsChecker) OpacitySDK(_blsChecker) {}
 *
 *          function processVerifiedData(VerificationParams calldata params) external {
 *              require(this.verify(params), "Verification failed");
 *              // Process verified data from params.payload
 *          }
 *      }
 *      ```
 */
abstract contract OpacitySDK is IOpacitySDK {
    /**
     * @notice The BLS signature checker contract used for cryptographic verification
     * @dev This contract is provided by EigenLayer and handles the BLS signature math
     */
    BLSSignatureChecker public immutable blsSignatureChecker;

    /**
     * @notice Denominator used for threshold percentage calculations
     * @dev QUORUM_THRESHOLD / THRESHOLD_DENOMINATOR gives the required stake fraction
     */
    uint8 public constant THRESHOLD_DENOMINATOR = 100;

    /**
     * @notice Minimum percentage of stake required for quorum (default: 66%)
     * @dev Can be modified by inheriting contracts if needed
     */
    uint8 public QUORUM_THRESHOLD = 66;

    /**
     * @notice Maximum age of reference block in blocks (default: 300 blocks)
     * @dev Attestations with older reference blocks will be rejected as stale
     */
    uint32 public BLOCK_STALE_MEASURE = 300;

    /**
     * @notice Initializes the OpacitySDK with the required BLS signature checker
     * @dev The BLS signature checker must be deployed before this contract and cannot be changed after deployment
     * @param _blsSignatureChecker Address of the deployed BLS signature checker contract (must be non-zero)
     */
    constructor(address _blsSignatureChecker) {
        require(_blsSignatureChecker != address(0), "Invalid BLS signature checker address");
        blsSignatureChecker = BLSSignatureChecker(_blsSignatureChecker);
    }

    /**
     * @notice Computes the unique payload hash used for signature verification
     * @dev Implements the UID(ProtoTag, UserAddr, P) computation where P is the commitment payload.
     *      The hash is computed over the userAddr, values, compositions, and conditions fields.
     *      Note: The signature field is intentionally excluded from the hash.
     *      Note: Protocol tag versioning is prepared but currently disabled.
     * @param payload The commitment payload containing the data to hash
     * @return The keccak256 hash of the ABI-encoded payload fields
     */
    function computePayloadHash(CommitmentPayload memory payload) public pure returns (bytes32) {
        // Protocol tag for versioning (commented out for now)
        // bytes32 protoTag = keccak256("OPACITY-v1");

        // Hash the entire payload structure
        bytes32 payloadHash =
            keccak256(abi.encode(payload.userAddr, payload.values, payload.compositions, payload.conditions));

        // return keccak256(abi.encode(protoTag, payload.userAddr, payloadHash));
        return payloadHash;
    }

    /**
     * @notice Verifies a BLS-signed attestation from the Opacity operator network
     * @dev Performs the following verification steps:
     *      1. Validates the reference block is not in the future (reverts with FutureBlockNumber)
     *      2. Validates the reference block is not stale (reverts with StaleBlockNumber)
     *      3. Computes the payload hash and verifies BLS signatures via the signature checker
     *      4. Checks that each quorum meets the stake threshold (reverts with InsufficientQuorumThreshold)
     *
     *      This function is view-only and does not modify state.
     * @param params The verification parameters containing quorum numbers, block reference, signature data, and payload
     * @return success Always returns true if verification succeeds; reverts on any failure
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

        // Check that signatories own at least QUORUM_THRESHOLD% of each quorum
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
     * @notice Returns the current quorum threshold percentage
     * @dev The threshold determines what fraction of stake must sign for verification to succeed.
     *      For example, 66 means 66% of the total quorum stake must have signed.
     * @return The quorum threshold as a percentage (0-100)
     */
    function getQuorumThreshold() external view returns (uint8) {
        return QUORUM_THRESHOLD;
    }

    /**
     * @notice Returns the maximum age of a reference block in blocks
     * @dev Reference blocks older than current block - BLOCK_STALE_MEASURE will be rejected.
     *      This prevents replay attacks with old operator sets.
     * @return The number of blocks after which a reference block is considered stale
     */
    function getBlockStaleMeasure() external view returns (uint32) {
        return BLOCK_STALE_MEASURE;
    }
}
