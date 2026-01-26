// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import "../OpacitySDK.sol";
import "../IOpacitySDK.sol";
import "@eigenlayer-middleware/interfaces/IBLSSignatureChecker.sol";

/**
 * @title SimpleVerificationConsumer
 * @notice A minimal example contract demonstrating basic Opacity attestation verification
 * @dev This contract shows the simplest possible integration with OpacitySDK.
 *      It verifies attestations and emits an event on success, but does not store any data.
 *      Use this as a template for stateless verification use cases.
 */
contract SimpleVerificationConsumer is OpacitySDK {
    /**
     * @notice Emitted when user data verification is attempted
     * @param user The address of the user whose data was verified
     * @param isValid Whether the verification succeeded
     */
    event DataVerified(address indexed user, bool isValid);

    /**
     * @notice Initializes the consumer with the BLS signature checker
     * @param _blsSignatureChecker Address of the deployed BLS signature checker contract
     */
    constructor(address _blsSignatureChecker) OpacitySDK(_blsSignatureChecker) {}

    /**
     * @notice Verifies user data and emits a verification event
     * @dev This function wraps the OpacitySDK verify() call in a try-catch to provide
     *      a boolean return value instead of reverting on failure. The verification result
     *      is emitted as a DataVerified event for off-chain tracking.
     * @param params The VerificationParams struct containing quorum numbers, reference block,
     *               BLS signature data, and the commitment payload
     * @return True if verification succeeded, false if verification failed or reverted
     */
    function verifyUserData(IOpacitySDK.VerificationParams calldata params) public returns (bool) {
        try this.verify(params) returns (bool verified) {
            // Verification successful - emit event
            emit DataVerified(params.payload.userAddr, verified);
            return verified;
        } catch {
            return false;
        }
    }
}
