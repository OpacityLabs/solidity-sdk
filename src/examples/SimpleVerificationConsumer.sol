// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import "../OpacitySDK.sol";
import "@eigenlayer-middleware/interfaces/IBLSSignatureChecker.sol";

contract SimpleVerificationConsumer is OpacitySDK {
    event DataVerified(address user, string platform, string resource, string value, bool isValid, bool watchtowerVerified);

    /**
     * @notice Constructor for SimpleVerificationConsumer
     * @param _blsSignatureChecker Address of the deployed BLS signature checker contract
     * @param _watchtowerAddress Address of the watchtower signer
     */
    constructor(address _blsSignatureChecker, address _watchtowerAddress) 
        OpacitySDK(_blsSignatureChecker, _watchtowerAddress) {}

    /**
     * @notice Verify user data using VerificationParams struct
     * @dev Primary interface - cleaner way to use the OpacitySDK
     * @param params The VerificationParams struct containing all verification parameters
     */
    function verifyUserData(VerificationParams calldata params) public returns (bool) {
        try this.verify(params) returns (bool verified) {
            // Verification successful - emit event
            emit DataVerified(
                params.userAddress, 
                params.platform, 
                params.resource, 
                params.value, 
                verified,
                watchtowerEnabled
            );
            return verified;
        } catch {
            // Verification failed - emit event with false
            emit DataVerified(
                params.userAddress, 
                params.platform, 
                params.resource, 
                params.value, 
                false,
                watchtowerEnabled
            );
            return false;
        }
    }
}
