// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "../OpacitySDK.sol";
import "@eigenlayer-middleware/interfaces/IBLSSignatureChecker.sol";

contract SimpleVerificationConsumer is OpacitySDK {
    
    event DataVerified(address user, string platform, string resource, string value, bool isValid);

    constructor() OpacitySDK() {}

    /**
     * @notice Verify user data using VerificationParams struct
     * @dev Primary interface - cleaner way to use the OpacitySDK
     * @param params The VerificationParams struct containing all verification parameters
     * @notice refrence the function below for the individual parameters
     */
    function verifyUserData(
        VerificationParams calldata params
    ) public returns (bool) {
        
        try this.verify(params) returns (bool verified) {
            // Verification successful - emit event  
            emit DataVerified(params.targetAddress, params.platform, params.resource, params.value, true);
            return true;
            
        } catch {
            // Verification failed - emit event with false status
            emit DataVerified(params.targetAddress, params.platform, params.resource, params.value, false);
            return false;
        }
    }

    /**
     * @notice Verify user data from individual parameters
     * @dev Helper function that constructs VerificationParams struct from individual parameters
     */
    function verifyUserDataFromParams(
        bytes calldata quorumNumbers,
        uint32 referenceBlockNumber,
        IBLSSignatureCheckerTypes.NonSignerStakesAndSignature calldata nonSignerStakesAndSignature,
        address user,
        string calldata platform,
        string calldata resource,
        string calldata value,
        uint256 threshold,
        string calldata signature,
        uint256 operatorCount
    ) public returns (bool) {
        
        // Construct the VerificationParams struct
        VerificationParams memory params = VerificationParams({
            quorumNumbers: quorumNumbers,
            referenceBlockNumber: referenceBlockNumber,
            nonSignerStakesAndSignature: nonSignerStakesAndSignature,
            targetAddress: user,
            platform: platform,
            resource: resource,
            value: value,
            threshold: threshold,
            signature: signature,
            operatorCount: operatorCount
        });
        
        try this.verify(params) returns (bool verified) {
            // Verification successful - emit event
            emit DataVerified(user, platform, resource, value, true);
            return true;
            
        } catch {
            return false;
        }
    }
} 