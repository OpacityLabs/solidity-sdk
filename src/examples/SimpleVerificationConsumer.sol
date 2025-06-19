// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "../OpacitySDK.sol";
import "@eigenlayer-middleware/interfaces/IBLSSignatureChecker.sol";

contract SimpleVerificationConsumer is OpacitySDK {
    
    event DataVerified(address user, string platform, string resource, string value, bool isValid);

    constructor() OpacitySDK() {}

    function verifyUserData(
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
        
        try this.verify(
            quorumNumbers,
            referenceBlockNumber,
            nonSignerStakesAndSignature,
            user,
            platform,
            resource,
            value,
            threshold,
            signature,
            operatorCount
        ) returns (
            IBLSSignatureCheckerTypes.QuorumStakeTotals memory stakeTotals,
            bytes32 signatoryRecordHash
        ) {
            // Verification successful - emit event
            emit DataVerified(user, platform, resource, value, true);
            return true;
            
        } catch {
            return false;
        }
    }
} 