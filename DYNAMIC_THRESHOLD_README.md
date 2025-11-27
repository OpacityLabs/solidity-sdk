# Dynamic Threshold Security System

## Overview

The Dynamic Threshold Security System is an enhancement to the OpacitySDK that automatically adjusts verification thresholds based on risk assessment. Instead of using a static threshold for all verifications, the system evaluates multiple risk factors to determine the appropriate security level for each verification request.

## Features

### 🎯 Risk-Based Security
- Automatically adjusts required consensus percentage (10% to 95%) based on risk
- Evaluates transaction value, platform trust, resource criticality, and user history
- Provides adaptive security that scales with actual risk

### 📊 Risk Assessment Factors

1. **Transaction Value** (0-40 risk points)
   - Low value: < 100 ETH → 10 points
   - Medium value: 100-1000 ETH → 20 points  
   - High value: 1000-10000 ETH → 30 points
   - Very high value: > 10000 ETH → 40 points

2. **Platform Trust** (0-30 risk points)
   - Trusted: 0 points
   - Verified: 10 points
   - Basic: 20 points
   - Untrusted: 30 points

3. **Resource Criticality** (0-30 risk points)
   - Trivial (e.g., social metrics): 0 points
   - Standard (e.g., preferences): 10 points
   - Sensitive (e.g., personal data): 20 points
   - Critical (e.g., financial data): 30 points

4. **User History** (reduces risk)
   - > 100 verifications: -10 points
   - > 50 verifications: -5 points

### 🔒 Risk Levels & Thresholds

| Risk Level | Risk Score | Required Threshold |
|------------|------------|-------------------|
| MINIMAL    | 0-20       | 10%              |
| LOW        | 21-40      | 30%              |
| MEDIUM     | 41-60      | 50%              |
| HIGH       | 61-80      | 70%              |
| CRITICAL   | 81-100     | 90%              |

## Architecture

```
┌─────────────────────────────────────┐
│         DynamicThresholdSDK         │
│  ┌─────────────────────────────┐    │
│  │    Risk Assessment Engine   │    │
│  │  ┌───────────────────────┐  │    │
│  │  │  Calculate Risk Score  │  │    │
│  │  │  - Value Assessment    │  │    │
│  │  │  - Platform Trust      │  │    │
│  │  │  │  - Resource Critical│  │    │
│  │  │  - User History        │  │    │
│  │  └───────────────────────┘  │    │
│  │           ↓                  │    │
│  │  ┌───────────────────────┐  │    │
│  │  │  Map to Risk Level    │  │    │
│  │  └───────────────────────┘  │    │
│  │           ↓                  │    │
│  │  ┌───────────────────────┐  │    │
│  │  │  Apply Multipliers    │  │    │
│  │  └───────────────────────┘  │    │
│  └─────────────────────────────┘    │
│                ↓                     │
│  ┌─────────────────────────────┐    │
│  │   BLS Signature Verification│    │
│  │   with Dynamic Threshold    │    │
│  └─────────────────────────────┘    │
└─────────────────────────────────────┘
```

## Usage

### 1. Deploy the Dynamic Verification Consumer

```solidity
import "./DynamicVerificationConsumer.sol";

// Deploy with BLS signature checker address
DynamicVerificationConsumer consumer = new DynamicVerificationConsumer(
    blsSignatureCheckerAddress
);
```

### 2. Configure Risk Settings

```solidity
// Set platform trust levels
consumer.setPlatformTrust("twitter", RiskAssessment.PlatformTrust.VERIFIED);
consumer.setPlatformTrust("unknown_platform", RiskAssessment.PlatformTrust.UNTRUSTED);

// Set resource criticality
consumer.setResourceCriticality("balance", RiskAssessment.ResourceCriticality.CRITICAL);
consumer.setResourceCriticality("followers", RiskAssessment.ResourceCriticality.TRIVIAL);

// Update risk configuration
RiskAssessment.RiskConfig memory config = RiskAssessment.RiskConfig({
    lowValueThreshold: 100 ether,
    mediumValueThreshold: 1000 ether,
    highValueThreshold: 10000 ether,
    platformMultiplier: 100,  // 100% = no change
    resourceMultiplier: 100,  // 100% = no change
    emergencyMode: false
});
consumer.updateRiskConfig(config);
```

### 3. Perform Verification with Dynamic Threshold

```solidity
// Prepare verification parameters
DynamicThresholdSDK.VerificationParams memory params = DynamicThresholdSDK.VerificationParams({
    quorumNumbers: hex"00",
    referenceBlockNumber: blockNumber,
    nonSignerStakesAndSignature: nonSignerData,
    userAddress: userAddress,
    platform: "twitter",
    resource: "balance",
    value: "1000",
    operatorThreshold: 5000 ether,  // High value transaction
    signature: "signature_data"
});

// Verify with dynamic threshold
(bool verified, RiskAssessment.RiskLevel riskLevel, uint8 threshold) = 
    consumer.verifyWithDynamicThreshold(params);

// Result: HIGH risk level, 70% threshold required
```

### 4. Query Risk Assessment

```solidity
// Get recommended threshold before verification
(RiskAssessment.RiskLevel level, uint8 threshold) = consumer.getRecommendedThreshold(
    "ethereum",      // platform
    "transaction",   // resource
    10000 ether     // value
);

// Analyze risk and emit event
consumer.analyzeRisk("discord", "identity", 100 ether);
```

## Deployment

### Using Forge Script

```bash
# Set your private key
export PRIVATE_KEY=your_private_key_here

# Optional: Use existing BLS checker
export EXISTING_BLS_CHECKER=0x... # Optional

# Deploy on Holesky testnet
forge script script/DeployDynamicThreshold.s.sol:DeployDynamicThreshold --rpc-url holesky --broadcast
```

### Deployment Output Example

```
========================================
    DYNAMIC THRESHOLD DEPLOYMENT SUMMARY
========================================
Registry Coordinator:            0x3e43AA225b5cB026C5E8a53f62572b10D526a50B
BLS Signature Checker:           0x2a55810daCeF9197d51B94A21c67d88b8d99b379
Dynamic Verification Consumer:   0x7b4468ce3306f886d4a741950acE0238e4204cdb
========================================

=== Risk Configuration ===
Low Value Threshold:             100 ETH
Medium Value Threshold:          1000 ETH
High Value Threshold:            10000 ETH
Platform Multiplier:             100%
Resource Multiplier:             100%
Emergency Mode:                  false

=== Example Risk Thresholds ===
MINIMAL Risk (e.g., social metrics):  10%
LOW Risk (e.g., preferences):         30%
MEDIUM Risk (e.g., user data):        50%
HIGH Risk (e.g., sensitive data):     70%
CRITICAL Risk (e.g., financial):      90%
```

## Contract Addresses (Holesky Testnet)

- **Registry Coordinator**: `0x3e43AA225b5cB026C5E8a53f62572b10D526a50B`
- **BLS Signature Checker**: [To be deployed]
- **Dynamic Verification Consumer**: [To be deployed]

## Security Considerations

1. **Threshold Bounds**: Thresholds are capped between 5% and 95% to prevent extremes
2. **Emergency Mode**: Can halt all verifications in case of detected threats
3. **Access Control**: Only contract owner can modify risk configurations
4. **Gradual Trust**: New platforms start as untrusted and build reputation over time
5. **Multipliers**: Platform and resource multipliers are capped at 200% to prevent manipulation

## Gas Optimization

- Risk calculation adds approximately 5,000 gas to verification
- Caching user history reduces repeated lookups
- Batch functions available for updating multiple configurations

## Benefits

✅ **Resource Efficiency**: Low-risk operations require fewer operators  
✅ **Enhanced Security**: High-value operations get stronger consensus  
✅ **Flexible Configuration**: Admins can tune risk parameters  
✅ **Better UX**: Faster verification for routine operations  
✅ **Economic Optimization**: Better allocation of operator resources  
✅ **Incident Response**: Can quickly adjust thresholds in response to threats  

## Testing

Run the test suite:

```bash
forge test --match-path test/DynamicThreshold.t.sol -vv
```

Key test cases:
- Risk level calculation for various scenarios
- Threshold enforcement and rejection
- User history impact on risk scoring
- Emergency mode functionality
- Configuration updates and batch operations

## Future Enhancements

- [ ] Machine learning for anomaly detection
- [ ] Time-based risk adjustments
- [ ] Geographic risk factors
- [ ] Cross-platform reputation sharing
- [ ] Automated threshold adjustment based on network conditions

## License

AGPL-3.0-only