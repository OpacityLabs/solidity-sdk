# OpacitySDK for Solidity
## Quick Start

### 1. Clone and Setup

```bash
git clone <repository-url>
cd opacity-solidity-sdk
forge install
```

### 2. Environment Setup

```bash
# Copy the example environment file
cp .env.example .env

# Edit .env and add your private key
PRIVATE_KEY=your_private_key_here
```

### 3. Deploy on Holesky Testnet

```bash
# Deploy all contracts (BLS signature checker + examples)
forge script script/DeployOpacityExamples.s.sol:DeployOpacityExamples --rpc-url holesky --broadcast
```

This command will:
1. Deploy the BLS signature checker contract
2. Deploy the SimpleVerificationConsumer example
3. Deploy the OpacityVerificationExample contract
4. Verify all contracts are properly linked
5. Output all deployed addresses

### Example Deployment Output

```
========================================
       DEPLOYMENT SUMMARY
========================================
Registry Coordinator:         0x3e43AA225b5cB026C5E8a53f62572b10D526a50B
BLS Signature Checker:        0x3031d2c33FB9d7e85bC03C1011D9b4aA571576D2
Simple Verification Consumer: 0x70B13fB637d52dB8a8Fd27580AE75045AD70b402
Opacity Verification Example: 0x337c51432123b3Fe5CbE90e8681461B98B381B22
========================================

=== Verification Checks ===
Simple Consumer BLS Address:  0x3031d2c33FB9d7e85bC03C1011D9b4aA571576D2
Storage Consumer BLS Address: 0x3031d2c33FB9d7e85bC03C1011D9b4aA571576D2
Simple Consumer properly linked:  true
Storage Consumer properly linked: true
All contracts deployed and linked successfully!
```

## Usage Examples

### Basic Verification (SimpleVerificationConsumer)

```solidity
// Create verification parameters
OpacitySDK.VerificationParams memory params = OpacitySDK.VerificationParams({
    quorumNumbers: quorumNumbers,
    referenceBlockNumber: referenceBlockNumber,
    nonSignerStakesAndSignature: nonSignerStakesAndSignature,
    targetAddress: userAddress,
    platform: "twitter",
    resource: "followers",
    value: "10000",
    threshold: 1000,
    signature: "signature_data",
    operatorCount: 5
});

// Verify the data
bool success = simpleConsumer.verifyUserData(params);
```

### Advanced Verification with Storage (OpacityVerificationExample)

```solidity
// Verify and store the result
(bool success, string memory verifiedValue) = opacityExample.verifyPrivateData(params);

if (success) {
    // Get stored verification details
    (bool isValid, string memory value, uint256 timestamp, bytes32 hash) = 
        opacityExample.getUserVerification(userAddress);
}
```

## Development

### Build

```bash
forge build
```

### Test

```bash
forge test
```

### Format Code

```bash
forge fmt
```

### Gas Snapshots

```bash
forge snapshot
```

## Contract Architecture

### OpacitySDK (Base Contract)
- **VerificationParams struct**: Wraps all verification parameters
- **verify()**: Main verification function returning boolean
- **Configurable thresholds**: Quorum and block staleness settings

### Example Contracts
- **SimpleVerificationConsumer**: Demonstrates basic verification with events
- **OpacityVerificationExample**: Shows advanced usage with storage and retrieval functions

## Dependencies

- **EigenLayer Middleware**: BLS signature checking and registry coordination
- **Foundry**: Development and testing framework
- **OpenZeppelin**: Standard library contracts (via EigenLayer)

## Important 
Make sure not to change the registry coordinator address in the deployment scripts
---

## Foundry Documentation

For more information about Foundry, visit: https://book.getfoundry.sh/

### Additional Foundry Commands

```bash
# Local development node
anvil

# Cast commands for chain interaction
cast <subcommand>

# Help
forge --help
anvil --help
cast --help
```