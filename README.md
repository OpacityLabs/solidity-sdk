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
3. Deploy the StorageQueryConsumer contract
4. Verify all contracts are properly linked
5. Output all deployed addresses

### Example Deployment Output 

```
========================================
         DEPLOYMENT SUMMARY
  ========================================
  Registry Coordinator:         0x3e43AA225b5cB026C5E8a53f62572b10D526a50B
  BLS Signature Checker:        0x2a55810daCeF9197d51B94A21c67d88b8d99b379
  Simple Verification Consumer: 0x1b4468ce3306f886d4a741950acE0238e4204cdb
  Storage Query Consumer:       0x5aEA3238EfEeacaB01aEf8209811FE1d2E1F1f19
  ========================================
  
=== Verification Checks ===
  Simple Consumer BLS Address:  0xD00873BbA73E4aecb5709d31539081E0a45a67bC
  Storage Consumer BLS Address: 0xD00873BbA73E4aecb5709d31539081E0a45a67bC
  Simple Consumer properly linked:  true
  Storage Consumer properly linked: true
  All contracts deployed and linked successfully!
```

### Contract Links on Holeskyscan

- [BLS Signature Checker](https://holesky.etherscan.io/address/0x2a55810daCeF9197d51B94A21c67d88b8d99b379)
- [Simple Verification Consumer](https://holesky.etherscan.io/address/0x1b4468ce3306f886d4a741950acE0238e4204cdb)
- [Storage Query Consumer](https://holesky.etherscan.io/address/0x5aEA3238EfEeacaB01aEf8209811FE1d2E1F1f19)

## Usage Examples

### Basic Verification (SimpleVerificationConsumer)

```solidity
// Create verification parameters
OpacitySDK.VerificationParams memory params = OpacitySDK.VerificationParams({
    quorumNumbers: quorumNumbers,
    referenceBlockNumber: referenceBlockNumber,
    nonSignerStakesAndSignature: nonSignerStakesAndSignature,
    userAddress: userAddress,
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

### Advanced Verification with Storage (StorageQueryConsumer)

```solidity
// Verify and store the result
(bool success, string memory verifiedValue) = storageQueryConsumer.verifyPrivateData(params);

if (success) {
    // Get stored verification details
    (bool isValid, string memory value, uint256 timestamp, bytes32 hash) = 
        storageQueryConsumer.getUserVerification(userAddress);
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
- no tests currently

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
- **StorageQueryConsumer**: Shows advanced usage with storage and retrieval functions

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