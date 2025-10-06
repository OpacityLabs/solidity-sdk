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
# Default deployment - deploys BLS + SimpleVerificationConsumer
forge script script/Deploy.s.sol:Deploy --rpc-url holesky --broadcast

# Deploy with existing BLS signature checker
forge script script/Deploy.s.sol:Deploy --sig "runWithBLS(address)" <BLS_ADDRESS> --rpc-url holesky --broadcast

# Full deployment including StorageQueryConsumer
forge script script/Deploy.s.sol:Deploy --sig "runFull(address)" 0x0 --rpc-url holesky --broadcast
```

All deployments:
- Write addresses to `deployments/latest.json`
- Use `REGISTRY_COORDINATOR` env var or default Holesky address
- Verify contracts are properly linked
- Output deployment summary

### Example Deployment Output

```
========================================
       DEPLOYMENT SUMMARY
========================================
Registry Coordinator:         0x3e43AA225b5cB026C5E8a53f62572b10D526a50B
BLS Signature Checker:        0x2a55810daCeF9197d51B94A21c67d88b8d99b379
Simple Verification Consumer: 0x1b4468ce3306f886d4a741950acE0238e4204cdb
========================================

=== Verification Check ===
Simple Consumer BLS Address:  0x2a55810daCeF9197d51B94A21c67d88b8d99b379
Simple Consumer properly linked:  true
All contracts deployed and linked successfully!

Deployment addresses written to deployments/latest.json
```

### Deployment JSON Output

After deployment, addresses are saved to `deployments/latest.json`:

```json
{
  "blsSignatureChecker": "0x2a55810daCeF9197d51B94A21c67d88b8d99b379",
  "blsSignatureCheckerStatus": "deployed",
  "registryCoordinator": "0x3e43AA225b5cB026C5E8a53f62572b10D526a50B",
  "simpleVerificationConsumer": "0x1b4468ce3306f886d4a741950acE0238e4204cdb",
  "timestamp": 1234567890
}
```

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

## Deployment Configuration

### Registry Coordinator

The deployment script supports configurable registry coordinator addresses:

- **Default Holesky Address**: `0x3e43AA225b5cB026C5E8a53f62572b10D526a50B`
- **Custom Address**: Set `REGISTRY_COORDINATOR` in `.env` file

```bash
# In .env file
REGISTRY_COORDINATOR=0x...
```

### Deployment Options

**1. Default Deployment** - Deploys BLS + SimpleVerificationConsumer
```bash
forge script script/Deploy.s.sol:Deploy --rpc-url holesky --broadcast
```

**2. Use Existing BLS** - Only deploys SimpleVerificationConsumer
```bash
forge script script/Deploy.s.sol:Deploy --sig "runWithBLS(address)" <BLS_ADDRESS> --rpc-url holesky --broadcast
```

**3. Full Deployment** - Includes StorageQueryConsumer
```bash
forge script script/Deploy.s.sol:Deploy --sig "runFull(address)" 0x0 --rpc-url holesky --broadcast
# Pass 0x0 to use env/default registry coordinator, or pass specific address
```

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