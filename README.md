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
# Deploy new BLS + SimpleVerificationConsumer
forge script script/Deploy.s.sol:Deploy --sig "run(address)" <REGISTRY_COORDINATOR> --rpc-url holesky --broadcast

# Deploy with existing BLS signature checker
forge script script/Deploy.s.sol:Deploy --sig "run(address,address)" <BLS_ADDRESS> <REGISTRY_COORDINATOR> --rpc-url holesky --broadcast
```

Both deployment modes:
- Deploy SimpleVerificationConsumer
- Write addresses to `deployments/latest.json`
- Verify contracts are properly linked
- Output deployment summary

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

### Deployment Modes

**1. Deploy new BLS + SimpleVerificationConsumer**
```bash
forge script script/Deploy.s.sol:Deploy --sig "run(address)" <REGISTRY_COORDINATOR> --rpc-url holesky --broadcast
```

**2. Deploy with existing BLS signature checker**
```bash
forge script script/Deploy.s.sol:Deploy --sig "run(address,address)" <BLS_ADDRESS> <REGISTRY_COORDINATOR> --rpc-url holesky --broadcast
```

Both modes require:
- `registryCoordinator`: Address of the registry coordinator contract
- `blsSignatureCheckerAddress` (mode 2 only): Address of existing BLS signature checker

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