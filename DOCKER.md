# Docker Deployment Guide for OpacitySDK

This guide explains how to build and run the OpacitySDK deployment using Docker.

## Using Pre-built Images from GitHub Container Registry (GHCR)

The easiest way to use the OpacitySDK Docker image is to pull it directly from GHCR:

```bash
# Pull the latest version
docker pull ghcr.io/opacitylabs/solidity-sdk:latest

# Or pull a specific version tag
docker pull ghcr.io/opacitylabs/solidity-sdk:v1.0.0
```

Then run it:

```bash
docker run \
  -e PRIVATE_KEY="your_private_key_here" \
  -e BLS_SIGNATURE_CHECKER_ADDRESS="0x2a55810daCeF9197d51B94A21c67d88b8d99b379" \
  -e REGISTRY_COORDINATOR_ADDRESS="0x3e43AA225b5cB026C5E8a53f62572b10D526a50B" \
  -v $(pwd)/deployments:/app/deployments \
  ghcr.io/opacitylabs/solidity-sdk:latest
```

### Available Tags

- `latest` - Latest build from the main branch
- `main` - Latest build from the main branch
- `v*` - Specific version tags (e.g., `v1.0.0`, `v1.2.3`)
- `sha-<commit>` - Specific commit builds (e.g., `sha-abc123d`)
- `pr-<number>` - Pull request builds (built but not pushed to registry)

## Building the Docker Image Locally

If you prefer to build the image yourself:

```bash
docker build -t opacity-sdk-deploy .
```

## Required Environment Variables

The following environment variables **must** be provided when running the container:

| Variable | Description | Example |
|----------|-------------|---------|
| `PRIVATE_KEY` | Private key for the deployer account (without 0x prefix) | `ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80` |
| `BLS_SIGNATURE_CHECKER_ADDRESS` | Address of the deployed BLS signature checker contract | `0x2a55810daCeF9197d51B94A21c67d88b8d99b379` |
| `REGISTRY_COORDINATOR_ADDRESS` | Address of the registry coordinator contract | `0x3e43AA225b5cB026C5E8a53f62572b10D526a50B` |

### Optional Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `RPC_URL` | Ethereum RPC endpoint URL | `https://ethereum-holesky.publicnode.com` |

## Running the Container

### Basic Usage

```bash
docker run \
  -e PRIVATE_KEY="your_private_key_here" \
  -e BLS_SIGNATURE_CHECKER_ADDRESS="0x2a55810daCeF9197d51B94A21c67d88b8d99b379" \
  -e REGISTRY_COORDINATOR_ADDRESS="0x3e43AA225b5cB026C5E8a53f62572b10D526a50B" \
  -v $(pwd)/deployments:/app/deployments \
  opacity-sdk-deploy
```

### Using a Custom RPC URL

```bash
docker run \
  -e PRIVATE_KEY="your_private_key_here" \
  -e BLS_SIGNATURE_CHECKER_ADDRESS="0x2a55810daCeF9197d51B94A21c67d88b8d99b379" \
  -e REGISTRY_COORDINATOR_ADDRESS="0x3e43AA225b5cB026C5E8a53f62572b10D526a50B" \
  -e RPC_URL="https://your-custom-rpc-endpoint.com" \
  -v $(pwd)/deployments:/app/deployments \
  opacity-sdk-deploy
```

### Using Environment File

Create a `.env` file:

```env
PRIVATE_KEY=your_private_key_here
BLS_SIGNATURE_CHECKER_ADDRESS=0x2a55810daCeF9197d51B94A21c67d88b8d99b379
REGISTRY_COORDINATOR_ADDRESS=0x3e43AA225b5cB026C5E8a53f62572b10D526a50B
RPC_URL=https://ethereum-holesky.publicnode.com
```

Run with the environment file:

```bash
docker run --env-file .env \
  -v $(pwd)/deployments:/app/deployments \
  opacity-sdk-deploy
```

## Volume Mounts

### Required Volume Mount

To access the deployment JSON file after deployment, you **must** mount a volume to `/app/deployments`:

```bash
-v $(pwd)/deployments:/app/deployments
```

This will create a `deployments` directory in your current working directory and the deployment JSON will be written to `deployments/latest.json`.

### Deployment JSON Output

After successful deployment, the file `/app/deployments/latest.json` will contain:

```json
{
  "blsSignatureChecker": "0x2a55810daCeF9197d51B94A21c67d88b8d99b379",
  "registryCoordinator": "0x3e43AA225b5cB026C5E8a53f62572b10D526a50B",
  "simpleVerificationConsumer": "0x1b4468ce3306f886d4a741950acE0238e4204cdb",
  "timestamp": 1234567890
}
```

## Complete Example with Docker Compose

Create a `docker-compose.yml` file:

```yaml
version: '3.8'

services:
  opacity-sdk-deploy:
    image: ghcr.io/opacitylabs/solidity-sdk:latest
    # Or build locally:
    # build: .
    environment:
      - PRIVATE_KEY=${PRIVATE_KEY}
      - BLS_SIGNATURE_CHECKER_ADDRESS=${BLS_SIGNATURE_CHECKER_ADDRESS}
      - REGISTRY_COORDINATOR_ADDRESS=${REGISTRY_COORDINATOR_ADDRESS}
      - RPC_URL=${RPC_URL:-https://ethereum-holesky.publicnode.com}
    volumes:
      - ./deployments:/app/deployments
```

Run with:

```bash
docker-compose up
```

## Troubleshooting

### Missing Environment Variables

If you see errors like:
```
Error: PRIVATE_KEY environment variable is required
```

Ensure all required environment variables are set.

### Permission Issues

If the deployment file cannot be written, ensure the mounted volume has write permissions:

```bash
mkdir -p deployments
chmod 777 deployments
```

### RPC Connection Issues

If deployment fails with RPC errors, verify:
1. Your RPC URL is correct and accessible
2. The RPC endpoint supports the network you're deploying to
3. You have sufficient funds in your deployer account

## Security Notes

⚠️ **Never commit your `.env` file containing the private key to version control!**

Add `.env` to your `.gitignore`:

```bash
echo ".env" >> .gitignore
```

## CI/CD and Automated Builds

The Docker image is automatically built and published to GitHub Container Registry (GHCR) via GitHub Actions:

- **On pushes to `main`**: Builds and tags as `latest` and `main`
- **On version tags** (e.g., `v1.0.0`): Builds and tags with semantic versions
- **On pull requests**: Builds for testing (not published)

### Workflow Details

The CI/CD pipeline (`.github/workflows/docker-publish.yml`) automatically:
- Builds multi-platform images (linux/amd64, linux/arm64)
- Uses build caching for faster builds
- Publishes to `ghcr.io/opacitylabs/solidity-sdk`
- Tags images appropriately based on the trigger

### Creating a Release

To create a new versioned release:

```bash
git tag v1.0.0
git push origin v1.0.0
```

This will automatically build and publish images tagged as:
- `ghcr.io/opacitylabs/solidity-sdk:v1.0.0`
- `ghcr.io/opacitylabs/solidity-sdk:1.0`
- `ghcr.io/opacitylabs/solidity-sdk:1`
