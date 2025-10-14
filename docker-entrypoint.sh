#!/bin/bash
set -e

# Check write permissions to deployment directory
echo "Checking deployment directory permissions..."
echo "Current user: $(whoami) (UID: $(id -u), GID: $(id -g))"
echo "Deployment directory: /app/deployments"
ls -ld /app/deployments

if [ ! -w /app/deployments ]; then
    echo "ERROR: /app/deployments is not writable by current user"
    echo "Please ensure the directory has proper permissions or use a volume mount"
    exit 1
fi

echo "✓ Deployment directory is writable"
echo ""

# Validate required environment variables
if [ -z "$PRIVATE_KEY" ]; then
    echo "Error: PRIVATE_KEY environment variable is required"
    exit 1
fi

if [ -z "$BLS_SIGNATURE_CHECKER_ADDRESS" ]; then
    echo "Error: BLS_SIGNATURE_CHECKER_ADDRESS environment variable is required"
    exit 1
fi

if [ -z "$REGISTRY_COORDINATOR_ADDRESS" ]; then
    echo "Error: REGISTRY_COORDINATOR_ADDRESS environment variable is required"
    exit 1
fi

# Set default RPC URL if not provided
RPC_URL="${RPC_URL:-https://ethereum-holesky.publicnode.com}"

echo "=========================================="
echo "OpacitySDK Docker Deployment"
echo "=========================================="
echo "RPC URL: $RPC_URL"
echo "BLS Signature Checker: $BLS_SIGNATURE_CHECKER_ADDRESS"
echo "Registry Coordinator: $REGISTRY_COORDINATOR_ADDRESS"
echo "=========================================="

# Run the deployment
forge script script/Deploy.s.sol:Deploy \
    --sig "run(address,address)" \
    "$BLS_SIGNATURE_CHECKER_ADDRESS" \
    "$REGISTRY_COORDINATOR_ADDRESS" \
    --rpc-url "$RPC_URL" \
    --private-key "$PRIVATE_KEY" \
    --broadcast

echo ""
echo "=========================================="
echo "Deployment Complete!"
echo "=========================================="
echo "Deployment JSON written to: /app/deployments/latest.json"
echo ""
echo "To access the deployment file, ensure you mounted a volume to /app/deployments"
