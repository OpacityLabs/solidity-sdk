#!/bin/bash
# Test script to verify container can write to deployment path

set -e

echo "Building Docker image..."
docker build -t opacitysdk-test .

echo ""
echo "Testing write permissions in container..."
echo "Running container with dummy environment variables..."

# Create a test deployment directory on host
mkdir -p ./test-deployments

# Run container with a simple write test
docker run --rm \
  -v "$(pwd)/test-deployments:/app/deployments" \
  opacitysdk-test \
  bash -c "
    echo 'Testing write permissions...'
    echo 'Current user:' \$(whoami)
    echo 'User ID:' \$(id -u)
    echo 'Group ID:' \$(id -g)
    echo ''
    echo 'Deployment directory permissions:'
    ls -la /app/ | grep deployments
    echo ''
    echo 'Attempting to write test file...'
    echo '{\"test\": \"success\"}' > /app/deployments/test.json
    echo 'Write successful!'
    cat /app/deployments/test.json
    echo ''
    echo 'File permissions:'
    ls -la /app/deployments/test.json
  "

echo ""
echo "=========================================="
echo "Write test completed successfully!"
echo "=========================================="
echo "Contents of test-deployments:"
ls -la ./test-deployments/

# Cleanup
rm -rf ./test-deployments
echo ""
echo "Cleanup complete. Container can write to deployment path!"
