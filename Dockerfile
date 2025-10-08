# Use Foundry base image
FROM ghcr.io/foundry-rs/foundry:latest

# Set working directory
WORKDIR /app

# Copy the entire codebase
COPY . .

# Create deployments directory if it doesn't exist
RUN mkdir -p /app/deployments

# Set entrypoint script with execute permissions
COPY --chmod=755 docker-entrypoint.sh /docker-entrypoint.sh

ENTRYPOINT ["/docker-entrypoint.sh"]
