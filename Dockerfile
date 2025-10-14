# Use Foundry base image
FROM ghcr.io/foundry-rs/foundry:latest

# Set working directory
WORKDIR /app

# Copy the entire codebase
COPY --chown=foundry:foundry . .

# Ensure deployments directory exists and has proper permissions
RUN mkdir -p /app/deployments && \
    chmod 755 /app/deployments

# Set entrypoint script with execute permissions
COPY --chmod=755 docker-entrypoint.sh /docker-entrypoint.sh

ENTRYPOINT ["/docker-entrypoint.sh"]
