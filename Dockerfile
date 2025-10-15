# Use Foundry base image
FROM ghcr.io/foundry-rs/foundry:latest

# Install jq as root
USER root
RUN apt-get update && apt-get install -y jq && rm -rf /var/lib/apt/lists/*
USER foundry

# Set working directory
WORKDIR /app

# Copy the entire codebase
COPY --chown=foundry:foundry . .

# Ensure deployments directory exists with proper permissions and ownership
RUN mkdir -p /app/deployments && \
    chown -R foundry:foundry /app/deployments && \
    chmod -R 755 /app/deployments

# Set entrypoint script with execute permissions
COPY --chmod=755 docker-entrypoint.sh /docker-entrypoint.sh

ENTRYPOINT ["/docker-entrypoint.sh"]
