# Use Foundry base image
FROM ghcr.io/foundry-rs/foundry:latest

# Set working directory
WORKDIR /app

# Copy the entire codebase
COPY . .

# Create deployments directory if it doesn't exist
RUN mkdir -p /app/deployments

# Set entrypoint script
COPY docker-entrypoint.sh /docker-entrypoint.sh
RUN chmod +x /docker-entrypoint.sh

ENTRYPOINT ["/docker-entrypoint.sh"]
