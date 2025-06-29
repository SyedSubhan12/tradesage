# Use Node.js LTS version
FROM node:18.19.1-slim

# Set environment variables
ENV NODE_ENV=production \
    APP_DIR=/app \
    NPM_CONFIG_LOGLEVEL=warn

# Create and set working directory owned by node user
RUN mkdir -p /app && chown -R node:node /app

# Switch to non-root user
USER node

# Set the working directory
WORKDIR /app

# Copy package files first for better caching
COPY --chown=node:node package*.json ./

# Install dependencies
RUN npm ci --only=production

# Copy startup wrapper and application files
COPY --chown=node:node devops/scripts/startup-wrapper.js ./scripts/
COPY --chown=node:node . .

# Install monitoring dependencies
RUN npm install --save winston prom-client

# Create necessary directories with correct permissions
RUN mkdir -p /app/logs /app/metrics && \
    chmod 755 /app/scripts/startup-wrapper.js

# Healthcheck
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD node -e "require('http').get('http://localhost:3000/health', (r) => r.statusCode === 200 ? process.exit(0) : process.exit(1))"

# Start the application using our wrapper
CMD ["node", "scripts/startup-wrapper.js", "index.js"] 