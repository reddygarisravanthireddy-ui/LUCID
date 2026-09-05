# Use official Node.js 20 LTS slim image
FROM node:20-slim

# Set working directory
WORKDIR /app

# Copy package manifests for optimal layer caching
COPY package*.json ./

# Install production dependencies
RUN npm ci --only=production

# Copy application source files
COPY . .

# Set environment defaults for container execution
ENV NODE_ENV=production
ENV PORT=8080

# Cloud Run defaults to container port 8080
EXPOSE 8080

# Start server
CMD ["node", "server.js"]
