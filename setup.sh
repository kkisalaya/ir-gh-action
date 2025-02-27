#!/bin/bash
# PSE GitHub Action - Setup Script
# This script configures the build environment to route HTTPS traffic through the PSE proxy

# Enable strict error handling
set -e

# Enable debug mode if requested
if [ "$DEBUG" = "true" ]; then
  set -x
fi

# Log with timestamp
log() {
  echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1"
}

# Error handler
error_handler() {
  log "ERROR: An error occurred on line $1"
  exit 1
}

# Set up error trap
trap 'error_handler $LINENO' ERR

# Validate required environment variables
validate_env_vars() {
  local required_vars=("API_URL" "APP_TOKEN" "PORTAL_URL" "SCAN_ID" "GITHUB_TOKEN")
  
  for var in "${required_vars[@]}"; do
    if [ -z "${!var}" ]; then
      log "ERROR: Required environment variable $var is not set"
      exit 1
    fi
  done
  
  log "Environment validation successful"
}

# Function to get ECR credentials
get_ecr_credentials() {
  log "Obtaining ECR credentials from $API_URL"
  
  # Fetch ECR details
  ECR_RESPONSE=$(curl -s -X GET "$API_URL/utilityapi/v1/registry?api_key=$APP_TOKEN")
  
  # Decode base64 token
  DECODED_TOKEN=$(echo "$ECR_RESPONSE" | grep -o '"data":"[^"]*' | cut -d'"' -f4 | base64 -d)
  
  # Extract ECR credentials
  ECR_USERNAME=$(echo "$DECODED_TOKEN" | grep -o '"username":"[^"]*' | cut -d'"' -f4)
  ECR_TOKEN=$(echo "$DECODED_TOKEN" | grep -o '"password":"[^"]*' | cut -d'"' -f4)
  ECR_REGION=$(echo "$DECODED_TOKEN" | grep -o '"region":"[^"]*' | cut -d'"' -f4)
  ECR_REGISTRY_ID=$(echo "$DECODED_TOKEN" | grep -o '"registry_id":"[^"]*' | cut -d'"' -f4)
  
  if [ -z "$ECR_USERNAME" ] || [ -z "$ECR_TOKEN" ]; then
    log "ERROR: Failed to obtain ECR credentials"
    exit 1
  fi
  
  log "ECR credentials obtained successfully"
  
  # Export variables for later use
  export ECR_USERNAME="$ECR_USERNAME"
  export ECR_TOKEN="$ECR_TOKEN"
  export ECR_REGION="$ECR_REGION"
  export ECR_REGISTRY_ID="$ECR_REGISTRY_ID"
}

# Function to set up dependencies
setup_dependencies() {
  log "Installing dependencies"
  
  # Detect Linux distribution
  if command -v apk > /dev/null 2>&1; then
    # Alpine Linux
    log "Detected Alpine Linux"
    apk add --no-cache iptables ca-certificates git curl docker
  else
    # Debian/Ubuntu
    log "Detected Debian/Ubuntu"
    apt-get update
    apt-get install -y iptables ca-certificates git curl
  fi
  
  log "Dependencies installed successfully"
}

# Function to pull and start PSE container
pull_and_start_pse_container() {
  log "Pulling and starting PSE container"
  
  # Login to ECR with retry mechanism
  MAX_RETRIES=3
  RETRY_DELAY=5
  ATTEMPT=1
  
  while [ $ATTEMPT -le $MAX_RETRIES ]; do
    log "Logging in to ECR, attempt $ATTEMPT of $MAX_RETRIES"
    if echo "$ECR_TOKEN" | docker login --username "$ECR_USERNAME" --password-stdin "$ECR_REGISTRY_ID.dkr.ecr.$ECR_REGION.amazonaws.com"; then
      log "ECR login successful"
      break
    else
      log "Failed to login to ECR, retrying in $RETRY_DELAY seconds..."
      sleep $RETRY_DELAY
      RETRY_DELAY=$((RETRY_DELAY * 2))
      ATTEMPT=$((ATTEMPT + 1))
    fi
  done
  
  if [ $ATTEMPT -gt $MAX_RETRIES ]; then
    log "ERROR: Failed to login to ECR after $MAX_RETRIES attempts"
    exit 1
  fi
  
  # Pull PSE container with retry mechanism
  ATTEMPT=1
  
  while [ $ATTEMPT -le $MAX_RETRIES ]; do
    log "Pulling PSE container, attempt $ATTEMPT of $MAX_RETRIES"
    if docker pull "$ECR_REGISTRY_ID.dkr.ecr.$ECR_REGION.amazonaws.com/pse:latest"; then
      log "PSE container pulled successfully"
      break
    else
      log "Failed to pull PSE container, retrying in $RETRY_DELAY seconds..."
      sleep $RETRY_DELAY
      RETRY_DELAY=$((RETRY_DELAY * 2))
      ATTEMPT=$((ATTEMPT + 1))
    fi
  done
  
  if [ $ATTEMPT -gt $MAX_RETRIES ]; then
    log "ERROR: Failed to pull PSE container after $MAX_RETRIES attempts"
    exit 1
  fi
  
  # Start PSE container with required environment variables
  log "Starting PSE container"
  docker run -d --name pse \
    -e PSE_DEBUG_FLAG="--alsologtostderr" \
    -e POLICY_LOG="t" \
    -e INVISIRISK_JWT_TOKEN="$APP_TOKEN" \
    -e INVISIRISK_PORTAL="$PORTAL_URL" \
    -e GITHUB_TOKEN="$GITHUB_TOKEN" \
    "$ECR_REGISTRY_ID.dkr.ecr.$ECR_REGION.amazonaws.com/pse:latest"
  
  # Get container IP for iptables configuration
  PSE_IP=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' pse)
  export PSE_IP="$PSE_IP"
  
  log "PSE container started with IP: $PSE_IP"
}

# Function to set up iptables rules
setup_iptables() {
  log "Setting up iptables rules"
  
  # Configure iptables to redirect HTTPS traffic
  iptables -t nat -N pse
  iptables -t nat -A OUTPUT -j pse
  
  # Redirect HTTPS traffic to PSE
  iptables -t nat -A pse -p tcp -m tcp --dport 443 -j DNAT --to-destination ${PSE_IP}:12345
  
  log "iptables rules configured successfully"
}

# Function to set up CA certificates
setup_ca_certificates() {
  log "Setting up CA certificates"
  
  # Fetch CA certificate from PSE with retries
  MAX_RETRIES=5
  RETRY_DELAY=3
  ATTEMPT=1
  
  while [ $ATTEMPT -le $MAX_RETRIES ]; do
    log "Fetching CA certificate, attempt $ATTEMPT of $MAX_RETRIES"
    if curl -k -s -o /etc/ssl/certs/pse.pem https://pse.invisirisk.com/ca; then
      log "CA certificate successfully retrieved"
      break
    else
      log "Failed to retrieve CA certificate, retrying in $RETRY_DELAY seconds..."
      sleep $RETRY_DELAY
      RETRY_DELAY=$((RETRY_DELAY * 2))
      ATTEMPT=$((ATTEMPT + 1))
    fi
  done
  
  if [ $ATTEMPT -gt $MAX_RETRIES ]; then
    log "ERROR: Failed to retrieve CA certificate after $MAX_RETRIES attempts"
    exit 1
  fi
  
  # Update CA certificates
  update-ca-certificates
  
  # Configure Git to use our CA
  git config --global http.sslCAInfo /etc/ssl/certs/pse.pem
  
  # Set environment variables for other tools
  export NODE_EXTRA_CA_CERTS=/etc/ssl/certs/pse.pem
  export REQUESTS_CA_BUNDLE=/etc/ssl/certs/pse.pem
  
  # Add to GITHUB_ENV to persist these variables
  echo "NODE_EXTRA_CA_CERTS=/etc/ssl/certs/pse.pem" >> $GITHUB_ENV
  echo "REQUESTS_CA_BUNDLE=/etc/ssl/certs/pse.pem" >> $GITHUB_ENV
  
  log "CA certificates configured successfully"
}

# Function to signal build start
signal_build_start() {
  log "Signaling build start"
  
  # Build URL parameters
  BASE_URL="${GITHUB_SERVER_URL}/"
  REPO="${GITHUB_REPOSITORY}"
  BUILD_URL="${BASE_URL}${REPO}/actions/runs/${GITHUB_RUN_ID}/attempts/${GITHUB_RUN_ATTEMPT}"
  
  # Send start signal to PSE
  RESPONSE=$(curl -s -o /dev/null -w "%{http_code}" -X POST "https://pse.invisirisk.com/start" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d "builder=github&id=${SCAN_ID}&build_id=${GITHUB_RUN_ID}&build_url=${BUILD_URL}&project=${GITHUB_REPOSITORY}&workflow=${GITHUB_WORKFLOW} - ${GITHUB_JOB}&builder_url=${BASE_URL}&scm=git&scm_commit=${GITHUB_SHA}&scm_branch=${GITHUB_REF_NAME}&scm_origin=${BASE_URL}${REPO}")
  
  if [ "$RESPONSE" != "200" ]; then
    log "ERROR: Failed to signal build start. Status: $RESPONSE"
    exit 1
  fi
  
  log "Build start signaled successfully"
}

# Main execution
main() {
  log "Starting PSE GitHub Action setup"
  
  validate_env_vars
  setup_dependencies
  get_ecr_credentials
  pull_and_start_pse_container
  setup_iptables
  setup_ca_certificates
  signal_build_start
  
  log "PSE GitHub Action setup completed successfully"
}

# Execute main function
main
