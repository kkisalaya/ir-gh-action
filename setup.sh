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

# Function to parse JSON
parse_json() {
  local json="$1"
  local field="$2"
  
  # Check if jq is available
  if command -v jq >/dev/null 2>&1; then
    # Use jq for more reliable JSON parsing
    value=$(echo "$json" | jq -r ".$field" 2>/dev/null)
    if [ "$value" != "null" ] && [ -n "$value" ]; then
      echo "$value"
      return 0
    fi
  fi
  
  # Fallback to grep-based extraction
  value=$(echo "$json" | grep -o "\"$field\":[[:space:]]*\"[^\"]*\"" | cut -d'"' -f4)
  echo "$value"
}

# Function to parse nested JSON
parse_nested_json() {
  local json="$1"
  local parent_field="$2"
  local child_field="$3"
  
  # Check if jq is available
  if command -v jq >/dev/null 2>&1; then
    # Use jq for more reliable JSON parsing
    value=$(echo "$json" | jq -r ".$parent_field.$child_field" 2>/dev/null)
    if [ "$value" != "null" ] && [ -n "$value" ]; then
      echo "$value"
      return 0
    fi
  fi
  
  # Fallback to extracting parent object first, then child field
  parent_obj=$(echo "$json" | grep -o "\"$parent_field\":[[:space:]]*{[^}]*}" | sed "s/\"$parent_field\":[[:space:]]*//")
  if [ -n "$parent_obj" ]; then
    value=$(echo "$parent_obj" | grep -o "\"$child_field\":[[:space:]]*\"[^\"]*\"" | cut -d'"' -f4)
    echo "$value"
  fi
}

# Function to get ECR credentials
get_ecr_credentials() {
  log "Obtaining ECR credentials from $API_URL"
  
  # Check if in test mode
  if [ "$TEST_MODE" = "true" ]; then
    log "Running in TEST_MODE, using dummy ECR credentials"
    export ECR_USERNAME="test_user"
    export ECR_TOKEN="test_token"
    export ECR_REGION="us-east-1"
    export ECR_REGISTRY_ID="123456789012"
    log "Dummy ECR credentials set"
    return 0
  fi
  
  # Log the API endpoint being called
  log "Calling API endpoint: $API_URL/utilityapi/v1/registry with API key"
  
  # Create temp file for headers
  HEADER_FILE=$(mktemp)
  
  # Fetch ECR details with verbose output
  log "Executing curl command..."
  if [ "$DEBUG" = "true" ]; then
    # In debug mode, use verbose output
    log "Running in debug mode with verbose curl output"
    ECR_RESPONSE=$(curl -L -v -D "$HEADER_FILE" -X GET "$API_URL/utilityapi/v1/registry?api_key=$APP_TOKEN" 2>&1 | tee /tmp/curl_debug.log)
    log "Full curl debug output saved to /tmp/curl_debug.log"
  else
    ECR_RESPONSE=$(curl -L -s -D "$HEADER_FILE" -X GET "$API_URL/utilityapi/v1/registry?api_key=$APP_TOKEN")
  fi
  
  # Log HTTP status and headers
  log "HTTP Response Headers:"
  log "$(cat "$HEADER_FILE" | grep -v "Authorization")"
  
  # Remove temp file
  rm "$HEADER_FILE"
  
  # Log the response (masked for security)
  log "API Response (masked): $(echo "$ECR_RESPONSE" | sed 's/"api_key":"[^"]*"/"api_key":"***"/g')"
  
  # Check if the response contains an error message
  if echo "$ECR_RESPONSE" | grep -q '"error"'; then
    log "Error received from API: $(echo "$ECR_RESPONSE" | grep -o '"error":[[:space:]]*"[^"]*"' | cut -d'"' -f4)"
    exit 1
  fi
  
  # Check if response is empty or not JSON
  if [ -z "$ECR_RESPONSE" ]; then
    log "ERROR: Empty response received from API"
    exit 1
  fi
  
  if ! echo "$ECR_RESPONSE" | grep -q '{'; then
    log "ERROR: Invalid JSON response received from API"
    log "Response: $ECR_RESPONSE"
    exit 1
  fi
  
  log "Attempting to extract data field from response"
  # Extract and log the data field (if present)
  DATA_FIELD=$(parse_json "$ECR_RESPONSE" "data")
  if [ -z "$DATA_FIELD" ]; then
    log "ERROR: No data field found in response"
    exit 1
  fi
  
  log "Data field found, attempting to decode"
  # Decode base64 token
  DECODED_TOKEN=$(echo "$DATA_FIELD" | base64 -d)
  
  # Log decoded token structure (without sensitive info)
  log "Decoded token structure: $(echo "$DECODED_TOKEN" | sed 's/"password":"[^"]*"/"password":"***"/g')"
  
  # Extract ECR credentials - updating patterns to match the actual JSON structure
  ECR_USERNAME=$(parse_json "$DECODED_TOKEN" "username")
  ECR_TOKEN=$(parse_json "$DECODED_TOKEN" "password")
  ECR_REGION=$(parse_json "$DECODED_TOKEN" "region")
  ECR_REGISTRY_ID=$(parse_json "$DECODED_TOKEN" "registry_id")
  
  # Log extracted values (masking sensitive data)
  log "Extracted username: ${ECR_USERNAME:0:3}***"
  log "Extracted token: ***"
  log "Extracted region: $ECR_REGION"
  log "Extracted registry ID: $ECR_REGISTRY_ID"
  
  if [ -z "$ECR_USERNAME" ] || [ -z "$ECR_TOKEN" ]; then
    log "ERROR: Failed to obtain ECR credentials"
    log "Username empty: $([ -z "$ECR_USERNAME" ] && echo "Yes" || echo "No")"
    log "Token empty: $([ -z "$ECR_TOKEN" ] && echo "Yes" || echo "No")"
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
    apk add --no-cache iptables ca-certificates git curl docker jq
  else
    # Debian/Ubuntu
    log "Detected Debian/Ubuntu"
    sudo apt-get update
    sudo apt-get install -y iptables ca-certificates git curl jq
  fi
  
  log "Dependencies installed successfully"
}

# Function to pull and start PSE container
pull_and_start_pse_container() {
  log "Setting up PSE container"
  
  # Check if in test mode
  if [ "$TEST_MODE" = "true" ]; then
    log "Running in TEST_MODE, skipping PSE container setup"
    # Set a dummy PSE_IP for iptables configuration
    export PSE_IP="127.0.0.1"
    return 0
  fi
  
  # Login to ECR with retry mechanism
  MAX_RETRIES=3
  RETRY_DELAY=5
  ATTEMPT=1
  
  while [ $ATTEMPT -le $MAX_RETRIES ]; do
    log "Logging in to ECR, attempt $ATTEMPT of $MAX_RETRIES"
    if echo "$ECR_TOKEN" | sudo docker login --username "$ECR_USERNAME" --password-stdin "$ECR_REGISTRY_ID.dkr.ecr.$ECR_REGION.amazonaws.com"; then
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
    if sudo docker pull "$ECR_REGISTRY_ID.dkr.ecr.$ECR_REGION.amazonaws.com/pse:latest"; then
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
  sudo docker run -d --name pse \
    -e PSE_DEBUG_FLAG="--alsologtostderr" \
    -e POLICY_LOG="t" \
    -e INVISIRISK_JWT_TOKEN="$APP_TOKEN" \
    -e INVISIRISK_PORTAL="$PORTAL_URL" \
    -e GITHUB_TOKEN="$GITHUB_TOKEN" \
    "$ECR_REGISTRY_ID.dkr.ecr.$ECR_REGION.amazonaws.com/pse:latest"
  
  # Get container IP for iptables configuration
  PSE_IP=$(sudo docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' pse)
  export PSE_IP="$PSE_IP"
  
  log "PSE container started with IP: $PSE_IP"
}

# Function to set up iptables rules
setup_iptables() {
  log "Setting up iptables rules"
  
  # Check if in test mode
  if [ "$TEST_MODE" = "true" ]; then
    log "Running in TEST_MODE, skipping iptables setup"
    return 0
  fi
  
  # Configure iptables to redirect HTTPS traffic
  sudo iptables -t nat -N pse
  sudo iptables -t nat -A OUTPUT -j pse
  
  # Redirect HTTPS traffic to PSE
  sudo iptables -t nat -A pse -p tcp -m tcp --dport 443 -j DNAT --to-destination ${PSE_IP}:12345
  
  log "iptables rules configured successfully"
}

# Function to set up certificates
setup_certificates() {
  log "Setting up certificates"
  
  # Check if in test mode
  if [ "$TEST_MODE" = "true" ]; then
    log "Running in TEST_MODE, skipping certificate setup"
    return 0
  fi
  
  # Fetch CA certificate from PSE with retries
  MAX_RETRIES=5
  RETRY_DELAY=3
  ATTEMPT=1
  
  while [ $ATTEMPT -le $MAX_RETRIES ]; do
    log "Fetching CA certificate, attempt $ATTEMPT of $MAX_RETRIES"
    if curl -L -k -s -o /tmp/pse.pem https://pse.invisirisk.com/ca; then
      sudo mv /tmp/pse.pem /etc/ssl/certs/pse.pem
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
  sudo update-ca-certificates
  
  # Configure Git to use our CA
  git config --global http.sslCAInfo /etc/ssl/certs/pse.pem
  
  # Set environment variables for other tools
  export NODE_EXTRA_CA_CERTS=/etc/ssl/certs/pse.pem
  export REQUESTS_CA_BUNDLE=/etc/ssl/certs/pse.pem
  
  # Add to GITHUB_ENV to persist these variables
  echo "NODE_EXTRA_CA_CERTS=/etc/ssl/certs/pse.pem" >> $GITHUB_ENV
  echo "REQUESTS_CA_BUNDLE=/etc/ssl/certs/pse.pem" >> $GITHUB_ENV
  
  log "Certificates configured successfully"
}

# Function to signal build start
signal_build_start() {
  log "Signaling build start"
  
  # Check if in test mode
  if [ "$TEST_MODE" = "true" ]; then
    log "Running in TEST_MODE, skipping build start signal"
    return 0
  fi
  
  # Build URL parameters
  BASE_URL="${GITHUB_SERVER_URL}/"
  REPO="${GITHUB_REPOSITORY}"
  BUILD_URL="${BASE_URL}${REPO}/actions/runs/${GITHUB_RUN_ID}/attempts/${GITHUB_RUN_ATTEMPT}"
  
  # Send start signal to PSE
  RESPONSE=$(curl -L -s -o /dev/null -w "%{http_code}" -X POST "https://pse.invisirisk.com/start" \
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
  setup_certificates
  signal_build_start
  
  log "PSE GitHub Action setup completed successfully"
}

# Execute main function
main
