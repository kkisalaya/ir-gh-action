#!/bin/bash
# PSE GitHub Action - Setup Script
# This script configures the build environment to route HTTPS traffic through the PSE proxy

# Enable strict error handling
set -e

# Enable debug mode if requested
if [ "$DEBUG" = "true" ]; then
  set -x
fi

# Set default mode if not provided
MODE=${MODE:-full}

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

# Helper function to run commands with or without sudo based on environment
run_with_privilege() {
  if [ "$(id -u)" = "0" ]; then
    # Running as root (common in containers), execute directly
    "$@"
  else
    # Not running as root, use sudo
    sudo "$@"
  fi
}

# Validate required environment variables based on mode
validate_env_vars() {
  local required_vars=()
  
  # Define required variables based on mode
  if [ "$MODE" = "pse_only" ]; then
    required_vars=("API_URL" "APP_TOKEN" "PORTAL_URL" "GITHUB_TOKEN") # SCAN_ID not required for pse_only
  elif [ "$MODE" = "full" ]; then
    required_vars=("API_URL" "APP_TOKEN" "PORTAL_URL" "SCAN_ID" "GITHUB_TOKEN")
  elif [ "$MODE" = "build_only" ]; then
    required_vars=("SCAN_ID" "GITHUB_TOKEN")
    # Debug PROXY_IP value
    log "Debug: PROXY_IP environment variable value: '$PROXY_IP'"
    
    # Check for PROXY_IP specifically for build_only mode
    if [ -z "$PROXY_IP" ]; then
      # Try using the fallback value from action.yml if available
      if [ -n "$PSE_PROXY_FALLBACK" ]; then
        log "INFO: Using fallback proxy IP: $PSE_PROXY_FALLBACK"
        PROXY_IP="$PSE_PROXY_FALLBACK"
        export PROXY_IP
      else
        log "ERROR: PROXY_IP is required for build_only mode but not set"
        log "TIP: Make sure to pass the proxy_ip output from the pse_only job"
        log "Example: proxy_ip: \"${{ needs.setup-pse.outputs.proxy_ip }}\""
        exit 1
      fi
    fi
  else 
    log "ERROR: Invalid mode $MODE. Valid modes are 'pse_only', 'build_only', and 'full'"
    exit 1
  fi
  
  for var in "${required_vars[@]}"; do
    if [ -z "${!var}" ]; then
      log "ERROR: Required environment variable $var is not set"
      exit 1
    fi
  done
  
  log "Environment validation successful for mode: $MODE"
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
    # Alpine typically runs as root in containers
    if [ "$(id -u)" = "0" ]; then
      apk add --no-cache iptables ca-certificates git curl docker jq
    else
      sudo apk add --no-cache iptables ca-certificates git curl docker jq
    fi
  else
    # Debian/Ubuntu
    log "Detected Debian/Ubuntu"
    run_with_privilege apt-get update
    run_with_privilege apt-get install -y iptables ca-certificates git curl jq
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
  
  # Set retry parameters
  MAX_RETRIES=3
  RETRY_DELAY=5
  
  # Login to ECR with retry mechanism
  ATTEMPT=1
  
  while [ $ATTEMPT -le $MAX_RETRIES ]; do
    log "Logging in to ECR, attempt $ATTEMPT of $MAX_RETRIES"
    if echo "$ECR_TOKEN" | run_with_privilege docker login --username "$ECR_USERNAME" --password-stdin "$ECR_REGISTRY_ID.dkr.ecr.$ECR_REGION.amazonaws.com"; then
      log "ECR login successful"
      break
    else
      log "ECR login failed, retrying in $RETRY_DELAY seconds..."
      sleep $RETRY_DELAY
      RETRY_DELAY=$((RETRY_DELAY * 2))
      ATTEMPT=$((ATTEMPT + 1))
    fi
  done
  
  if [ $ATTEMPT -gt $MAX_RETRIES ]; then
    log "ERROR: Failed to login to ECR after $MAX_RETRIES attempts"
    exit 1
  fi
  
  # Define the correct image path
  PRIMARY_IMAGE="$ECR_REGISTRY_ID.dkr.ecr.$ECR_REGION.amazonaws.com/invisirisk/pse-proxy:latest"
  FALLBACK_IMAGES=(
    "$ECR_REGISTRY_ID.dkr.ecr.$ECR_REGION.amazonaws.com/pse:latest"
    "$ECR_REGISTRY_ID.dkr.ecr.$ECR_REGION.amazonaws.com/pse-proxy:latest"
    "$ECR_REGISTRY_ID.dkr.ecr.$ECR_REGION.amazonaws.com/invisirisk/pse:latest"
  )
  
  # Try primary image first
  log "Trying primary PSE image: $PRIMARY_IMAGE"
  PSE_IMAGE="$PRIMARY_IMAGE"
  
  ATTEMPT=1
  while [ $ATTEMPT -le $MAX_RETRIES ]; do
    log "Pulling PSE container, attempt $ATTEMPT of $MAX_RETRIES"
    PULL_OUTPUT=$(run_with_privilege docker pull "$PSE_IMAGE" 2>&1)
    PULL_STATUS=$?
    
    if [ $PULL_STATUS -eq 0 ]; then
      log "PSE container pulled successfully"
      break
    else
      log "Failed to pull PSE container (exit code: $PULL_STATUS)"
      log "Error output: $PULL_OUTPUT"
      
      # If we've exhausted retries for this image, try fallbacks
      if [ $ATTEMPT -eq $MAX_RETRIES ] && [ ${#FALLBACK_IMAGES[@]} -gt 0 ]; then
        FALLBACK_IMAGE=${FALLBACK_IMAGES[0]}
        FALLBACK_IMAGES=("${FALLBACK_IMAGES[@]:1}")
        log "Trying fallback PSE image: $FALLBACK_IMAGE"
        PSE_IMAGE="$FALLBACK_IMAGE"
        ATTEMPT=1
        continue
      fi
      
      log "Retrying in $RETRY_DELAY seconds..."
      sleep $RETRY_DELAY
      RETRY_DELAY=$((RETRY_DELAY * 2))
      ATTEMPT=$((ATTEMPT + 1))
    fi
  done
  
  if [ $ATTEMPT -gt $MAX_RETRIES ] && [ ${#FALLBACK_IMAGES[@]} -eq 0 ]; then
    log "ERROR: Failed to pull PSE container after trying all repository paths"
    log "Last error: $PULL_OUTPUT"
    
    # Try to get more information about the repository
    log "Attempting to get more information about the repository..."
    run_with_privilege docker logout "$ECR_REGISTRY_ID.dkr.ecr.$ECR_REGION.amazonaws.com" || true
    echo "$ECR_TOKEN" | run_with_privilege docker login --username "$ECR_USERNAME" --password-stdin "$ECR_REGISTRY_ID.dkr.ecr.$ECR_REGION.amazonaws.com"
    REPO_INFO=$(aws ecr describe-repositories --registry-id "$ECR_REGISTRY_ID" --region "$ECR_REGION" 2>&1 || echo "AWS CLI not available or not configured")
    log "Repository information: $REPO_INFO"
    
    exit 1
  fi
  
  # Start PSE container with required environment variables
  log "Starting PSE container"
  run_with_privilege docker run -d --name pse \
    -e PSE_DEBUG_FLAG="--alsologtostderr" \
    -e POLICY_LOG="t" \
    -e INVISIRISK_JWT_TOKEN="$APP_TOKEN" \
    -e INVISIRISK_PORTAL="$PORTAL_URL" \
    -e GITHUB_TOKEN="$GITHUB_TOKEN" \
    "$PSE_IMAGE"
  
  # Get container IP for iptables configuration
  PSE_IP=$(run_with_privilege docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' pse)
  export PSE_IP="$PSE_IP"
  export PROXY_IP="$PSE_IP"
  
  # Save the API values to environment for later use
  echo "PSE_API_URL=$API_URL" >> $GITHUB_ENV
  echo "PSE_APP_TOKEN=$APP_TOKEN" >> $GITHUB_ENV
  echo "PSE_PORTAL_URL=$PORTAL_URL" >> $GITHUB_ENV
  echo "PSE_PROXY_IP=$PSE_IP" >> $GITHUB_ENV
  
  # Also save the PSE proxy IP as an output parameter
  echo "proxy_ip=$PSE_IP" >> $GITHUB_OUTPUT
  
  # Double check that the proxy IP has been properly set as output
  log "Set proxy_ip output parameter to: $PSE_IP"
  
  log "PSE container started with IP: $PSE_IP"
  log "Proxy IP has been saved to GitHub environment as PSE_PROXY_IP"
}

# Function to set up iptables rules
setup_iptables() {
  log "Setting up iptables rules"
  
  # Check if in test mode
  if [ "$TEST_MODE" = "true" ]; then
    log "Running in TEST_MODE, skipping iptables setup"
    return 0
  fi
  
  # Configure iptables rules based on the mode
  local proxy_port=12345
  local target_ip
  
  # Determine which IP to use for redirection
  if [ "$MODE" = "build_only" ]; then
    # In build_only mode, use the provided PROXY_IP
    target_ip="$PROXY_IP"
    log "Using provided proxy IP for iptables: $target_ip"
    
    # Double check that PROXY_IP is actually set
    if [ -z "$target_ip" ]; then
      log "ERROR: PROXY_IP is empty in build_only mode. This should not happen!"
      log "Here are the available environment variables that might help debug:"
      env | grep -E 'PROXY|PSE|GITHUB_' || true
      log "Check that you're passing the proxy_ip output from the pse_only job correctly"
      log "Example: proxy_ip: \"${{ needs.setup-pse.outputs.proxy_ip }}\""
      exit 1
    fi
  else
    # In other modes, use the local PSE container IP
    target_ip="$PSE_IP"
    log "Using local PSE container IP for iptables: $target_ip"
  fi
  
  # Configure iptables to redirect HTTPS traffic
  run_with_privilege iptables -t nat -N pse 2>/dev/null || true
  run_with_privilege iptables -t nat -F pse 2>/dev/null || true
  run_with_privilege iptables -t nat -D OUTPUT -j pse 2>/dev/null || true
  run_with_privilege iptables -t nat -A OUTPUT -j pse
  
  # Redirect HTTPS traffic to PSE
  run_with_privilege iptables -t nat -A pse -p tcp -m tcp --dport 443 -j DNAT --to-destination ${target_ip}:${proxy_port}
  
  # Add exceptions for local connections
  run_with_privilege iptables -t nat -A pse -p tcp -d 127.0.0.1 --dport 443 -j ACCEPT
  run_with_privilege iptables -t nat -A pse -p tcp -d localhost --dport 443 -j ACCEPT
  
  log "iptables rules configured successfully to redirect traffic to ${target_ip}:${proxy_port}"
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
  
  # Create directory for extra CA certificates if it doesn't exist
  run_with_privilege mkdir -p /usr/local/share/ca-certificates/extra
  log "Created directory for extra CA certificates"
  
  # Determine the CA certificate source based on mode
  local cert_source
  
  if [ "$MODE" = "build_only" ]; then
    # In build_only mode, use the provided PROXY_IP
    cert_source="https://${PROXY_IP}:8443/ca"
    log "Using remote PSE proxy for CA certificate: $cert_source"
  else
    # In other modes, use the pse.invisirisk.com domain
    cert_source="https://pse.invisirisk.com/ca"
    log "Using main PSE domain for CA certificate: $cert_source"
  fi
  
  while [ $ATTEMPT -le $MAX_RETRIES ]; do
    log "Fetching CA certificate from $cert_source, attempt $ATTEMPT of $MAX_RETRIES"
    if curl -L -k -s -o /tmp/pse.crt "$cert_source"; then
      # Copy to the proper location for Ubuntu/Debian
      run_with_privilege cp /tmp/pse.crt /usr/local/share/ca-certificates/extra/pse.crt
      log "CA certificate successfully retrieved and copied to /usr/local/share/ca-certificates/extra/"
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
  
  # Update CA certificates non-interactively
  log "Updating CA certificates..."
  run_with_privilege update-ca-certificates
  
  # Set the correct path for the installed certificate
  CA_CERT_PATH="/etc/ssl/certs/pse.crt"
  
  # Verify the certificate was properly installed
  if [ -f "$CA_CERT_PATH" ]; then
    log "CA certificate successfully installed at $CA_CERT_PATH"
  else
    # Try to find the actual location
    CA_CERT_PATH=$(find /etc/ssl/certs -name "*pse*" | head -n 1)
    if [ -z "$CA_CERT_PATH" ]; then
      log "WARNING: Could not locate installed CA certificate, using default path"
      CA_CERT_PATH="/etc/ssl/certs/pse.crt"
    else
      log "Found CA certificate at $CA_CERT_PATH"
    fi
  fi
  
  # Configure Git to use our CA
  git config --global http.sslCAInfo "$CA_CERT_PATH"
  
  # Set environment variables for other tools
  export NODE_EXTRA_CA_CERTS="$CA_CERT_PATH"
  export REQUESTS_CA_BUNDLE="$CA_CERT_PATH"
  
  # Add to GITHUB_ENV to persist these variables
  echo "NODE_EXTRA_CA_CERTS=$CA_CERT_PATH" >> $GITHUB_ENV
  echo "REQUESTS_CA_BUNDLE=$CA_CERT_PATH" >> $GITHUB_ENV
  
  log "Certificates configured successfully"
}

# Function to URL encode a string
url_encode() {
  local string="$1"
  local encoded=""
  local i
  for (( i=0; i<${#string}; i++ )); do
    local c="${string:$i:1}"
    case "$c" in
      [a-zA-Z0-9.~_-]) encoded="$encoded$c" ;;
      *) encoded="$encoded$(printf '%%%02X' "'$c")" ;;
    esac
  done
  echo "$encoded"
}

# Function to validate scan ID
validate_scan_id() {
  # In pse_only mode, we may not have a SCAN_ID and that's ok
  if [ "$MODE" = "pse_only" ] && [ -z "$SCAN_ID" ]; then
    log "NOTE: No SCAN_ID provided in pse_only mode - this is acceptable"
    # Generate a temporary ID just for validation purposes
    SCAN_ID="temp-proxy-$(date +%Y%m%d%H%M%S)"
    log "Generated temporary SCAN_ID: $SCAN_ID"
    return 0
  elif [ -z "$SCAN_ID" ]; then
    log "ERROR: No SCAN_ID available"
    return 1
  fi
  
  if [ "$SCAN_ID" = "null" ] || [ "$SCAN_ID" = "undefined" ]; then
    log "ERROR: Invalid SCAN_ID: $SCAN_ID"
    return 1
  fi
  
  # Check if SCAN_ID is a valid UUID (basic check)
  if ! echo "$SCAN_ID" | grep -E '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' >/dev/null; then
    log "WARNING: SCAN_ID does not appear to be a valid UUID: $SCAN_ID"
    # Continue anyway as it might be a different format
  fi
  
  log "SCAN_ID validation passed: $SCAN_ID"
  return 0
}

# Function to signal build start
signal_build_start() {
  log "Signaling build start"
  
  # Check if in test mode or pse_only mode
  if [ "$TEST_MODE" = "true" ]; then
    log "Running in TEST_MODE, skipping build start signal"
    return 0
  elif [ "$MODE" = "pse_only" ]; then
    log "Running in PSE_ONLY mode, not sending build start signal"
    log "Build start signal will be sent during the build phase"
    return 0
  fi
  
  # Validate scan ID
  if ! validate_scan_id; then
    log "WARNING: Cannot signal build start due to invalid SCAN_ID"
    log "Continuing anyway..."
    return 0
  fi
  
  # Use PSE endpoint directly
  BASE_URL="https://pse.invisirisk.com"
  
  # Get Git information with fallbacks for CI environment
  git_url=$(git config --get remote.origin.url 2>/dev/null || echo "https://github.com/$GITHUB_REPOSITORY.git")
  git_branch=$(git rev-parse --abbrev-ref HEAD 2>/dev/null || echo "${GITHUB_REF#refs/heads/}")
  git_commit=$(git rev-parse HEAD 2>/dev/null || echo "$GITHUB_SHA")
  repo_name=$(basename -s .git "$git_url" 2>/dev/null || echo "$GITHUB_REPOSITORY")
  
  # Build URL for the GitHub run
  build_url="${GITHUB_SERVER_URL}/${GITHUB_REPOSITORY}/actions/runs/${GITHUB_RUN_ID}"
  
  # Build parameters
  params="builder=$(url_encode "samplegithub")"
  params="${params}&id=$(url_encode "$SCAN_ID")"
  params="${params}&build_id=$(url_encode "$GITHUB_RUN_ID")"
  params="${params}&build_url=$(url_encode "$build_url")"
  params="${params}&project=$(url_encode "${repo_name:-$GITHUB_REPOSITORY}")"
  params="${params}&workflow=$(url_encode "$GITHUB_WORKFLOW")"
  params="${params}&builder_url=$(url_encode "$GITHUB_SERVER_URL")"
  params="${params}&scm=$(url_encode "git")"
  params="${params}&scm_commit=$(url_encode "$git_commit")"
  params="${params}&scm_branch=$(url_encode "$git_branch")"
  params="${params}&scm_origin=$(url_encode "$git_url")"
  
  log "Sending start signal to PSE with parameters: $params"
  
  # Send request with retries
  MAX_RETRIES=3
  RETRY_DELAY=2
  ATTEMPT=1
  
  while [ $ATTEMPT -le $MAX_RETRIES ]; do
    log "Sending start signal, attempt $ATTEMPT of $MAX_RETRIES"
    
    RESPONSE=$(curl -X POST "${BASE_URL}/start" \
      -H 'Content-Type: application/x-www-form-urlencoded' \
      -H 'User-Agent: pse-action' \
      -d "$params" \
      -k --tlsv1.2 --insecure \
      --retry 3 --retry-delay 2 --max-time 10 \
      -s -w "\n%{http_code}" 2>&1)
    
    HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
    RESPONSE_BODY=$(echo "$RESPONSE" | sed '$d')
    
    if [ "$HTTP_CODE" -ge 200 ] && [ "$HTTP_CODE" -lt 300 ]; then
      log "Start signal sent successfully (HTTP $HTTP_CODE)"
      log "Response: $RESPONSE_BODY"
      return 0
    else
      log "Failed to send start signal (HTTP $HTTP_CODE)"
      log "Response: $RESPONSE_BODY"
      log "Retrying in $RETRY_DELAY seconds..."
      sleep $RETRY_DELAY
      RETRY_DELAY=$((RETRY_DELAY * 2))
      ATTEMPT=$((ATTEMPT + 1))
    fi
  done
  
  log "WARNING: Failed to send start signal after $MAX_RETRIES attempts"
  log "Continuing anyway..."
  return 0
}

# Function to register cleanup script
register_cleanup() {
  log "Registering cleanup script"
  
  # Determine the action path
  ACTION_PATH="${GITHUB_ACTION_PATH:-$(dirname "$0")}"
  
  # Set environment variable for cleanup script path
  if [ -n "$GITHUB_ENV" ]; then
    log "Setting GITHUB_CLEANUP environment variable"
    echo "GITHUB_CLEANUP=${ACTION_PATH}/cleanup.sh" >> "$GITHUB_ENV"
    
    # Ensure SCAN_ID is available for the post-action step
    if [ -n "$SCAN_ID" ]; then
      log "Setting SCAN_ID environment variable for post-action step"
      echo "SCAN_ID=$SCAN_ID" >> "$GITHUB_ENV"
    else
      log "WARNING: SCAN_ID is not set, post-action step may not work correctly"
    fi
    
    # Save important variables to GitHub environment for use in cleanup
    log "Saving variables to GitHub environment for cleanup"
    echo "GITHUB_CLEANUP=${ACTION_PATH}/cleanup.sh" >> "$GITHUB_ENV"
    echo "SCAN_ID=$SCAN_ID" >> "$GITHUB_ENV"
    echo "PSE_API_URL=$API_URL" >> "$GITHUB_ENV"
    echo "PSE_APP_TOKEN=$APP_TOKEN" >> "$GITHUB_ENV"
    echo "PSE_PORTAL_URL=$PORTAL_URL" >> "$GITHUB_ENV"
    
    log "Cleanup script registered at: ${ACTION_PATH}/cleanup.sh"
  else
    log "GITHUB_ENV is not set, skipping cleanup registration"
  fi
  
  # Set output for cleanup flag
  if [ -n "$GITHUB_OUTPUT" ]; then
    log "Setting cleanup output variable"
    echo "cleanup=true" >> "$GITHUB_OUTPUT"
  else
    log "GITHUB_OUTPUT is not set, skipping output registration"
  fi
}

# Main execution
main() {
  log "Starting PSE GitHub Action setup in $MODE mode"
  
  validate_env_vars
  setup_dependencies
  
  if [ "$MODE" = "pse_only" ]; then
    # PSE container setup only
    log "Running in PSE_ONLY mode - setting up PSE container only"
    get_ecr_credentials
    pull_and_start_pse_container
    
    log "PSE_ONLY mode setup completed successfully"
    log "PSE container is running at IP: $PROXY_IP"
    log "This IP address has been saved to GitHub environment as PSE_PROXY_IP"
    log "Use this value in the build_only mode by setting mode: 'build_only' and proxy_ip: \${{ steps.<step-id>.outputs.proxy_ip }}"
    
  elif [ "$MODE" = "build_only" ]; then
    # Build environment setup only
    log "Running in BUILD_ONLY mode - configuring build environment only"
    
    # Enhanced debugging for proxy_ip issues in build_only mode
    log "Using PSE proxy at IP: $PROXY_IP"
    
    # When in a container, ensure proxy_ip is explicitly passed and visible
    if [ "$(id -u)" = "0" ]; then
      log "Detected container environment (running as root)"
      log "PROXY_IP environment variable: $PROXY_IP"
      
      # Try multiple fallback mechanisms to ensure PROXY_IP is set
      if [ -z "$PROXY_IP" ]; then
        if [ -n "$PSE_PROXY_IP" ]; then
          # First try to use PSE_PROXY_IP from the environment
          log "Using PSE_PROXY_IP ($PSE_PROXY_IP) as fallback"
          PROXY_IP="$PSE_PROXY_IP"
          export PROXY_IP
        elif [ -n "$PSE_PROXY_FALLBACK" ]; then
          # Next try using the fallback parameter set in action.yml
          log "Using PSE_PROXY_FALLBACK ($PSE_PROXY_FALLBACK) from action.yml"
          PROXY_IP="$PSE_PROXY_FALLBACK"
          export PROXY_IP
        else
          # Last resort: use hardcoded value - common docker bridge network first address
          log "WARNING: Using hardcoded proxy IP (172.17.0.2) as last resort"
          log "This may work but it's not guaranteed. Check job logs for actual IP."
          PROXY_IP="172.17.0.2"
          export PROXY_IP
        fi
      fi
    fi
    setup_iptables
    setup_certificates
    signal_build_start
    register_cleanup
    
    log "BUILD_ONLY mode setup completed successfully"
    
  else
    # Full setup (default)
    log "Running in FULL mode - complete PSE setup"
    get_ecr_credentials
    pull_and_start_pse_container
    setup_iptables
    setup_certificates
    signal_build_start
    register_cleanup
    
    log "FULL mode setup completed successfully"
  fi
  
  # If we're in debug mode, display container status
  if [ "$DEBUG" = "true" ] && [ "$MODE" != "build_only" ]; then
    log "Container status:"
    run_with_privilege docker ps -a | grep pse || true
    log "Container logs (last 10 lines):"
    run_with_privilege docker logs --tail 10 pse 2>&1 || true
  fi
  
  if [ "$MODE" != "build_only" ]; then
    log "PSE container logs will be displayed at the end of the run"
  fi
}

# Execute main function
main
