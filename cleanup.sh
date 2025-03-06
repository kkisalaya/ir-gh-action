#!/bin/bash
# PSE GitHub Action - Cleanup Script
# This script cleans up the PSE proxy configuration and signals the end of the build
# Compatible with both container and non-container environments

# Find the location of scripts in the repository
find_script() {
  local script_name="$1"
  local script_path=""
  
  # Check common locations
  local possible_paths=(
    "$GITHUB_ACTION_PATH/$script_name"
    "$GITHUB_WORKSPACE/$script_name"
    "$PWD/$script_name"
    "$RUNNER_WORKSPACE/$(basename $GITHUB_REPOSITORY)/$script_name"
    "/github/workspace/$script_name"
    "$(dirname "$0")/$script_name"
    "./$script_name"
  )
  
  for path in "${possible_paths[@]}"; do
    if [ -f "$path" ]; then
      script_path="$path"
      break
    fi
  done
  
  # If not found, search using find command
  if [ -z "$script_path" ]; then
    local repo_paths=(
      "$GITHUB_WORKSPACE"
      "$RUNNER_WORKSPACE/$(basename $GITHUB_REPOSITORY)"
      "/github/workspace"
      "$PWD"
    )
    
    for repo_path in "${repo_paths[@]}"; do
      if [ -d "$repo_path" ]; then
        local found_script=$(find "$repo_path" -name "$script_name" -type f -print -quit 2>/dev/null)
        if [ -n "$found_script" ]; then
          script_path="$found_script"
          break
        fi
      fi
    done
  fi
  
  echo "$script_path"
}

# Enable strict error handling
set -e

# Enable debug mode if requested
if [ "$DEBUG" = "true" ]; then
  set -x
fi

# Detect if running in a container
is_container() {
  # Check multiple indicators of container environment
  if [ -f "/.dockerenv" ] || [ -f "/run/.containerenv" ] || grep -q 'docker\|lxc' /proc/1/cgroup 2>/dev/null; then
    log "Detected container environment"
    return 0  # True in bash
  else
    log "Detected non-container environment"
    return 1  # False in bash
  fi
}

# Function to execute a command with or without sudo based on environment
exec_with_privileges() {
  if is_container; then
    # In container, try to run without sudo
    "$@"
  else
    # On host, use sudo
    sudo "$@"
  fi
}

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
  # Check for API_URL
  if [ -z "$API_URL" ]; then
    log "INFO: API_URL is not set, trying to use PSE_API_URL from previous step..."
    if [ -n "$PSE_API_URL" ]; then
      export API_URL="$PSE_API_URL"
      log "Using API_URL from previous step: $API_URL"
    else
      log "ERROR: Could not determine API_URL. Please provide it as an input parameter or run setup first."
      exit 1
    fi
  fi
  
  # Check for APP_TOKEN
  if [ -z "$APP_TOKEN" ]; then
    log "INFO: APP_TOKEN is not set, trying to use PSE_APP_TOKEN from previous step..."
    if [ -n "$PSE_APP_TOKEN" ]; then
      export APP_TOKEN="$PSE_APP_TOKEN"
      log "Using APP_TOKEN from previous step (value hidden)"
    else
      log "ERROR: Could not determine APP_TOKEN. Please provide it as an input parameter or run setup first."
      exit 1
    fi
  fi
  
  # Check for PORTAL_URL
  if [ -z "$PORTAL_URL" ]; then
    log "INFO: PORTAL_URL is not set, trying to use PSE_PORTAL_URL from previous step..."
    if [ -n "$PSE_PORTAL_URL" ]; then
      export PORTAL_URL="$PSE_PORTAL_URL"
      log "Using PORTAL_URL from previous step: $PORTAL_URL"
    else
      # Try to use API_URL as fallback
      export PORTAL_URL="$API_URL"
      log "Using API_URL as fallback for PORTAL_URL: $PORTAL_URL"
    fi
  fi
  
  # Check SCAN_ID separately with warning instead of error
  if [ -z "$SCAN_ID" ]; then
    log "INFO: SCAN_ID is not set, using a default value for cleanup..."
    # Generate a unique ID for this cleanup session
    export SCAN_ID="cleanup_$(date +%s)_${GITHUB_RUN_ID:-unknown}"
    log "Using generated SCAN_ID: $SCAN_ID"
  fi
  
  log "Environment validation successful"
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
  if [ -z "$SCAN_ID" ]; then
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

# Function to signal build end
signal_build_end() {
  log "Signaling build end to InvisiRisk API"
  
  # Check if in test mode
  if [ "$TEST_MODE" = "true" ]; then
    log "Running in TEST_MODE, skipping API call"
    return 0
  fi
  
  # Check if SCAN_ID is set
  if [ -z "$SCAN_ID" ]; then
    log "ERROR: SCAN_ID is not set, cannot signal build end"
    return 1
  fi
  
  # Use PSE endpoint directly
  BASE_URL="https://pse.invisirisk.com"
  
  # Build URL for the GitHub run
  build_url="${GITHUB_SERVER_URL}/${GITHUB_REPOSITORY}/actions/runs/${GITHUB_RUN_ID}"
  
  # Build parameters
  params="id=$(url_encode "$SCAN_ID")"
  params="${params}&build_url=$(url_encode "$build_url")"
  params="${params}&status=$(url_encode "${GITHUB_RUN_RESULT:-unknown}")"
  
  log "Sending end signal to PSE with parameters: $params"
  
  # Send request with retries
  MAX_RETRIES=3
  RETRY_DELAY=2
  ATTEMPT=1
  
  while [ $ATTEMPT -le $MAX_RETRIES ]; do
    log "Sending end signal, attempt $ATTEMPT of $MAX_RETRIES"
    
    RESPONSE=$(curl -X POST "${BASE_URL}/end" \
      -H 'Content-Type: application/x-www-form-urlencoded' \
      -H 'User-Agent: pse-action' \
      -d "$params" \
      -k --tlsv1.2 --insecure \
      --retry 3 --retry-delay 2 --max-time 10 \
      -s -w "\n%{http_code}" 2>&1)
    
    HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
    RESPONSE_BODY=$(echo "$RESPONSE" | sed '$d')
    
    if [ "$HTTP_CODE" -ge 200 ] && [ "$HTTP_CODE" -lt 300 ]; then
      log "End signal sent successfully (HTTP $HTTP_CODE)"
      log "Response: $RESPONSE_BODY"
      return 0
    else
      log "Failed to send end signal (HTTP $HTTP_CODE)"
      log "Response: $RESPONSE_BODY"
      log "Retrying in $RETRY_DELAY seconds..."
      sleep $RETRY_DELAY
      RETRY_DELAY=$((RETRY_DELAY * 2))
      ATTEMPT=$((ATTEMPT + 1))
    fi
  done
  
  log "WARNING: Failed to send end signal after $MAX_RETRIES attempts"
  log "Continuing anyway..."
  return 0
}

# Function to display container logs
display_container_logs() {
  local container_name="$1"
  
  log "Displaying logs for container: $container_name"
  
  # Check if in test mode
  if [ "$TEST_MODE" = "true" ]; then
    log "Running in TEST_MODE, skipping container logs display"
    return 0
  fi
  
  # Check if sudo is available, install it if needed and we're in a container
  if is_container && ! command -v sudo >/dev/null 2>&1; then
    log "sudo not found, installing it"
    apt-get update
    apt-get install -y sudo
    log "sudo installed successfully"
  fi

  # Check if container exists or existed
  if ! exec_with_privileges docker ps -a -q -f name="$container_name" > /dev/null 2>&1; then
    log "Container $container_name not found, cannot display logs"
    return 1
  fi
  
  # Display a separator for better readability
  echo "================================================================="
  echo "                   PSE CONTAINER LOGS                            "
  echo "================================================================="
  
  # Get all logs from the container
  exec_with_privileges docker logs "$container_name" 2>&1 || log "Failed to retrieve container logs"
  
  # Display another separator
  echo "================================================================="
  echo "                END OF PSE CONTAINER LOGS                        "
  echo "================================================================="
}

# Function to clean up PSE container
cleanup_pse_container() {
  log "Cleaning up PSE container"
  
  # Check if in test mode
  if [ "$TEST_MODE" = "true" ]; then
    log "Running in TEST_MODE, skipping PSE container cleanup"
    return 0
  fi
  
  # Display container logs before stopping it
  display_container_logs "pse"
  
  # Stop and remove PSE container if it exists
  if exec_with_privileges docker ps -a | grep -q pse; then
    exec_with_privileges docker stop pse 2>/dev/null || true
    exec_with_privileges docker rm pse 2>/dev/null || true
    log "PSE container stopped and removed"
  else
    log "No PSE container to clean up"
  fi
}

# Function to clean up iptables rules
cleanup_iptables() {
  log "Cleaning up iptables rules"
  
  # Check if in test mode
  if [ "$TEST_MODE" = "true" ]; then
    log "Running in TEST_MODE, skipping iptables cleanup"
    return 0
  fi
  
  # Remove iptables rules
  if exec_with_privileges iptables -t nat -L pse >/dev/null 2>&1; then
    exec_with_privileges iptables -t nat -D OUTPUT -j pse 2>/dev/null || true
    exec_with_privileges iptables -t nat -F pse 2>/dev/null || true
    exec_with_privileges iptables -t nat -X pse 2>/dev/null || true
    log "iptables rules removed successfully"
  else
    log "No iptables rules to clean up"
  fi
}

# Function to clean up certificates
cleanup_certificates() {
  log "Cleaning up certificates"
  
  # Check if in test mode
  if [ "$TEST_MODE" = "true" ]; then
    log "Running in TEST_MODE, skipping certificate cleanup"
    return 0
  fi
  
  # Remove PSE certificate from the Ubuntu CA store
  if [ -f /usr/local/share/ca-certificates/extra/pse.crt ]; then
    log "Removing PSE certificate from CA store"
    exec_with_privileges rm -f /usr/local/share/ca-certificates/extra/pse.crt
    exec_with_privileges update-ca-certificates --fresh
    log "PSE certificate removed"
  elif [ -f /etc/ssl/certs/pse.pem ]; then
    # Backward compatibility for old installations
    log "Removing legacy PSE certificate"
    exec_with_privileges rm -f /etc/ssl/certs/pse.pem
    exec_with_privileges update-ca-certificates --fresh
    log "Legacy PSE certificate removed"
  else
    log "No PSE certificate found to clean up"
  fi
  
  # Reset Git SSL configuration
  git config --global --unset http.sslCAInfo || true
  
  # Clean up environment variables
  unset NODE_EXTRA_CA_CERTS
  unset REQUESTS_CA_BUNDLE
  
  log "Certificate cleanup completed"
}

# Main execution
main() {
  log "Starting PSE GitHub Action cleanup"
  
  # Validate environment variables
  validate_env_vars
  
  # Display container logs before cleanup
  display_container_logs "pse"
  
  # Signal build end to InvisiRisk API
  signal_build_end
  
  # Clean up resources
  cleanup_pse_container
  cleanup_iptables
  cleanup_certificates
  
  log "PSE GitHub Action cleanup completed successfully"
}

# Execute main function
main
