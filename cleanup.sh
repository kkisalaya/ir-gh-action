#!/bin/bash
# PSE GitHub Action - Cleanup Script
# This script cleans up the PSE proxy configuration and signals the end of the build

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
  local required_vars=("API_URL" "APP_TOKEN" "PORTAL_URL")
  
  for var in "${required_vars[@]}"; do
    if [ -z "${!var}" ]; then
      log "ERROR: Required environment variable $var is not set"
      exit 1
    fi
  done
  
  # Check SCAN_ID separately with warning instead of error
  if [ -z "$SCAN_ID" ]; then
    log "WARNING: SCAN_ID is not set. This may be because scan creation failed. Continuing with cleanup..."
    # Set a dummy value to prevent further errors
    export SCAN_ID="cleanup_only"
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
  
  # Make API call to signal build end
  END_RESPONSE=$(curl -L -s -X POST "$API_URL/utilityapi/v1/scan/$SCAN_ID/end" \
    -H "Content-Type: application/json" \
    -d "{\"api_key\": \"$APP_TOKEN\"}")
  
  # Print response for debugging (masking sensitive data)
  if [ "$DEBUG" = "true" ]; then
    log "API Response (masked): $(echo "$END_RESPONSE" | sed 's/"api_key":"[^"]*"/"api_key":"***"/g')"
  fi
  
  # Check if the response contains an error message
  if echo "$END_RESPONSE" | grep -q '"error"'; then
    log "ERROR: Failed to signal build end: $(echo "$END_RESPONSE" | grep -o '"error":"[^"]*' | cut -d'"' -f4)"
    return 1
  fi
  
  log "Build end signaled successfully"
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
  
  # Check if container exists or existed
  if ! sudo docker ps -a -q -f name="$container_name" > /dev/null 2>&1; then
    log "Container $container_name not found, cannot display logs"
    return 1
  fi
  
  # Display a separator for better readability
  echo "================================================================="
  echo "                   PSE CONTAINER LOGS                            "
  echo "================================================================="
  
  # Get all logs from the container
  sudo docker logs "$container_name" 2>&1 || log "Failed to retrieve container logs"
  
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
  if sudo docker ps -a | grep -q pse; then
    sudo docker stop pse 2>/dev/null || true
    sudo docker rm pse 2>/dev/null || true
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
  if sudo iptables -t nat -L pse >/dev/null 2>&1; then
    sudo iptables -t nat -D OUTPUT -j pse 2>/dev/null || true
    sudo iptables -t nat -F pse 2>/dev/null || true
    sudo iptables -t nat -X pse 2>/dev/null || true
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
  
  # Remove PSE certificate
  if [ -f /etc/ssl/certs/pse.pem ]; then
    sudo rm -f /etc/ssl/certs/pse.pem
    sudo update-ca-certificates --fresh
    log "PSE certificate removed"
  else
    log "No PSE certificate to clean up"
  fi
  
  # Reset Git SSL configuration
  git config --global --unset http.sslCAInfo || true
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
