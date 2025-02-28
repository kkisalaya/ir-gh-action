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

# Function to signal build end
signal_build_end() {
  log "Signaling build end"
  
  # Check if in test mode
  if [ "$TEST_MODE" = "true" ]; then
    log "Running in TEST_MODE, skipping build end signal"
    return 0
  fi
  
  # Skip if using dummy SCAN_ID
  if [ "$SCAN_ID" = "cleanup_only" ]; then
    log "Skipping build end signal as no valid SCAN_ID is available"
    return 0
  fi
  
  # Build URL parameters
  BASE_URL="${GITHUB_SERVER_URL}/"
  REPO="${GITHUB_REPOSITORY}"
  BUILD_URL="${BASE_URL}${REPO}/actions/runs/${GITHUB_RUN_ID}/attempts/${GITHUB_RUN_ATTEMPT}"
  
  # Determine build status
  BUILD_STATUS="${GITHUB_JOB_STATUS:-success}"
  
  # Send end signal to PSE with retry mechanism
  MAX_RETRIES=3
  RETRY_DELAY=3
  ATTEMPT=1
  
  while [ $ATTEMPT -le $MAX_RETRIES ]; do
    log "Sending build end signal, attempt $ATTEMPT of $MAX_RETRIES"
    RESPONSE=$(curl -L -s -o /dev/null -w "%{http_code}" -X POST "https://pse.invisirisk.com/end" \
      -H "Content-Type: application/x-www-form-urlencoded" \
      -d "build_url=${BUILD_URL}&status=${BUILD_STATUS}")
    
    if [ "$RESPONSE" = "200" ]; then
      log "Build end signaled successfully"
      break
    else
      log "Failed to signal build end. Status: $RESPONSE, retrying in $RETRY_DELAY seconds..."
      sleep $RETRY_DELAY
      RETRY_DELAY=$((RETRY_DELAY * 2))
      ATTEMPT=$((ATTEMPT + 1))
    fi
  done
  
  if [ $ATTEMPT -gt $MAX_RETRIES ]; then
    log "WARNING: Failed to signal build end after $MAX_RETRIES attempts"
    # Continue with cleanup despite failure to signal
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

# Function to stop and remove PSE container
cleanup_pse_container() {
  log "Cleaning up PSE container"
  
  # Check if in test mode
  if [ "$TEST_MODE" = "true" ]; then
    log "Running in TEST_MODE, skipping PSE container cleanup"
    return 0
  fi
  
  # Stop and remove PSE container if it exists
  if sudo docker ps -a | grep -q pse; then
    sudo docker stop pse 2>/dev/null || true
    sudo docker rm pse 2>/dev/null || true
    log "PSE container stopped and removed"
  else
    log "No PSE container to clean up"
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
  
  validate_env_vars
  signal_build_end
  cleanup_iptables
  cleanup_pse_container
  cleanup_certificates
  
  log "PSE GitHub Action cleanup completed successfully"
}

# Execute main function
main
