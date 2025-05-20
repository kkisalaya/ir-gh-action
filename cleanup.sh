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

# Function to display PSE binary logs
display_pse_binary_logs() {
  log "Displaying logs for PSE binary"
  
  # Check if in test mode
  if [ "$TEST_MODE" = "true" ]; then
    log "Running in TEST_MODE, skipping PSE binary logs display"
    return 0
  fi
  
  
    
  LOG_FILE_TO_DISPLAY="/tmp/pse_binary.log"

  # Check if the log file exists
  if [ ! -f "$LOG_FILE_TO_DISPLAY" ]; then
    log "Log file $LOG_FILE_TO_DISPLAY does not exist"
    return 0
  fi
  
  # Display a separator for better readability
  echo "================================================================="
  echo "                   PSE BINARY LOGS                               "
  echo "================================================================="
  
  # Display the log file contents
  cat "$LOG_FILE_TO_DISPLAY" || log "Failed to display PSE binary logs"
  
  # Display another separator
  echo "================================================================="
  echo "                END OF PSE BINARY LOGS                           "
  echo "================================================================="
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
  
  

  # Default to PSE endpoint directly
  BASE_URL="https://pse.invisirisk.com"
  log "Using default PSE endpoint: $BASE_URL"

  
  # Build URL for the GitHub run
  build_url="${GITHUB_SERVER_URL}/${GITHUB_REPOSITORY}/actions/runs/${GITHUB_RUN_ID}"

  # --- GitHub API Log Download ---
  DOWNLOADED_LOG_ZIP_FILE="/tmp/workflow_run_logs_${GITHUB_RUN_ID:-unknown}.zip"
  
  # When going through PSE proxy, we need elevated permissions
  # Try to use PAT first, fall back to GITHUB_TOKEN
  if [ -n "$GITHUB_PAT" ]; then
    log "Using provided GITHUB_PAT for authentication"
    TOKEN_TO_USE="$GITHUB_PAT"
  else
    log "Using default GITHUB_TOKEN for authentication"
    TOKEN_TO_USE="$GITHUB_TOKEN"
  fi

  # Ensure we have the repository information
  if [ -z "$GITHUB_REPOSITORY" ]; then
    log "ERROR: GITHUB_REPOSITORY environment variable is not set"
    DOWNLOADED_LOG_ZIP_FILE=""
    return 1
  fi

  # Log context for debugging
  log "Debug: GitHub Context:"
  log "- Repository: $GITHUB_REPOSITORY"
  log "- Run ID: $GITHUB_RUN_ID"
  log "- Token Type: ${TOKEN_TO_USE:0:4}... (truncated)"

  # Construct and validate the API URL
  GITHUB_API_LOG_URL="https://api.github.com/repos/${GITHUB_REPOSITORY}/actions/runs/${GITHUB_RUN_ID}/logs"
  log "Debug: API URL components:"
  log "- Base: https://api.github.com/repos"
  log "- Repository: ${GITHUB_REPOSITORY}"
  log "- Run ID: ${GITHUB_RUN_ID}"
  log "- Full URL: ${GITHUB_API_LOG_URL}"

  # Add a delay to allow GitHub API to make logs available
  log "Waiting 30 seconds for logs to become available..."
  sleep 30

  log "Attempting to download workflow run logs from GitHub API: $GITHUB_API_LOG_URL"

  # Ensure we have a token available
  if [ -z "$TOKEN_TO_USE" ]; then
    log "WARNING: No token available. Cannot download logs from GitHub API."
    DOWNLOADED_LOG_ZIP_FILE="" # Ensure we don't try to send a non-existent file
  else
    # Download the log archive
    # -L follows redirects, -o saves to file
    # Headers for authentication and API versioning
    log "Downloading logs to $DOWNLOADED_LOG_ZIP_FILE..."
    # First try to get the error message without saving to file
    ERROR_RESPONSE=$(curl -v -L \
      -H "Accept: application/vnd.github+json" \
      -H "Authorization: Bearer $TOKEN_TO_USE" \
      -H "X-GitHub-Api-Version: 2022-11-28" \
      "$GITHUB_API_LOG_URL" 2>/tmp/curl_error.log)
    
    log "GitHub API Response:"
    echo "$ERROR_RESPONSE"
    
    log "Curl error output:"
    cat /tmp/curl_error.log
    
    # Log proxy environment for debugging
    log "Proxy environment:"
    env | grep -i proxy || echo "No proxy environment variables set"
    
    # Now attempt the actual download
    API_RESPONSE_CODE=$(curl -v -L \
      -H "Accept: application/vnd.github+json" \
      -H "Authorization: Bearer $TOKEN_TO_USE" \
      -H "X-GitHub-Api-Version: 2022-11-28" \
      -o "$DOWNLOADED_LOG_ZIP_FILE" \
      -w "%{http_code}" \
      "$GITHUB_API_LOG_URL" 2>&1 | tee /tmp/curl_output.log)
    
    log "Download attempt curl output:"
    cat /tmp/curl_output.log

    if [ "$API_RESPONSE_CODE" = "200" ] && [ -f "$DOWNLOADED_LOG_ZIP_FILE" ] && [ -s "$DOWNLOADED_LOG_ZIP_FILE" ]; then
      log "Successfully downloaded workflow logs from GitHub API (HTTP $API_RESPONSE_CODE). Archive: $DOWNLOADED_LOG_ZIP_FILE"
    elif [ "$API_RESPONSE_CODE" = "302" ]; then # Check if it's a redirect that curl -L should have handled
        log "Received HTTP 302, curl -L should have followed. Checking if file was downloaded."
        if [ -f "$DOWNLOADED_LOG_ZIP_FILE" ] && [ -s "$DOWNLOADED_LOG_ZIP_FILE" ]; then
            log "Log archive downloaded successfully after redirect. Archive: $DOWNLOADED_LOG_ZIP_FILE"
        else
            log "WARNING: Failed to download logs after redirect or file is empty (HTTP $API_RESPONSE_CODE). File: $DOWNLOADED_LOG_ZIP_FILE"
            DOWNLOADED_LOG_ZIP_FILE=""
        fi
    else
      log "WARNING: Failed to download logs from GitHub API (HTTP $API_RESPONSE_CODE). See curl output above if any."
      # Clean up potentially empty or partial file
      rm -f "$DOWNLOADED_LOG_ZIP_FILE"
      DOWNLOADED_LOG_ZIP_FILE=""
    fi
  fi
  # --- End GitHub API Log Download ---
  
  # Build parameters
  # Build parameters for the curl command to InvisiRisk
  params_data=(
    -F "id=$(url_encode "$SCAN_ID")"
    -F "build_url=$(url_encode "$build_url")"
    -F "status=$(url_encode "${INPUT_JOB_STATUS:-unknown}")"
  )
  
  # Add log file to curl command if download was successful
  if [ -n "$DOWNLOADED_LOG_ZIP_FILE" ] && [ -f "$DOWNLOADED_LOG_ZIP_FILE" ]; then
    log "Preparing to send downloaded log archive $DOWNLOADED_LOG_ZIP_FILE with the end signal."
    params_data+=(-F "build_logs=@$DOWNLOADED_LOG_ZIP_FILE")
  else
    log "No GitHub log archive will be sent (download failed or was skipped)."
  fi

  log "Sending end signal to PSE with parameters and potentially logs."

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
      "${params_data[@]}" \
      -k --tlsv1.2 --insecure \
      --connect-timeout 5 \
      --retry 3 --retry-delay 2 --max-time 10 \
      -s -w "\n%{http_code}" 2>&1)

    echo "Response: $RESPONSE"
    
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
  
  # Check if container exists or existed, but this is a non critical error
  if ! sudo docker ps -a -q -f name="$container_name" > /dev/null 2>&1; then
    log "Container $container_name not found, cannot display logs"
    return 0
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
  
  # Remove PSE certificate from the Ubuntu CA store
  if [ -f /usr/local/share/ca-certificates/extra/pse.crt ]; then
    log "Removing PSE certificate from CA store"
    run_with_privilege rm -f /usr/local/share/ca-certificates/extra/pse.crt
    log "Running update-ca-certificates"
    run_with_privilege update-ca-certificates --fresh
    log "PSE certificate removed"
  elif [ -f /etc/ssl/certs/pse.pem ]; then
    # Backward compatibility for old installations
    log "Removing legacy PSE certificate"
    run_with_privilege rm -f /etc/ssl/certs/pse.pem
    run_with_privilege update-ca-certificates --fresh
    log "Legacy PSE certificate removed"
  else
    log "No PSE certificate found to clean up"
  fi
  
  # Reset Git SSL configuration
  git config --global --unset http.sslCAInfo || true
  
  # Clean up environment variables
  unset NODE_EXTRA_CA_CERTS
  unset REQUESTS_CA_BUNDLE

   # Re-enable IPv6 if it was disabled
  log "Re-enabling IPv6"
  run_with_privilege sysctl -w net.ipv6.conf.all.disable_ipv6=0
  run_with_privilege sysctl -w net.ipv6.conf.default.disable_ipv6=0
  run_with_privilege sysctl -w net.ipv6.conf.lo.disable_ipv6=0
  
  log "Certificate cleanup completed"
}

# Main execution
main() {
  log "Starting PSE GitHub Action cleanup"
  
  # Validate environment variables
  #validate_env_vars
  
  # Determine if we're in a containerized environment
  IS_CONTAINERIZED=false
  if [ -n "$PSE_PROXY_HOSTNAME" ]; then
    log "Detected containerized build environment using hostname: $PSE_PROXY_HOSTNAME"
    IS_CONTAINERIZED=true
  fi

   # Display PSE binary logs if we're using the binary setup mode
  if [ -n "$PSE_LOG_FILE" ]; then
    display_pse_binary_logs
  fi
  
  # Signal build end to InvisiRisk API
  signal_build_end

 
  
  # Only display container logs and clean up container if not in a containerized environment
  # In a containerized environment, the PSE container is managed by GitHub Actions as a service container
  if [ "$IS_CONTAINERIZED" = "false" ]; then
    # Display container logs before cleanup
    display_container_logs "pse"
    
    # Clean up container
    cleanup_pse_container
  else
    log "Skipping container cleanup in containerized environment"
    log "The service container will be automatically cleaned up by GitHub Actions"
  fi
  
  # Always clean up iptables and certificates
  cleanup_iptables
  cleanup_certificates
  
  log "PSE GitHub Action cleanup completed successfully"
}

# Execute main function
main
