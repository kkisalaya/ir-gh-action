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
  local strlen=${#string}
  local encoded=""
  local pos c o
  
  for (( pos=0; pos<strlen; pos++ )); do
    c=${string:$pos:1}
    case "$c" in
      [-_.~a-zA-Z0-9] ) o="$c" ;;
      * )               o=$(printf '%%%02X' "'$c") ;;
    esac
    encoded+="$o"
  done
  echo "$encoded"
}

# Function to get build logs
get_build_logs() {
  log "Collecting build logs using GitHub API"
  local log_content=""
  
  # Check for GitHub Actions environment
  if [ -n "$GITHUB_WORKFLOW" ] && [ -n "$GITHUB_REPOSITORY" ] && [ -n "$GITHUB_RUN_ID" ] && [ -n "$GITHUB_TOKEN" ]; then
    log "Using GitHub API to fetch build logs for run ID: $GITHUB_RUN_ID"
    
    # Use GitHub API to get logs from the current workflow run
    local api_response=$(curl -s -H "Authorization: token $GITHUB_TOKEN" \
      -H "Accept: application/vnd.github.v3+json" \
      "https://api.github.com/repos/$GITHUB_REPOSITORY/actions/runs/$GITHUB_RUN_ID/logs")
    
    # Check if we got a redirect URL for downloading logs (GitHub returns a download URL)
    if [[ "$api_response" == *"Message":* ]] || [[ "$api_response" == *"message":* ]]; then
      log "Error fetching logs: $api_response"
      log_content="Error fetching logs from GitHub API: $api_response"
    else
      # Get logs from the current job steps
      log "Fetching current job logs"
      local job_logs=$(curl -s -H "Authorization: token $GITHUB_TOKEN" \
        -H "Accept: application/vnd.github.v3+json" \
        "https://api.github.com/repos/$GITHUB_REPOSITORY/actions/jobs/$GITHUB_JOB/steps")
      
      # Extract relevant logs
      log_content="GitHub Workflow Run ID: $GITHUB_RUN_ID\nJob ID: $GITHUB_JOB\n\n$job_logs\n\n"
      
      # Add recent output as additional context
      if [ -f "/tmp/github_output" ]; then
        log_content+="\n--- Recent Output ---\n$(tail -n 200 /tmp/github_output 2>/dev/null)"
      fi
    fi
  else
    # Fallback for non-GitHub environments or missing required variables
    log "GitHub environment variables missing, collecting available logs"
    log_content="Build logs not available: Missing required GitHub environment variables"
    
    # Add environment details
    log_content+="\n\nEnvironment: GITHUB_WORKFLOW=$GITHUB_WORKFLOW, GITHUB_REPOSITORY=$GITHUB_REPOSITORY, GITHUB_RUN_ID=$GITHUB_RUN_ID"
    
    # Try to get some local logs as fallback
    if [ -f "/tmp/github_output" ]; then
      log_content+="\n\n--- Local Logs ---\n$(tail -n 500 /tmp/github_output 2>/dev/null)"
    fi
  fi
  
  # Limit log size to avoid exceeding request limits
  local max_log_size=100000
  if [ ${#log_content} -gt $max_log_size ]; then
    log "Truncating oversized build logs (${#log_content} bytes)"
    log_content="${log_content:0:$max_log_size}...\n[Log truncated due to size]"
  fi
  
  echo "$log_content"
}

# Function to get workflow YAML
get_workflow_yaml() {
  log "Attempting to retrieve workflow YAML using GitHub API"
  local workflow_content=""
  
  # Check for GitHub Actions environment and required variables
  if [ -n "$GITHUB_WORKFLOW" ] && [ -n "$GITHUB_REPOSITORY" ] && [ -n "$GITHUB_TOKEN" ] && [ -n "$GITHUB_WORKFLOW_REF" ]; then
    # Extract the workflow file path from GITHUB_WORKFLOW_REF
    local workflow_file=""
    local workflow_ref="$GITHUB_WORKFLOW_REF"
    
    log "GITHUB_WORKFLOW_REF: $workflow_ref"
    
    # Extract workflow file path from GITHUB_WORKFLOW_REF
    if [[ "$workflow_ref" =~ ^([^@]+) ]]; then
      workflow_file="${BASH_REMATCH[1]}"
      log "Extracted workflow file path: $workflow_file"
      
      # Use GitHub API to get the workflow file content
      log "Fetching workflow file content from GitHub API"
      local api_response=$(curl -s -H "Authorization: token $GITHUB_TOKEN" \
        -H "Accept: application/vnd.github.v3.raw" \
        "https://api.github.com/repos/$GITHUB_REPOSITORY/contents/$workflow_file")
      
      # Check if we got valid content
      if [[ "$api_response" == *"Message":* ]] || [[ "$api_response" == *"message":* ]]; then
        log "Error fetching workflow file: $api_response"
        
        # Fallback to local file if available
        if [ -n "$GITHUB_WORKSPACE" ] && [ -f "$GITHUB_WORKSPACE/$workflow_file" ]; then
          log "Falling back to local workflow file: $GITHUB_WORKSPACE/$workflow_file"
          workflow_content=$(cat "$GITHUB_WORKSPACE/$workflow_file")
        else
          workflow_content="Error fetching workflow YAML from GitHub API: $api_response"
        fi
      else
        workflow_content="$api_response"
      fi
    else
      log "Could not parse workflow file from GITHUB_WORKFLOW_REF: $workflow_ref"
      
      # Try to find workflow file from run information
      log "Attempting to get workflow from run information"
      local run_info=$(curl -s -H "Authorization: token $GITHUB_TOKEN" \
        -H "Accept: application/vnd.github.v3+json" \
        "https://api.github.com/repos/$GITHUB_REPOSITORY/actions/runs/$GITHUB_RUN_ID")
      
      # Extract workflow path from run info
      local path_from_run=$(echo "$run_info" | grep -o '\"path\":\"[^\"]*\"' | cut -d '\"' -f 4)
      
      if [ -n "$path_from_run" ]; then
        log "Found workflow path from run info: $path_from_run"
        
        # Get workflow content
        workflow_content=$(curl -s -H "Authorization: token $GITHUB_TOKEN" \
          -H "Accept: application/vnd.github.v3.raw" \
          "https://api.github.com/repos/$GITHUB_REPOSITORY/contents/$path_from_run")
      else
        workflow_content="Could not determine workflow file path"
      fi
    fi
  else
    # Fallback for non-GitHub environments or missing required variables
    log "GitHub environment variables missing, cannot retrieve workflow YAML"
    workflow_content="Workflow YAML not available: Missing required GitHub environment variables"
    
    # Add environment details
    workflow_content+="\n\nEnvironment: GITHUB_WORKFLOW=$GITHUB_WORKFLOW, GITHUB_REPOSITORY=$GITHUB_REPOSITORY, GITHUB_WORKFLOW_REF=$GITHUB_WORKFLOW_REF"
  fi
  
  # Limit YAML size to avoid exceeding request limits
  local max_yaml_size=50000
  if [ ${#workflow_content} -gt $max_yaml_size ]; then
    log "Truncating oversized workflow YAML (${#workflow_content} bytes)"
    workflow_content="${workflow_content:0:$max_yaml_size}...\n[YAML truncated due to size]"
  fi
  
  echo "$workflow_content"
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
  
  # Build parameters
  params="id=$(url_encode "$SCAN_ID")"
  params="${params}&build_url=$(url_encode "$build_url")"
  params="${params}&status=$(url_encode "${INPUT_JOB_STATUS:-unknown}")"
  
  log "Sending end signal to PSE with parameters: $params"
  
  # Send request with retries
  MAX_RETRIES=3
  RETRY_DELAY=2
  ATTEMPT=1
  
  while [ $ATTEMPT -le $MAX_RETRIES ]; do
    log "Sending end signal, attempt $ATTEMPT of $MAX_RETRIES"
    
    # Collect build logs and workflow YAML
    BUILD_LOGS=$(get_build_logs)
    WORKFLOW_YAML=$(get_workflow_yaml)
    
    # Base64 encode build logs and workflow YAML for better handling of special characters
    ENCODED_BUILD_LOGS=$(echo "$BUILD_LOGS" | base64 -w 0)
    ENCODED_WORKFLOW_YAML=$(echo "$WORKFLOW_YAML" | base64 -w 0)
    
    # Add build logs and workflow YAML to parameters (base64 encoded)
    params="${params}&build_logs_encoding=base64"
    params="${params}&build_logs=$(url_encode "$ENCODED_BUILD_LOGS")"
    params="${params}&workflow_yaml_encoding=base64"
    params="${params}&workflow_yaml=$(url_encode "$ENCODED_WORKFLOW_YAML")"
    
    log "Collected build logs (${#BUILD_LOGS} bytes) and workflow YAML (${#WORKFLOW_YAML} bytes)"
    
    RESPONSE=$(curl -X POST "${BASE_URL}/end" \
      -H 'Content-Type: application/x-www-form-urlencoded' \
      -H 'User-Agent: pse-action' \
      -d "$params" \
      -k --tlsv1.2 --insecure \
      --connect-timeout 5 \
      --retry 3 --retry-delay 2 --max-time 30 \
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
