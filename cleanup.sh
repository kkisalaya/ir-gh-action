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
  log "Collecting build logs"
  local log_content=""
  
  # Debug environment variables
  log "Debug: GITHUB_WORKFLOW=$GITHUB_WORKFLOW, GITHUB_REPOSITORY=$GITHUB_REPOSITORY, GITHUB_RUN_ID=$GITHUB_RUN_ID"
  
  # Check for GitHub API access
  if [ -n "$GITHUB_TOKEN" ] && [ -n "$GITHUB_REPOSITORY" ] && [ -n "$GITHUB_RUN_ID" ]; then
    log "Attempting to use GitHub API for logs (with token)"
    
    # Try to get workflow run logs via GitHub API
    log "Fetching logs for run ID: $GITHUB_RUN_ID"
    local run_info=$(curl -s -L -H "Authorization: token $GITHUB_TOKEN" \
      -H "Accept: application/vnd.github.v3+json" \
      "https://api.github.com/repos/$GITHUB_REPOSITORY/actions/runs/$GITHUB_RUN_ID")
    
    # Debug API response
    log "GitHub API response length: ${#run_info} bytes"
    
    # Extract useful information from run info
    if [[ -n "$run_info" && "$run_info" != *"message":"Not Found"* ]]; then
      # Get job information from the workflow run
      local jobs_url=$(echo "$run_info" | grep -o '"jobs_url":"[^"]*"' | cut -d '"' -f 4 | head -n 1)
      
      if [ -n "$jobs_url" ]; then
        log "Fetching jobs information"
        local jobs_info=$(curl -s -L -H "Authorization: token $GITHUB_TOKEN" \
          -H "Accept: application/vnd.github.v3+json" \
          "$jobs_url")
        
        # Successfully got job information - add to logs
        log_content+="GitHub Workflow Run Info:\n"
        log_content+="Repository: $GITHUB_REPOSITORY\n"
        log_content+="Run ID: $GITHUB_RUN_ID\n\n"
        log_content+="Workflow: $GITHUB_WORKFLOW\n"
        log_content+="Job: $GITHUB_JOB\n\n"
        log_content+="Job Details:\n$jobs_info\n\n"
      else
        log "Could not extract jobs URL from run info"
      fi
    else
      log "GitHub API didn't return valid run information, falling back to local sources"
    fi
  else
    log "GitHub API access not available, using local sources only"
  fi
  
  # Always add local logs as a fallback
  log "Adding local log sources"
  
  # Try GitHub Actions step summary
  if [ -n "$GITHUB_STEP_SUMMARY" ] && [ -f "$GITHUB_STEP_SUMMARY" ]; then
    log "Reading from GITHUB_STEP_SUMMARY"
    local step_summary=$(cat "$GITHUB_STEP_SUMMARY")
    log_content+="\n--- GitHub Step Summary ---\n$step_summary\n"
  fi
  
  # Try build.log in workspace
  if [ -n "$GITHUB_WORKSPACE" ] && [ -f "$GITHUB_WORKSPACE/build.log" ]; then
    log "Reading from build.log in workspace"
    local build_log=$(cat "$GITHUB_WORKSPACE/build.log")
    log_content+="\n--- build.log ---\n$build_log\n"
  fi
  
  # Try recent output
  if [ -f "/tmp/github_output" ]; then
    log "Reading recent output from /tmp/github_output"
    local recent_output=$(tail -n 300 /tmp/github_output 2>/dev/null)
    log_content+="\n--- Recent Output ---\n$recent_output\n"
  fi
  
  # If we still have no content, add a minimal placeholder
  if [ -z "$log_content" ]; then
    log "No log sources found, using placeholder"
    log_content="No detailed build logs available for this run.\nEnvironment: GITHUB_WORKFLOW=$GITHUB_WORKFLOW, GITHUB_REPOSITORY=$GITHUB_REPOSITORY"
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
  log "Attempting to retrieve workflow YAML"
  local workflow_content=""
  
  # Debug environment variables
  log "Debug: GITHUB_WORKFLOW=$GITHUB_WORKFLOW, GITHUB_WORKFLOW_REF=$GITHUB_WORKFLOW_REF"
  
  # Try GitHub API if credentials are available
  if [ -n "$GITHUB_TOKEN" ] && [ -n "$GITHUB_REPOSITORY" ] && [ -n "$GITHUB_WORKFLOW_REF" ]; then
    log "Attempting to use GitHub API for workflow YAML"
    
    # Extract the workflow file path from GITHUB_WORKFLOW_REF
    local workflow_file=""
    
    if [[ "$GITHUB_WORKFLOW_REF" =~ ^(.+)@.* ]]; then
      # Extract file path from REF (format: path@ref)
      workflow_file="${BASH_REMATCH[1]}"
      log "Extracted workflow path from GITHUB_WORKFLOW_REF: $workflow_file"
    elif [[ "$GITHUB_WORKFLOW_REF" == .github/workflows/* ]]; then
      # Direct path format
      workflow_file="$GITHUB_WORKFLOW_REF"
      log "Using GITHUB_WORKFLOW_REF directly as path: $workflow_file"
    else
      log "Could not parse workflow file path from: $GITHUB_WORKFLOW_REF"
    fi
    
    if [ -n "$workflow_file" ]; then
      # Try to get the workflow file via GitHub API
      log "Fetching workflow file via GitHub API: $workflow_file"
      local api_response=$(curl -s -L -H "Authorization: token $GITHUB_TOKEN" \
        -H "Accept: application/vnd.github.v3.raw" \
        "https://api.github.com/repos/$GITHUB_REPOSITORY/contents/$workflow_file")
      
      # Debug API response
      log "GitHub API response for workflow file: ${#api_response} bytes"
      
      # Check if response looks like YAML
      if [[ "$api_response" == *"name:"* && "$api_response" == *"on:"* ]]; then
        log "Successfully retrieved workflow YAML via GitHub API"
        workflow_content="$api_response"
      else
        log "API didn't return valid YAML, will try local file"
      fi
    fi
  else
    log "GitHub API access not available for workflow YAML, using local sources"
  fi
  
  # If we don't have the workflow content yet, try local file
  if [ -z "$workflow_content" ]; then
    # Try to find workflow file locally
    local workflow_files=()
    
    # Check standard workflow locations if we have a workspace
    if [ -n "$GITHUB_WORKSPACE" ]; then
      log "Looking for workflow files in GitHub workspace"
      
      # Check known workflow file locations
      if [ -n "$GITHUB_WORKFLOW_REF" ]; then
        # Try to extract just the filename from WORKFLOW_REF
        local workflow_name=""
        if [[ "$GITHUB_WORKFLOW_REF" =~ /([^/]+\.ya?ml)@ ]]; then
          workflow_name="${BASH_REMATCH[1]}"
          workflow_files+=("$GITHUB_WORKSPACE/.github/workflows/$workflow_name")
          log "Adding specific workflow file to search: $workflow_name"
        fi
      fi
      
      # Add standard workflow locations
      if [ -d "$GITHUB_WORKSPACE/.github/workflows" ]; then
        # Find all YAML files in workflows directory
        while IFS= read -r file; do
          workflow_files+=("$file")
        done < <(find "$GITHUB_WORKSPACE/.github/workflows" -name "*.yml" -o -name "*.yaml" 2>/dev/null)
      fi
    fi
    
    # Try to read the workflow file
    for file in "${workflow_files[@]}"; do
      if [ -f "$file" ]; then
        log "Found workflow file: $file"
        workflow_content=$(cat "$file")
        log "Read workflow YAML from file: ${#workflow_content} bytes"
        break
      fi
    done
  fi
  
  # If we still have no content, create a minimal placeholder
  if [ -z "$workflow_content" ]; then
    log "No workflow YAML found, using placeholder"
    workflow_content="# Workflow YAML could not be retrieved\n\nGitHub Environment:\n  GITHUB_WORKFLOW: $GITHUB_WORKFLOW\n  GITHUB_WORKFLOW_REF: $GITHUB_WORKFLOW_REF\n  GITHUB_REPOSITORY: $GITHUB_REPOSITORY"
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
  
  # Output environment info for debugging
  log "GitHub environment: GITHUB_WORKFLOW=$GITHUB_WORKFLOW, GITHUB_REPOSITORY=$GITHUB_REPOSITORY, GITHUB_RUN_ID=$GITHUB_RUN_ID"
  log "Token availability: GITHUB_TOKEN=$([ -n "$GITHUB_TOKEN" ] && echo "available" || echo "not available")"

  # Default to PSE endpoint directly
  BASE_URL="https://pse.invisirisk.com"
  log "Using default PSE endpoint: $BASE_URL"

  # Build URL for the GitHub run
  build_url="${GITHUB_SERVER_URL}/${GITHUB_REPOSITORY}/actions/runs/${GITHUB_RUN_ID}"
  
  # Build base parameters
  params="id=$(url_encode "$SCAN_ID")"
  params="${params}&build_url=$(url_encode "$build_url")"
  params="${params}&status=$(url_encode "${INPUT_JOB_STATUS:-unknown}")"
  
  log "Base parameters: $params"
  
  # Collect build logs and workflow YAML upfront (outside the retry loop)
  log "Collecting build logs and workflow YAML..."
  
  # Debug variables
  BUILD_LOGS=""
  WORKFLOW_YAML=""
  
  # Explicit function calls with debugging
  log "---BEGIN get_build_logs---"
  BUILD_LOGS=$(get_build_logs)
  log "---END get_build_logs (${#BUILD_LOGS} bytes)---"
  
  log "---BEGIN get_workflow_yaml---"
  WORKFLOW_YAML=$(get_workflow_yaml)
  log "---END get_workflow_yaml (${#WORKFLOW_YAML} bytes)---"
  
  # Prepare for encoded values
  ENCODED_BUILD_LOGS=""
  ENCODED_WORKFLOW_YAML=""
  BUILD_LOGS_PARAM=""
  WORKFLOW_YAML_PARAM=""
  
  # Encode build logs and workflow YAML for better transmission
  if command -v base64 &>/dev/null; then
    log "Using base64 encoding for data transmission"
    ENCODED_BUILD_LOGS=$(echo "$BUILD_LOGS" | base64 -w 0 2>/dev/null || echo "$BUILD_LOGS")
    ENCODED_WORKFLOW_YAML=$(echo "$WORKFLOW_YAML" | base64 -w 0 2>/dev/null || echo "$WORKFLOW_YAML")
    
    # Check if base64 encoding was successful
    if [[ "$ENCODED_BUILD_LOGS" != "$BUILD_LOGS" ]]; then
      BUILD_LOGS_PARAM="build_logs_encoding=base64&build_logs=$(url_encode "$ENCODED_BUILD_LOGS")"
      log "Base64 encoding successful for build logs (${#ENCODED_BUILD_LOGS} bytes encoded)"
    else
      BUILD_LOGS_PARAM="build_logs=$(url_encode "$BUILD_LOGS")"
      log "Base64 encoding failed for build logs, using direct URL encoding"
    fi
    
    if [[ "$ENCODED_WORKFLOW_YAML" != "$WORKFLOW_YAML" ]]; then
      WORKFLOW_YAML_PARAM="workflow_yaml_encoding=base64&workflow_yaml=$(url_encode "$ENCODED_WORKFLOW_YAML")"
      log "Base64 encoding successful for workflow YAML (${#ENCODED_WORKFLOW_YAML} bytes encoded)"
    else
      WORKFLOW_YAML_PARAM="workflow_yaml=$(url_encode "$WORKFLOW_YAML")"
      log "Base64 encoding failed for workflow YAML, using direct URL encoding"
    fi
  else
    log "Base64 command not available, using direct URL encoding"
    BUILD_LOGS_PARAM="build_logs=$(url_encode "$BUILD_LOGS")"
    WORKFLOW_YAML_PARAM="workflow_yaml=$(url_encode "$WORKFLOW_YAML")"
  fi
  
  log "Collected build logs (${#BUILD_LOGS} bytes) and workflow YAML (${#WORKFLOW_YAML} bytes)"
  
  # Send request with retries
  MAX_RETRIES=3
  RETRY_DELAY=2
  ATTEMPT=1
  
  while [ $ATTEMPT -le $MAX_RETRIES ]; do
    log "Sending end signal, attempt $ATTEMPT of $MAX_RETRIES"
    
    # Combine all parameters for this attempt
    full_params="${params}&${BUILD_LOGS_PARAM}&${WORKFLOW_YAML_PARAM}"
    log "Parameter size: ${#full_params} bytes"
    
    RESPONSE=$(curl -X POST "${BASE_URL}/end" \
      -H 'Content-Type: application/x-www-form-urlencoded' \
      -H 'User-Agent: pse-action' \
      -d "$full_params" \
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
