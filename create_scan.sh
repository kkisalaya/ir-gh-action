#!/bin/bash
# PSE GitHub Action - Create Scan Script
# This script creates a scan in the InvisiRisk Portal and returns the scan ID

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
  echo "ERROR: An error occurred on line $1"
  exit 1
}

# Set up error trap
trap 'error_handler $LINENO' ERR

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

# Install jq if needed
install_jq() {
  if ! command -v jq >/dev/null 2>&1; then
    echo "Installing jq for JSON parsing..."
    if command -v apt-get >/dev/null 2>&1; then
      sudo apt-get update -qq && sudo apt-get install -y jq
    elif command -v apk >/dev/null 2>&1; then
      apk add --no-cache jq
    elif command -v yum >/dev/null 2>&1; then
      sudo yum install -y jq
    else
      echo "Could not install jq, falling back to grep-based parsing"
    fi
  else
    echo "jq is already installed"
  fi
}

# Create scan in InvisiRisk Portal
create_scan() {
  echo "Creating scan in InvisiRisk Portal..."
  
  # Check if API_URL and APP_TOKEN are set
  if [ -z "$API_URL" ]; then
    echo "ERROR: API_URL is not set"
    exit 1
  fi
  
  if [ -z "$APP_TOKEN" ]; then
    echo "ERROR: APP_TOKEN is not set"
    exit 1
  fi
  
  # Create the scan
  SCAN_RESPONSE=$(curl -L -s -X POST "$API_URL/utilityapi/v1/scan" \
    -H "Content-Type: application/json" \
    -d "{\"api_key\": \"$APP_TOKEN\"}")
  
  # Don't print the actual response to avoid GitHub file command issues
  echo "API call completed successfully"
  
  # Check if the response contains an error message
  if echo "$SCAN_RESPONSE" | grep -q '"error"'; then
    echo "Error received from API: $(echo "$SCAN_RESPONSE" | grep -o '"error":"[^"]*' | cut -d'"' -f4)"
    exit 1
  fi
  
  # Try to extract scan_id using parse_json function
  SCAN_ID=$(parse_json "$SCAN_RESPONSE" "scan_id")
  
  # If first pattern fails, try alternative field name
  if [ -z "$SCAN_ID" ]; then
    SCAN_ID=$(parse_json "$SCAN_RESPONSE" "id")
  fi
  
  # If still not found, try to extract from data field
  if [ -z "$SCAN_ID" ]; then
    # Try to extract nested field
    SCAN_ID=$(parse_nested_json "$SCAN_RESPONSE" "data" "scan_id")
  fi
  
  # Try one more field name
  if [ -z "$SCAN_ID" ]; then
    SCAN_ID=$(parse_nested_json "$SCAN_RESPONSE" "data" "id")
  fi
  
  if [ -z "$SCAN_ID" ]; then
    echo "Error: Failed to create scan object or extract scan ID from response"
    exit 1
  fi
  
  echo "Scan object created with ID: $SCAN_ID"
  echo "$SCAN_ID"
}

# Main execution
install_jq
SCAN_ID=$(create_scan)

# Make sure SCAN_ID is exported for other scripts to use
export SCAN_ID="$SCAN_ID"

# Set GitHub environment variable
if [ -n "$GITHUB_ENV" ]; then
  echo "SCAN_ID=$SCAN_ID" >> "$GITHUB_ENV"
fi

# Set GitHub output variable
if [ -n "$GITHUB_OUTPUT" ]; then
  echo "scan_id=$SCAN_ID" >> "$GITHUB_OUTPUT"
fi

# Print success message
echo "Scan created successfully with ID: $SCAN_ID"
