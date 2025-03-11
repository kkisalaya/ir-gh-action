#!/bin/bash
# PSE GitHub Action - Intercept Script
# This script configures iptables and certificates for HTTPS interception

# Enable strict error handling
set -e

# Enable debug mode if requested or forced
if [ "$DEBUG" = "true" ] || [ "$DEBUG_FORCE" = "true" ]; then
  DEBUG="true"
  export DEBUG
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

# Validate required environment variables
validate_env_vars() {
  local required_vars=("SCAN_ID")
  
  for var in "${required_vars[@]}"; do
    if [ -z "${!var}" ]; then
      log "ERROR: Required environment variable $var is not set"
      exit 1
    fi
  done
  
  log "Environment validation successful"
}

# Function to discover the PSE proxy container IP
discover_pse_proxy_ip() {
  # Redirect all log messages to stderr so they don't get captured in the function output
  log "Attempting to discover PSE proxy container IP" >&2
  local discovered_ip=""
  
  # Try to find the container by image name
  log "Looking for PSE proxy container by image..." >&2
  local pse_containers=$(run_with_privilege docker ps --filter "ancestor=invisirisk/pse-proxy" --format "{{.Names}}" 2>/dev/null || echo "")
  
  # If not found, try with ECR path
  if [ -z "$pse_containers" ]; then
    log "Trying with ECR path..." >&2
    pse_containers=$(run_with_privilege docker ps --filter "ancestor=282904853176.dkr.ecr.us-west-2.amazonaws.com/invisirisk/pse-proxy" --format "{{.Names}}" 2>/dev/null || echo "")
  fi
  
  # If still not found, try with any available registry ID and region
  if [ -z "$pse_containers" ] && [ -n "$ECR_REGISTRY_ID" ] && [ -n "$ECR_REGION" ]; then
    log "Trying with provided ECR registry ID and region..." >&2
    pse_containers=$(run_with_privilege docker ps --filter "ancestor=$ECR_REGISTRY_ID.dkr.ecr.$ECR_REGION.amazonaws.com/invisirisk/pse-proxy" --format "{{.Names}}" 2>/dev/null || echo "")
  fi
  
  # If containers found, get the IP of the first one
  if [ -n "$pse_containers" ]; then
    local container_name=$(echo "$pse_containers" | head -n 1)
    log "Found PSE proxy container: $container_name" >&2
    discovered_ip=$(run_with_privilege docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$container_name" 2>/dev/null || echo "")
    log "Discovered PSE proxy IP: $discovered_ip" >&2
  else
    log "No PSE proxy containers found by image name" >&2
  fi
  
  # Only output the IP address, nothing else
  echo "$discovered_ip"
}

# Function to set up iptables rules
setup_iptables() {
  log "Setting up iptables rules"
  
  # Check if in test mode
  if [ "$TEST_MODE" = "true" ]; then
    log "Running in TEST_MODE, skipping iptables setup"
    return 0
  fi
  
  # Configure iptables rules
  local proxy_port=12345
  local target_ip
  
  # Always use the specific approach to get the proxy's IP
  log "Getting PSE proxy container IP using container name from docker ps"
  
  # Get the container name for the PSE proxy
  CONTAINER_NAME=$(run_with_privilege docker ps --filter "ancestor=282904853176.dkr.ecr.us-west-2.amazonaws.com/invisirisk/pse-proxy:latest" --format "{{.Names}}")
  
  if [ -n "$CONTAINER_NAME" ]; then
    log "Found PSE proxy container: $CONTAINER_NAME"
    
    # Get the IP address from the container
    PSE_IP=$(run_with_privilege docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$CONTAINER_NAME")
    
    if [ -n "$PSE_IP" ]; then
      log "Successfully obtained PSE proxy IP: $PSE_IP"
      # Override any existing PROXY_IP with the discovered one
      export PROXY_IP="$PSE_IP"
      echo "PSE_PROXY_IP=$PSE_IP" >> $GITHUB_ENV
      log "Using discovered proxy IP: $PSE_IP"
    else
      log "Warning: Could not get IP address from container $CONTAINER_NAME"
    fi
  else
    log "Warning: Could not find PSE proxy container"
  fi
  
  # Check if we're using hostname instead of IP
  if [ -n "$PROXY_HOSTNAME" ]; then
    log "Using proxy hostname: $PROXY_HOSTNAME"
    
    # Try to resolve hostname to IP if possible
    if command -v getent > /dev/null 2>&1; then
      RESOLVED_IP=$(getent hosts $PROXY_HOSTNAME | awk '{ print $1 }' | head -n 1)
      if [ -n "$RESOLVED_IP" ]; then
        log "Resolved $PROXY_HOSTNAME to IP: $RESOLVED_IP"
        target_ip="$RESOLVED_IP"
      else
        log "Could not resolve hostname to IP, using PROXY_IP if available"
        target_ip="$PROXY_IP"
      fi
    else
      log "getent not available, using PROXY_IP if available"
      target_ip="$PROXY_IP"
    fi
  else
    # Use the provided PROXY_IP
    target_ip="$PROXY_IP"
    log "Using provided proxy IP for iptables: $target_ip"
  fi
  
  # Double check that target_ip is actually set
  if [ -z "$target_ip" ]; then
    log "ERROR: Could not determine target IP for iptables!"
    log "Here are the available environment variables that might help debug:"
    env | grep -E 'PROXY|PSE|GITHUB_' || true
    log "Check that you're passing either proxy_ip or proxy_hostname correctly"
    exit 1
  fi
  
  # Set up iptables rules to redirect HTTPS traffic to the PSE proxy
  log "Setting up iptables rules to redirect HTTPS traffic to $target_ip:$proxy_port"
  
  # Check if iptables is available
  if ! command -v iptables >/dev/null 2>&1; then
    log "iptables not found, installing..."
    
    # Install iptables based on the available package manager
    if command -v apt-get >/dev/null 2>&1; then
      run_with_privilege apt-get update
      run_with_privilege apt-get install -y iptables
    elif command -v yum >/dev/null 2>&1; then
      run_with_privilege yum install -y iptables
    else
      log "ERROR: Unsupported package manager. Please install iptables manually."
      exit 1
    fi
  fi
  
  # Add iptables rules
  run_with_privilege iptables -t nat -A OUTPUT -p tcp --dport 443 -j DNAT --to-destination "$target_ip:$proxy_port"
  run_with_privilege iptables -t nat -A POSTROUTING -j MASQUERADE
  
  log "iptables rules set up successfully"
}

# Function to set up certificates
setup_certificates() {
  log "Setting up certificates"
  
  # Check if in test mode
  if [ "$TEST_MODE" = "true" ]; then
    log "Running in TEST_MODE, skipping certificate setup"
    return 0
  fi
  
  # Determine certificate endpoint
  local cert_endpoint
  local cert_host
  
  if [ -n "$PROXY_HOSTNAME" ]; then
    cert_host="$PROXY_HOSTNAME"
  else
    cert_host="$PROXY_IP"
  fi
  
  cert_endpoint="http://$cert_host:12345/cert"
  log "Getting certificate from $cert_endpoint"
  
  # Create certificate directory
  local cert_dir="/usr/local/share/ca-certificates"
  run_with_privilege mkdir -p "$cert_dir"
  
  # Download certificate
  local cert_file="$cert_dir/pse-ca.crt"
  run_with_privilege curl -s -o "$cert_file" "$cert_endpoint"
  
  # Check if certificate was downloaded successfully
  if [ ! -s "$cert_file" ]; then
    log "ERROR: Failed to download certificate from $cert_endpoint"
    log "Trying alternative methods..."
    
    # Try alternative methods to get the certificate
    run_with_privilege curl -s -o "$cert_file" "http://$cert_host:12345/cert"
    
    if [ ! -s "$cert_file" ]; then
      log "ERROR: All certificate download attempts failed"
      exit 1
    fi
  fi
  
  # Update CA certificates
  if command -v update-ca-certificates >/dev/null 2>&1; then
    run_with_privilege update-ca-certificates
  elif command -v update-ca-trust >/dev/null 2>&1; then
    run_with_privilege update-ca-trust
  else
    log "WARNING: Could not update CA certificates. Certificate may not be trusted."
  fi
  
  # Set up certificate for Python
  if command -v python3 >/dev/null 2>&1; then
    log "Setting up certificate for Python"
    
    # Create Python certificate directory
    local python_cert_dir="/etc/python/cert"
    run_with_privilege mkdir -p "$python_cert_dir"
    
    # Copy certificate to Python directory
    run_with_privilege cp "$cert_file" "$python_cert_dir/pse-ca.pem"
    
    # Set Python certificate environment variable
    echo "REQUESTS_CA_BUNDLE=$python_cert_dir/pse-ca.pem" >> $GITHUB_ENV
    echo "SSL_CERT_FILE=$python_cert_dir/pse-ca.pem" >> $GITHUB_ENV
  fi
  
  # Set up certificate for Node.js
  if command -v node >/dev/null 2>&1; then
    log "Setting up certificate for Node.js"
    
    # Set Node.js certificate environment variable
    echo "NODE_EXTRA_CA_CERTS=$cert_file" >> $GITHUB_ENV
  fi
  
  log "Certificates set up successfully"
}

# Main function
main() {
  log "Starting PSE GitHub Action intercept mode"
  
  validate_env_vars
  setup_iptables
  setup_certificates
  
  log "Intercept mode completed successfully"
  log "HTTPS traffic is now being intercepted by the PSE proxy"
}

# Execute main function
main
