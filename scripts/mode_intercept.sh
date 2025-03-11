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
validate_environment() {
  log "Validating environment variables for intercept mode"
  
  # If PROXY_IP is not set, try to discover it (regardless of whether PROXY_HOSTNAME is set)
  if [ -z "$PROXY_IP" ]; then
    if [ -z "$PROXY_HOSTNAME" ]; then
      log "PROXY_IP or PROXY_HOSTNAME not provided, attempting to discover PSE proxy IP"
    else
      log "PROXY_HOSTNAME provided but PROXY_IP not set, resolving hostname to IP"
    fi
    
    discovered_ip=$(discover_pse_proxy_ip)
    
    if [ -n "$discovered_ip" ]; then
      log "Successfully discovered PSE proxy IP: $discovered_ip"
      export PROXY_IP="$discovered_ip"
      echo "PSE_PROXY_IP=$discovered_ip" >> $GITHUB_ENV
    else
      log "ERROR: Could not discover PSE proxy IP automatically"
      log "Please provide either proxy_ip or proxy_hostname input parameter"
      exit 1
    fi
  fi
  
  # If SCAN_ID is not set and we're not in test mode, fail
  if [ -z "$SCAN_ID" ] && [ "$TEST_MODE" != "true" ]; then
    log "ERROR: SCAN_ID must be provided for intercept mode when not in test mode"
    log "Please provide scan_id input parameter or run in test mode"
    exit 1
  fi
  
  log "Environment validation successful"
}

# Function to discover the PSE proxy container IP
discover_pse_proxy_ip() {
  # Redirect all log messages to stderr so they don't get captured in the function output
  log "Attempting to discover PSE proxy container IP" >&2
  local discovered_ip=""
  
  # First, check if Docker is available
  if command -v docker >/dev/null 2>&1; then
    log "Docker is available, attempting to find PSE proxy container" >&2
    
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
  else
    log "Docker is not available, cannot discover container directly" >&2
  fi
  
  # If we couldn't find the IP using Docker or Docker is not available,
  # try to resolve using hostname as a fallback
  if [ -z "$discovered_ip" ]; then
    log "Attempting to resolve PSE proxy using hostname..." >&2
    
    # Determine which hostname to use - use PROXY_HOSTNAME if provided, otherwise default to 'pse-proxy'
    local hostname_to_try="pse-proxy"
    local alt_hostname="${hostname_to_try}.local"
    
    if [ -n "$PROXY_HOSTNAME" ]; then
      log "Using provided PROXY_HOSTNAME: $PROXY_HOSTNAME" >&2
      hostname_to_try="$PROXY_HOSTNAME"
      alt_hostname=""  # Don't try .local suffix with user-provided hostname
    else
      log "Using default hostname: $hostname_to_try" >&2
    fi
    
    # Try all available hostname resolution methods in sequence until one succeeds
    
    # Method 1: getent
    if command -v getent >/dev/null 2>&1 && [ -z "$discovered_ip" ]; then
      log "Using getent to resolve hostname $hostname_to_try" >&2
      discovered_ip=$(getent hosts "$hostname_to_try" 2>/dev/null | awk '{ print $1 }' | head -n 1)
      
      if [ -n "$discovered_ip" ]; then
        log "Successfully resolved using getent: $discovered_ip" >&2
      elif [ -n "$alt_hostname" ]; then
        # Try with alternative hostname if it exists
        log "Trying alternative hostname with getent: $alt_hostname" >&2
        discovered_ip=$(getent hosts "$alt_hostname" 2>/dev/null | awk '{ print $1 }' | head -n 1)
        if [ -n "$discovered_ip" ]; then
          log "Successfully resolved alternative hostname using getent: $discovered_ip" >&2
        fi
      fi
    fi
    
    # Method 2: host command
    if command -v host >/dev/null 2>&1 && [ -z "$discovered_ip" ]; then
      log "Using host command to resolve hostname $hostname_to_try" >&2
      discovered_ip=$(host -t A "$hostname_to_try" 2>/dev/null | grep "has address" | head -n 1 | awk '{ print $NF }')
      
      if [ -n "$discovered_ip" ]; then
        log "Successfully resolved using host command: $discovered_ip" >&2
      elif [ -n "$alt_hostname" ]; then
        # Try with alternative hostname if it exists
        log "Trying alternative hostname with host command: $alt_hostname" >&2
        discovered_ip=$(host -t A "$alt_hostname" 2>/dev/null | grep "has address" | head -n 1 | awk '{ print $NF }')
        if [ -n "$discovered_ip" ]; then
          log "Successfully resolved alternative hostname using host command: $discovered_ip" >&2
        fi
      fi
    fi
    
    # Method 3: nslookup
    if command -v nslookup >/dev/null 2>&1 && [ -z "$discovered_ip" ]; then
      log "Using nslookup to resolve hostname $hostname_to_try" >&2
      discovered_ip=$(nslookup "$hostname_to_try" 2>/dev/null | grep "Address:" | tail -n 1 | awk '{ print $2 }')
      
      if [ -n "$discovered_ip" ]; then
        log "Successfully resolved using nslookup: $discovered_ip" >&2
      elif [ -n "$alt_hostname" ]; then
        # Try with alternative hostname if it exists
        log "Trying alternative hostname with nslookup: $alt_hostname" >&2
        discovered_ip=$(nslookup "$alt_hostname" 2>/dev/null | grep "Address:" | tail -n 1 | awk '{ print $2 }')
        if [ -n "$discovered_ip" ]; then
          log "Successfully resolved alternative hostname using nslookup: $discovered_ip" >&2
        fi
      fi
    fi
    
    # Method 4: ping (last resort)
    if command -v ping >/dev/null 2>&1 && [ -z "$discovered_ip" ]; then
      log "Using ping to resolve hostname $hostname_to_try" >&2
      discovered_ip=$(ping -c 1 "$hostname_to_try" 2>/dev/null | grep "PING" | head -n 1 | awk -F'[()]' '{ print $2 }')
      
      if [ -n "$discovered_ip" ]; then
        log "Successfully resolved using ping: $discovered_ip" >&2
      elif [ -n "$alt_hostname" ]; then
        # Try with alternative hostname if it exists
        log "Trying alternative hostname with ping: $alt_hostname" >&2
        discovered_ip=$(ping -c 1 "$alt_hostname" 2>/dev/null | grep "PING" | head -n 1 | awk -F'[()]' '{ print $2 }')
        if [ -n "$discovered_ip" ]; then
          log "Successfully resolved alternative hostname using ping: $discovered_ip" >&2
        fi
      fi
    fi
    
    if [ -n "$discovered_ip" ]; then
      log "Successfully resolved PSE proxy IP from hostname: $discovered_ip" >&2
    else
      log "Could not resolve PSE proxy hostname using any available method" >&2
    fi
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
  
  # By this point, PROXY_IP should be set either directly or via discover_pse_proxy_ip
  # in the validate_environment function
  if [ -z "$PROXY_IP" ]; then
    log "ERROR: PROXY_IP is not set. This should not happen as validation should have caught this."
    log "Here are the available environment variables that might help debug:"
    env | grep -E 'PROXY|PSE|GITHUB_' || true
    exit 1
  fi
  
  log "Using proxy IP for iptables: $PROXY_IP"
  
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
  run_with_privilege iptables -t nat -A OUTPUT -p tcp --dport 443 -j DNAT --to-destination "$PROXY_IP:$proxy_port"
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
  
  validate_environment
  setup_iptables
  setup_certificates
  
  log "Intercept mode completed successfully"
  log "HTTPS traffic is now being intercepted by the PSE proxy"
}

# Execute main function
main
