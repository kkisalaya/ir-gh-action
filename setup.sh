#!/bin/bash
# PSE GitHub Action - Setup Script
# This script serves as a dispatcher for the different modes of the PSE GitHub Action

# Enable strict error handling
set -e

# Enable debug mode if requested or forced
if [ "$DEBUG" = "true" ] || [ "$DEBUG_FORCE" = "true" ]; then
  DEBUG="true"
  export DEBUG
  set -x
fi

# Set default mode if not provided
MODE=${MODE:-all}

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

# Validate mode-specific requirements
validate_mode_requirements() {
  log "Validating requirements for mode: $MODE"
  
  case "$MODE" in
    prepare)
      # For prepare mode, api_url and app_token are required
      if [ -z "$API_URL" ] || [ -z "$APP_TOKEN" ]; then
        log "ERROR: api_url and app_token are required for prepare mode"
        exit 1
      fi
      ;;
      
    setup)
      # For setup mode, api_url, app_token, and scan_id are required unless in test mode
      if [ -z "$API_URL" ] || [ -z "$APP_TOKEN" ]; then
        log "ERROR: api_url and app_token are required for setup mode"
        exit 1
      fi
      
      if [ -z "$SCAN_ID" ] && [ "$TEST_MODE" != "true" ]; then
        log "ERROR: scan_id is required for setup mode when not in test mode"
        exit 1
      fi
      ;;
      
    intercept)
      # For intercept mode, proxy_ip or proxy_hostname is required
      if [ -z "$PROXY_IP" ] && [ -z "$PROXY_HOSTNAME" ]; then
        log "ERROR: proxy_ip or proxy_hostname is required for intercept mode"
        exit 1
      fi
      
      if [ -z "$SCAN_ID" ] && [ "$TEST_MODE" != "true" ]; then
        log "ERROR: scan_id is required for intercept mode when not in test mode"
        exit 1
      fi
      ;;
      
    all)
      # For all mode, api_url and app_token are required
      if [ -z "$API_URL" ] || [ -z "$APP_TOKEN" ]; then
        log "ERROR: api_url and app_token are required for all mode"
        exit 1
      fi
      ;;
      
    *)
      # For legacy modes, validate based on their equivalent modes
      case "$MODE" in
        full)
          if [ -z "$API_URL" ] || [ -z "$APP_TOKEN" ]; then
            log "ERROR: api_url and app_token are required for full mode"
            exit 1
          fi
          ;;
          
        pse_only)
          if [ -z "$API_URL" ] || [ -z "$APP_TOKEN" ]; then
            log "ERROR: api_url and app_token are required for pse_only mode"
            exit 1
          fi
          
          if [ -z "$SCAN_ID" ] && [ "$TEST_MODE" != "true" ]; then
            log "ERROR: scan_id is required for pse_only mode when not in test mode"
            exit 1
          fi
          ;;
          
        build_only)
          if [ -z "$PROXY_IP" ] && [ -z "$PROXY_HOSTNAME" ]; then
            log "ERROR: proxy_ip or proxy_hostname is required for build_only mode"
            exit 1
          fi
          
          if [ -z "$SCAN_ID" ] && [ "$TEST_MODE" != "true" ]; then
            log "ERROR: scan_id is required for build_only mode when not in test mode"
            exit 1
          fi
          ;;
          
        prepare_only)
          if [ -z "$API_URL" ] || [ -z "$APP_TOKEN" ]; then
            log "ERROR: api_url and app_token are required for prepare_only mode"
            exit 1
          fi
          ;;
      esac
      ;;
  esac
  
  log "Mode-specific requirements validation successful"
}

# Main function
main() {
  log "Starting PSE GitHub Action in $MODE mode"
  
  # Validate mode-specific requirements
  validate_mode_requirements
  
  # Create scripts directory if it doesn't exist
  SCRIPTS_DIR="$(dirname "$0")/scripts"
  if [ ! -d "$SCRIPTS_DIR" ]; then
    mkdir -p "$SCRIPTS_DIR"
    
    # Copy the mode scripts to the scripts directory
    cp "$(dirname "$0")/prepare.sh" "$SCRIPTS_DIR/mode_prepare.sh" 2>/dev/null || true
    cp "$(dirname "$0")/scripts/setup.sh" "$SCRIPTS_DIR/mode_setup.sh" 2>/dev/null || true
    cp "$(dirname "$0")/scripts/intercept.sh" "$SCRIPTS_DIR/mode_intercept.sh" 2>/dev/null || true
    
    # Make scripts executable
    chmod +x "$SCRIPTS_DIR"/*.sh 2>/dev/null || true
  fi
  
  # Execute the appropriate script based on the mode
  case "$MODE" in
    prepare)
      log "Running in prepare mode - obtaining scan ID and ECR credentials"
      # Source the prepare script to maintain environment variables
      if [ -f "$SCRIPTS_DIR/mode_prepare.sh" ]; then
        . "$SCRIPTS_DIR/mode_prepare.sh"
      else
        log "ERROR: mode_prepare.sh script not found in $SCRIPTS_DIR"
        exit 1
      fi
      ;;
      
    setup)
      log "Running in setup mode - pulling and running the PSE proxy container"
      # Source the setup script to maintain environment variables
      if [ -f "$SCRIPTS_DIR/mode_setup.sh" ]; then
        . "$SCRIPTS_DIR/mode_setup.sh"
      else
        log "ERROR: mode_setup.sh script not found in $SCRIPTS_DIR"
        exit 1
      fi
      ;;
      
    intercept)
      log "Running in intercept mode - configuring iptables and certificates"
      # Source the intercept script to maintain environment variables
      if [ -f "$SCRIPTS_DIR/mode_intercept.sh" ]; then
        . "$SCRIPTS_DIR/mode_intercept.sh"
      else
        log "ERROR: mode_intercept.sh script not found in $SCRIPTS_DIR"
        exit 1
      fi
      ;;
      
    all)
      log "Running in all mode - performing all operations"
      
      # Run prepare mode
      log "Step 1: Preparing scan ID and ECR credentials"
      if [ -f "$SCRIPTS_DIR/mode_prepare.sh" ]; then
        . "$SCRIPTS_DIR/mode_prepare.sh"
      else
        log "ERROR: mode_prepare.sh script not found in $SCRIPTS_DIR"
        exit 1
      fi
      
      # Run setup mode
      log "Step 2: Setting up PSE proxy container"
      if [ -f "$SCRIPTS_DIR/mode_setup.sh" ]; then
        . "$SCRIPTS_DIR/mode_setup.sh"
      else
        log "ERROR: mode_setup.sh script not found in $SCRIPTS_DIR"
        exit 1
      fi
      
      # Run intercept mode
      log "Step 3: Configuring iptables and certificates"
      if [ -f "$SCRIPTS_DIR/mode_intercept.sh" ]; then
        . "$SCRIPTS_DIR/mode_intercept.sh"
      else
        log "ERROR: mode_intercept.sh script not found in $SCRIPTS_DIR"
        exit 1
      fi
      ;;
      
    # Legacy mode support for backward compatibility
    full)
      log "Running in full mode (legacy) - performing all operations"
      MODE="all"
      export MODE
      main
      ;;
      
    pse_only)
      log "Running in pse_only mode (legacy) - equivalent to setup mode"
      MODE="setup"
      export MODE
      main
      ;;
      
    build_only)
      log "Running in build_only mode (legacy) - equivalent to intercept mode"
      MODE="intercept"
      export MODE
      main
      ;;
      
    prepare_only)
      log "Running in prepare_only mode (legacy) - equivalent to prepare mode"
      MODE="prepare"
      export MODE
      main
      ;;
      
    *)
      log "ERROR: Invalid mode $MODE. Valid modes are 'prepare', 'setup', 'intercept', and 'all'"
      log "Legacy modes 'full', 'pse_only', 'build_only', and 'prepare_only' are also supported for backward compatibility"
      exit 1
      ;;
  esac
  
  log "PSE GitHub Action completed successfully in $MODE mode"
}

# Execute main function
main
