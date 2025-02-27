# PSE Security Proxy GitHub Action

This GitHub Action configures the Proxy Security Engine (PSE) to monitor and secure your build process by intercepting HTTPS traffic and applying security policies.

## Overview

The PSE GitHub Action is a component of InvisiRisk's software supply chain GRC (Governance, Risk, and Compliance) platform. It sets up a secure proxy that:

1. Intercepts build system HTTPS traffic
2. Applies configurable security policies based on Open Policy Agent
3. Monitors and reports on build activities for security and compliance purposes
4. Generates detailed reports in the InvisiRisk Portal

## Features

- **Transparent Integration**: Works with your existing GitHub Actions workflows
- **Security Policy Enforcement**: Prevents the use of vulnerable dependencies
- **Build Activity Monitoring**: Tracks all network activity during your build
- **Compliance Reporting**: Generates detailed reports for audit and compliance purposes
- **Minimal Performance Impact**: Optimized for speed and reliability

## Usage

### Basic Example

```yaml
name: Build with PSE Security

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout code
        uses: actions/checkout@v3
      
      - name: Setup PSE Security Proxy
        uses: invisirisk/pse-action@v1
        with:
          api_url: 'https://your-api-url.com'
          app_token: ${{ secrets.INVISIRISK_TOKEN }}
          portal_url: 'https://your-portal-url.com'
      
      # Your build steps go here
      - name: Build application
        run: |
          npm install
          npm run build
```

That's it! The PSE Security Proxy GitHub Action handles all the complexity internally:
- Creating a scan object in the InvisiRisk Portal
- Obtaining ECR credentials for pulling the PSE container
- Setting up the proxy configuration
- Routing all HTTPS traffic through the proxy
- Reporting build results back to the InvisiRisk Portal

### With Debug Mode

If you need more detailed logging, you can enable debug mode:

```yaml
- name: Setup PSE Security Proxy
  uses: invisirisk/pse-action@v1
  with:
    api_url: 'https://your-api-url.com'
    app_token: ${{ secrets.INVISIRISK_TOKEN }}
    portal_url: 'https://your-portal-url.com'
    debug: 'true'
```

## Inputs

| Input | Description | Required | Default |
|-------|-------------|----------|---------|
| `api_url` | URL of the InvisiRisk API | Yes | N/A |
| `app_token` | Authentication token for the InvisiRisk API | Yes | N/A |
| `portal_url` | URL of the InvisiRisk Portal | Yes | N/A |
| `debug` | Enable debug mode for verbose logging | No | `false` |

## Prerequisites

1. An active InvisiRisk account with API access
2. API token with appropriate permissions
3. GitHub Actions workflow running on Ubuntu (other Linux distributions are supported but may require additional configuration)

## How It Works

1. The action sets up a Man-in-the-Middle (MITM) proxy that intercepts all HTTPS traffic from your build
2. It configures the build environment to trust the PSE certificate
3. All HTTPS traffic is routed through the PSE proxy, which applies security policies
4. Build activity is monitored and reported to the InvisiRisk Portal
5. After the build completes, the action cleans up the proxy configuration

## Troubleshooting

### Common Issues

1. **Certificate Trust Issues**:
   - Verify that the PSE certificate is properly installed
   - Check if your build tools respect the standard certificate environment variables

2. **Network Configuration Problems**:
   - Ensure that your build environment allows iptables modifications
   - Check if there are any conflicting network configurations

3. **Docker-in-Docker Issues**:
   - If your build uses Docker, ensure that the Docker daemon is configured to trust the PSE certificate

## Support

For support, please contact InvisiRisk support at support@invisirisk.com or open an issue in this repository.

## License

This GitHub Action is licensed under the [MIT License](LICENSE).
