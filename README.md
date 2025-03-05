# PSE Security Proxy GitHub Action

This GitHub Action integrates with InvisiRisk's Pipeline Security Engine (PSE) to enhance the security of your build process.

## Overview

The PSE GitHub Action helps you secure your software supply chain by monitoring and enforcing security policies during your build process. It integrates seamlessly with your existing GitHub Actions workflows to provide:

- **Security Policy Enforcement**: Prevent the use of vulnerable dependencies
- **Build Activity Monitoring**: Track network activity during your build
- **Compliance Reporting**: Generate detailed reports for audit and compliance purposes
- **Minimal Performance Impact**: Optimized for speed and reliability

## How It Works

The PSE GitHub Action performs the following steps:

1. Creates a scan object in the InvisiRisk Portal to track the build session
2. Sets up the PSE proxy container to monitor network traffic during the build
3. Configures iptables rules to route HTTPS traffic through the proxy
4. Installs necessary certificates to enable secure communication

At the end of your workflow, you need to run the same action with `cleanup: true` to:
1. Send the end signal to the InvisiRisk API
2. Display the container logs
3. Clean up the PSE container and related resources

## Usage

### Basic Example

Add the PSE GitHub Action to your workflow:

```yaml
name: Build NPM Package
on:
  push:
    branches: [ main ]
  pull_request:
    branches: [ main ]
jobs:
  build:
    runs-on: ubuntu-latest
    permissions:
      contents: read
    
    strategy:
      matrix:
        node-version: [18.x]
    steps:
    - name: Setup PSE
      id: pse-setup
      uses: kkisalaya/ir-gh-action@v0.14
      with:
        api_url: 'https://app.invisirisk.com'
        app_token: ${{ secrets.INVISIRISK_TOKEN }}
        portal_url: 'https://app.invisirisk.com'
        github_token: ${{ secrets.GITHUB_TOKEN }}
        
    - name: Install system dependencies
      run: |
        sudo apt-get update
        sudo apt-get install -y curl wget git
        
    - name: Checkout the code
      uses: actions/checkout@v3
      
    - name: Use Node.js ${{ matrix.node-version }}
      uses: actions/setup-node@v3
      with:
        node-version: ${{ matrix.node-version }}
        
    - name: Install dependencies
      run: |
        npm install
        npm ci
        
    - name: Build and Test
      run: |
        npm run build --if-present
        npm test
        
    - name: Cleanup PSE
      if: always()
      uses: kkisalaya/ir-gh-action@v0.14
      with:
        api_url: 'https://app.invisirisk.com'
        app_token: ${{ secrets.INVISIRISK_TOKEN }}
        portal_url: 'https://app.invisirisk.com'
        github_token: ${{ secrets.GITHUB_TOKEN }}
        cleanup: 'true'
        scan_id: ${{ steps.pse-setup.outputs.scan_id }}
```

The PSE proxy will be set up before your build steps and cleaned up after all steps have completed. The `if: always()` condition ensures that cleanup happens even if previous steps fail.

### With Debug Mode

If you need more detailed logging, you can enable debug mode:

```yaml
- name: Setup PSE Security Proxy
  uses: ir-gh-action@v1
  with:
    api_url: 'https://your-api-url.com'
    app_token: ${{ secrets.INVISIRISK_TOKEN }}
    portal_url: 'https://your-portal-url.com'
    github_token: ${{ secrets.GITHUB_TOKEN }}
    debug: 'true'
```

## Inputs

| Input | Description | Required | Default |
|-------|-------------|----------|---------|
| `api_url` | URL of the InvisiRisk API | Yes | N/A |
| `app_token` | Authentication token for the InvisiRisk API | Yes | N/A |
| `portal_url` | URL of the InvisiRisk Portal | Yes | N/A |
| `github_token` | GitHub token to be passed to the PSE container for GitHub authentication | No | `${{ github.token }}` |
| `debug` | Enable debug mode for verbose logging | No | `false` |
| `test_mode` | Enable test mode to bypass API calls and container setup for testing. Use this when you want to test the action without actually running the PSE container. | No | `false` |
| `cleanup` | Clean up the PSE container and related resources | No | `false` |

## Prerequisites

1. An active InvisiRisk account with API access
2. API token with appropriate permissions
3. GitHub Actions workflow running on Ubuntu (other Linux distributions are supported but may require additional configuration)

## Troubleshooting

### Common Issues

1. **Certificate Trust Issues**:
   - Verify that your build tools respect the standard certificate environment variables
   - Contact InvisiRisk support if certificate issues persist

2. **Network Configuration Problems**:
   - Ensure that your build environment allows outbound network connections
   - Check if there are any network restrictions in your GitHub Actions environment

3. **Docker-in-Docker Issues**:
   - If your build uses Docker, ensure that the Docker daemon is properly configured

## Support

For support, please contact InvisiRisk support at support@invisirisk.com or open an issue in this repository.

## License

This GitHub Action is licensed under the [MIT License](LICENSE).
