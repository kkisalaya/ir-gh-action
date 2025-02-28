# PSE Security Proxy GitHub Action

This GitHub Action integrates with InvisiRisk's Pipeline Security Engine (PSE) to enhance the security of your build process.

## Overview

The PSE GitHub Action helps you secure your software supply chain by monitoring and enforcing security policies during your build process. It integrates seamlessly with your existing GitHub Actions workflows to provide:

- **Security Policy Enforcement**: Prevent the use of vulnerable dependencies
- **Build Activity Monitoring**: Track network activity during your build
- **Compliance Reporting**: Generate detailed reports for audit and compliance purposes
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
        uses: ir-gh-action@v1
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

That's it! The PSE Security Proxy GitHub Action handles all the complexity internally, allowing you to focus on your build process while ensuring security and compliance.

### With Debug Mode

If you need more detailed logging, you can enable debug mode:

```yaml
- name: Setup PSE Security Proxy
  uses: ir-gh-action@v1
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
| `test_mode` | Enable test mode to bypass API calls for testing | No | `false` |

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
