# Porkbun SSL Certificate to Cloudflare Upload Script

A comprehensive bash script to easily upload and manage SSL certificates from Porkbun to Cloudflare's Web Application Firewall (WAF). This script includes prerequisite checking, input validation, and supports both new certificate uploads and updates to existing certificates.

## Features

- ✅ **Prerequisite Checking**: Automatically validates required dependencies
- ✅ **Input Validation**: Validates certificate files, API credentials, and certificate/key matching
- ✅ **Certificate Information**: Displays certificate details including expiration date
- ✅ **Update Support**: Can update existing certificates or create new ones
- ✅ **Error Handling**: Comprehensive error handling with clear messages
- ✅ **Logging**: Detailed logging of all operations
- ✅ **Colorized Output**: Easy-to-read colored terminal output
- ✅ **Flexible Configuration**: Support for command-line arguments and environment variables

## Prerequisites

The script will automatically check for these dependencies:

- `curl` - For API requests
- `jq` - For JSON processing
- `openssl` - For certificate validation

### Installation of Dependencies

**Ubuntu/Debian:**
```bash
sudo apt-get update
sudo apt-get install curl jq openssl
```

**CentOS/RHEL:**
```bash
sudo yum install curl jq openssl
```

**macOS:**
```bash
brew install curl jq openssl
```

## Setup

1. **Download the script:**
   ```bash
   curl -O https://raw.githubusercontent.com/your-repo/porkbun-to-cloudflare-ssl.sh
   chmod +x porkbun-to-cloudflare-ssl.sh
   ```

2. **Get your Cloudflare credentials:**
   - **Zone ID**: Found in your Cloudflare dashboard → Select your domain → Right sidebar "Zone ID"
   - **API Token**: Cloudflare dashboard → Profile → API Tokens → Create Token
     - Use "Custom token" with these permissions:
       - Zone: `Zone:Read`
       - Zone: `SSL and Certificates:Edit`

3. **Prepare your SSL certificates from Porkbun:**
   - Download your SSL certificate files from Porkbun
   - Typically named `public.key.pem` (certificate) and `private.key.pem` (private key)

## Usage

### Basic Usage

```bash
./porkbun-to-cloudflare-ssl.sh -z "your_zone_id" -t "your_api_token"
```

### Advanced Usage Examples

**With custom certificate file paths:**
```bash
./porkbun-to-cloudflare-ssl.sh \
  -z "your_zone_id" \
  -t "your_api_token" \
  -c "/path/to/certificate.pem" \
  -k "/path/to/private-key.pem" \
  -n "my-custom-cert-name"
```

**Update existing certificate:**
```bash
./porkbun-to-cloudflare-ssl.sh -z "your_zone_id" -t "your_api_token" --update
```

**Update specific certificate by ID:**
```bash
./porkbun-to-cloudflare-ssl.sh \
  -z "your_zone_id" \
  -t "your_api_token" \
  --update \
  --existing-cert-id "existing_certificate_id"
```

**With verbose output:**
```bash
./porkbun-to-cloudflare-ssl.sh -z "your_zone_id" -t "your_api_token" -v
```

### Using Environment Variables

Set environment variables to avoid passing credentials via command line:

```bash
export CF_ZONE_ID="your_zone_id"
export CF_API_TOKEN="your_api_token"
export SSL_CERT_FILE="/path/to/certificate.pem"
export SSL_KEY_FILE="/path/to/private-key.pem"

./porkbun-to-cloudflare-ssl.sh
```

## Command Line Options

| Option | Short | Description | Default |
|--------|-------|-------------|---------|
| `--zone-id` | `-z` | Cloudflare Zone ID (required) | `$CF_ZONE_ID` |
| `--token` | `-t` | Cloudflare API token (required) | `$CF_API_TOKEN` |
| `--cert-file` | `-c` | Path to certificate file | `public.key.pem` |
| `--key-file` | `-k` | Path to private key file | `private.key.pem` |
| `--cert-name` | `-n` | Certificate name in Cloudflare | Auto-generated |
| `--update` | `-u` | Update existing certificate | `false` |
| `--existing-cert-id` | | Specific certificate ID to update | Auto-detected |
| `--verbose` | `-v` | Enable verbose output | `false` |
| `--help` | `-h` | Show help message | |

## Environment Variables

| Variable | Description |
|----------|-------------|
| `CF_ZONE_ID` | Cloudflare Zone ID |
| `CF_API_TOKEN` | Cloudflare API Token |
| `SSL_CERT_FILE` | Path to certificate file |
| `SSL_KEY_FILE` | Path to private key file |

## Certificate Renewal Workflow

For automated certificate renewal, you can create a simple workflow:

1. **Download new certificates from Porkbun** (manual or automated)
2. **Run the update script:**
   ```bash
   ./porkbun-to-cloudflare-ssl.sh --update -z "$CF_ZONE_ID" -t "$CF_API_TOKEN"
   ```

### Automation with Cron

Add to your crontab for monthly certificate updates:

```bash
# Run on the 1st day of every month at 2 AM
0 2 1 * * /path/to/porkbun-to-cloudflare-ssl.sh --update -z "$CF_ZONE_ID" -t "$CF_API_TOKEN" >> /var/log/ssl-update.log 2>&1
```

## Validation Process

The script performs comprehensive validation:

1. **Prerequisite Check**: Ensures `curl`, `jq`, and `openssl` are installed
2. **File Validation**: 
   - Verifies certificate and key files exist
   - Validates certificate format using OpenSSL
   - Validates private key format
   - Confirms certificate and key match
3. **API Validation**: Tests Cloudflare credentials and zone access
4. **Certificate Information**: Displays certificate subject, issuer, expiration, and SAN

## Troubleshooting

### Common Issues

**"Missing required commands"**
- Install the missing dependencies listed in the Prerequisites section

**"Certificate and private key do not match"**
- Ensure you're using the correct certificate and key files from the same SSL certificate package

**"Cloudflare API validation failed"**
- Verify your Zone ID and API Token are correct
- Ensure your API Token has the necessary permissions
- Check that the zone exists in your Cloudflare account

**"Certificate upload failed"**
- Check that your certificate is valid and not expired
- Ensure the certificate format is PEM
- Verify you have sufficient permissions in Cloudflare

### Debug Mode

Enable verbose output to see detailed API requests and responses:

```bash
./porkbun-to-cloudflare-ssl.sh -z "zone_id" -t "api_token" --verbose
```

### Log Files

The script creates a log file `ssl_upload.log` in the same directory with detailed information about each run.

## Security Best Practices

1. **Protect your API tokens**: Store them securely and limit their permissions
2. **Secure certificate files**: Ensure proper file permissions (600 for private keys)
3. **Regular rotation**: Update certificates before expiration
4. **Monitor expiration**: Set up alerts for certificate expiration dates

## File Permissions

Set appropriate permissions for security:

```bash
chmod 700 porkbun-to-cloudflare-ssl.sh  # Script executable by owner only
chmod 600 private.key.pem               # Private key readable by owner only
chmod 644 public.key.pem                # Certificate readable by owner and group
```

## API Token Permissions

Create a Cloudflare API token with these specific permissions:

- **Zone Resources**: Include your specific zone
- **Permissions**:
  - `Zone:Zone:Read`
  - `Zone:SSL and Certificates:Edit`

## Contributing

Contributions are welcome! Please feel free to submit issues, feature requests, or pull requests.

## License

This project is released under the MIT License.

## Changelog

### Version 1.0
- Initial release
- Basic certificate upload functionality
- Certificate update support
- Comprehensive validation
- Error handling and logging
- Colorized output

## Support

If you encounter any issues or need help:

1. Check the troubleshooting section above
2. Review the log file for detailed error information
3. Ensure all prerequisites are met
4. Verify your Cloudflare API token permissions

For bugs or feature requests, please open an issue in the GitHub repository.
