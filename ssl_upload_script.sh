#!/bin/bash

#SSL Certificate to Cloudflare Upload Script
# Author: Wesley Finch
# Version: 1.1 - Fixed API endpoints and payload format
# Description: Upload/update SSL certificates from local/Provider to Cloudflare

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOG_FILE="${SCRIPT_DIR}/ssl_upload.log"

# Function to log messages
log() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $1" | tee -a "${LOG_FILE}"
}

# Function to print colored output
print_status() {
    local color=$1
    local message=$2
    echo -e "${color}${message}${NC}"
    log "$message"
}

# Function to print usage
usage() {
    cat << EOF
Usage: $0 [OPTIONS]

Upload SSL certificates from Porkbun to Cloudflare

OPTIONS:
    -z, --zone-id ZONE_ID           Cloudflare Zone ID (required)
    -t, --token TOKEN              Cloudflare API token (required)
    -c, --cert-file CERT_FILE      Path to public certificate file (default: public.key.pem)
    -k, --key-file KEY_FILE        Path to private key file (default: private.key.pem)
    -n, --cert-name CERT_NAME      Certificate name in Cloudflare (default: auto-generated)
    -u, --update                   Update existing certificate instead of creating new
    --existing-cert-id CERT_ID     Existing certificate ID to update (auto-detected if not provided)
    -v, --verbose                  Enable verbose output
    -h, --help                     Show this help message

EXAMPLES:
    # Basic usage
    $0 -z "your_zone_id" -t "your_api_token"
    
    # With custom file paths
    $0 -z "zone_id" -t "api_token" -c "/path/to/cert.pem" -k "/path/to/key.pem"
    
    # Update existing certificate
    $0 -z "zone_id" -t "api_token" --update
    
    # Update specific certificate
    $0 -z "zone_id" -t "api_token" --update --existing-cert-id "cert_id"

ENVIRONMENT VARIABLES:
    CF_ZONE_ID                     Cloudflare Zone ID
    CF_API_TOKEN                   Cloudflare API Token
    SSL_CERT_FILE                  Path to certificate file
    SSL_KEY_FILE                   Path to private key file

EOF
}

# Function to check prerequisites
check_prerequisites() {
    print_status "$BLUE" "🔍 Checking prerequisites..."
    
    # Check for required commands
    local required_commands=("curl" "jq" "openssl")
    local missing_commands=()
    
    for cmd in "${required_commands[@]}"; do
        if ! command -v "$cmd" &> /dev/null; then
            missing_commands+=("$cmd")
        fi
    done
    
    if [ ${#missing_commands[@]} -ne 0 ]; then
        print_status "$RED" "❌ Missing required commands: ${missing_commands[*]}"
        echo ""
        echo "Please install the missing commands:"
        echo "  Ubuntu/Debian: sudo apt-get install curl jq openssl"
        echo "  CentOS/RHEL:   sudo yum install curl jq openssl"
        echo "  macOS:         brew install curl jq openssl"
        exit 1
    fi
    
    print_status "$GREEN" "✅ All prerequisites met"
}

# Function to validate certificate files
validate_cert_files() {
    local cert_file=$1
    local key_file=$2
    
    print_status "$BLUE" "🔍 Validating certificate files..."
    
    # Check if files exist
    if [[ ! -f "$cert_file" ]]; then
        print_status "$RED" "❌ Certificate file not found: $cert_file"
        exit 1
    fi
    
    if [[ ! -f "$key_file" ]]; then
        print_status "$RED" "❌ Private key file not found: $key_file"
        exit 1
    fi
    
    # Check if file contains a public key instead of certificate
    if grep -q "BEGIN PUBLIC KEY" "$cert_file"; then
        print_status "$RED" "❌ Found public key instead of SSL certificate in: $cert_file"
        echo ""
        echo "The file contains a public key, but an SSL certificate is required."
        echo "SSL certificates should start with: -----BEGIN CERTIFICATE-----"
        echo "Public keys start with:             -----BEGIN PUBLIC KEY-----"
        echo ""
        echo "Please ensure you have downloaded the complete SSL certificate bundle"
        echo "which should include:"
        echo "  • SSL Certificate file (*.crt, *.pem, *.cert)"
        echo "  • Private Key file (*.key, *.pem)"
        echo ""
        echo "Available files in current directory:"
        ls -la *.{crt,pem,cert,key} 2>/dev/null || echo "  No certificate files found"
        exit 1
    fi
    
    # Validate certificate format
    if ! openssl x509 -in "$cert_file" -text -noout &> /dev/null; then
        print_status "$RED" "❌ Invalid certificate format in: $cert_file"
        echo ""
        echo "Expected format: SSL Certificate (X.509)"
        echo "File should start with: -----BEGIN CERTIFICATE-----"
        echo ""
        echo "Current file content preview:"
        head -5 "$cert_file"
        exit 1
    fi
    
    # Validate private key format (try different key types)
    local key_valid=false
    for key_type in rsa ec pkcs8; do
        case $key_type in
            rsa)
                if openssl rsa -in "$key_file" -check -noout &> /dev/null; then
                    key_valid=true
                    break
                fi
                ;;
            ec)
                if openssl ec -in "$key_file" -check -noout &> /dev/null; then
                    key_valid=true
                    break
                fi
                ;;
            pkcs8)
                if openssl pkey -in "$key_file" -check -noout &> /dev/null; then
                    key_valid=true
                    break
                fi
                ;;
        esac
    done
    
    if [[ "$key_valid" != "true" ]]; then
        print_status "$RED" "❌ Invalid private key format in: $key_file"
        echo ""
        echo "Private key should be in PEM format and start with one of:"
        echo "  -----BEGIN RSA PRIVATE KEY-----"
        echo "  -----BEGIN EC PRIVATE KEY-----"
        echo "  -----BEGIN PRIVATE KEY-----"
        echo ""
        echo "Current file content preview:"
        head -3 "$key_file"
        exit 1
    fi
    
    # Check if certificate and key match
    local cert_modulus=""
    local key_modulus=""
    
    # Get certificate public key
    cert_modulus=$(openssl x509 -noout -pubkey -in "$cert_file" 2>/dev/null | openssl md5 2>/dev/null)
    
    # Get private key public key (try different formats)
    for key_type in rsa ec pkey; do
        case $key_type in
            rsa)
                if key_modulus=$(openssl rsa -in "$key_file" -pubout -outform PEM 2>/dev/null | openssl md5 2>/dev/null); then
                    break
                fi
                ;;
            ec)
                if key_modulus=$(openssl ec -in "$key_file" -pubout -outform PEM 2>/dev/null | openssl md5 2>/dev/null); then
                    break
                fi
                ;;
            pkey)
                if key_modulus=$(openssl pkey -in "$key_file" -pubout -outform PEM 2>/dev/null | openssl md5 2>/dev/null); then
                    break
                fi
                ;;
        esac
    done
    
    if [[ "$cert_modulus" != "$key_modulus" ]] || [[ -z "$cert_modulus" ]] || [[ -z "$key_modulus" ]]; then
        print_status "$RED" "❌ Certificate and private key do not match"
        echo ""
        echo "This usually means:"
        echo "  • Files are from different SSL certificates"
        echo "  • One of the files is corrupted"
        echo "  • Wrong file format"
        echo ""
        echo "Please ensure both files are from the same SSL certificate package"
        exit 1
    fi
    
    # Get certificate information
    local cert_subject=$(openssl x509 -noout -subject -in "$cert_file" 2>/dev/null | sed 's/subject=//')
    local cert_issuer=$(openssl x509 -noout -issuer -in "$cert_file" 2>/dev/null | sed 's/issuer=//')
    local cert_expiry=$(openssl x509 -noout -enddate -in "$cert_file" 2>/dev/null | sed 's/notAfter=//')
    local cert_san=$(openssl x509 -noout -text -in "$cert_file" 2>/dev/null | grep -A1 "Subject Alternative Name" | tail -1 | sed 's/^[ \t]*//' || echo "None")
    
    print_status "$GREEN" "✅ Certificate validation successful"
    echo "  Subject: $cert_subject"
    echo "  Issuer: $cert_issuer"
    echo "  Expires: $cert_expiry"
    echo "  SAN: $cert_san"
}

# Function to validate Cloudflare credentials
validate_cloudflare_creds() {
    local zone_id=$1
    local api_token=$2
    
    print_status "$BLUE" "☁️ Validating Cloudflare credentials..."
    
    # Test API token and get zone information
    local response=$(curl -s -X GET "https://api.cloudflare.com/client/v4/zones/$zone_id" \
        -H "Authorization: Bearer $api_token" \
        -H "Content-Type: application/json")
    
    # Debug output for troubleshooting
    if [[ "$verbose" == "true" ]]; then
        echo "API Response: $response"
    fi
    
    local success=$(echo "$response" | jq -r '.success // false')
    
    if [[ "$success" != "true" ]]; then
        local error_msg=$(echo "$response" | jq -r '.errors[0].message // "Unknown error"')
        print_status "$RED" "❌ Cloudflare API validation failed: $error_msg"
        exit 1
    fi
    
    local zone_name=$(echo "$response" | jq -r '.result.name')
    print_status "$GREEN" "✅ Cloudflare credentials validated for zone: $zone_name"
}

# Function to find existing certificate
find_existing_cert() {
    local zone_id=$1
    local api_token=$2
    local cert_name=$3
    
    print_status "$BLUE" "🔍 Searching for existing certificates..."
    
    # FIXED: Use the correct API endpoint for custom certificates
    local response=$(curl -s -X GET "https://api.cloudflare.com/client/v4/zones/$zone_id/custom_certificates" \
        -H "Authorization: Bearer $api_token" \
        -H "Content-Type: application/json")
    
    local success=$(echo "$response" | jq -r '.success // false')
    
    if [[ "$success" != "true" ]]; then
        print_status "$YELLOW" "⚠️ Could not retrieve existing certificates"
        return 1
    fi
    
    # Look for certificate by name (or first certificate if name not found)
    local cert_id=$(echo "$response" | jq -r ".result[] | select(.name == \"$cert_name\") | .id" | head -1)
    
    if [[ -z "$cert_id" || "$cert_id" == "null" ]]; then
        cert_id=$(echo "$response" | jq -r '.result[0].id // empty')
    fi
    
    if [[ -n "$cert_id" && "$cert_id" != "null" ]]; then
        echo "$cert_id"
        return 0
    fi
    
    return 1
}

# Function to upload new certificate
upload_certificate() {
    local zone_id=$1
    local api_token=$2
    local cert_file=$3
    local key_file=$4
    local cert_name=$5
    
    print_status "$BLUE" "📤 Uploading new SSL certificate..."
    
    # Read certificate and key content
    local cert_content=$(cat "$cert_file")
    local key_content=$(cat "$key_file")
    
    # FIXED: Create JSON payload with correct format for Cloudflare API
    local payload=$(jq -n \
        --arg certificate "$cert_content" \
        --arg private_key "$key_content" \
        --arg bundle_method "ubiquitous" \
        --arg type "sni_custom" \
        '{
            certificate: $certificate,
            private_key: $private_key,
            bundle_method: $bundle_method,
            type: $type
        }')
    
    # FIXED: Use the correct API endpoint for custom certificates
    local response=$(curl -s -X POST "https://api.cloudflare.com/client/v4/zones/$zone_id/custom_certificates" \
        -H "Authorization: Bearer $api_token" \
        -H "Content-Type: application/json" \
        -d "$payload")
    
    local success=$(echo "$response" | jq -r '.success // false')
    
    if [[ "$success" != "true" ]]; then
        local error_msg=$(echo "$response" | jq -r '.errors[0].message // "Unknown error"')
        print_status "$RED" "❌ Certificate upload failed: $error_msg"
        echo ""
        echo "Full response:"
        echo "$response" | jq '.'
        exit 1
    fi
    
    local cert_id=$(echo "$response" | jq -r '.result.id')
    print_status "$GREEN" "✅ Certificate uploaded successfully!"
    echo "  Certificate ID: $cert_id"
    echo "  Certificate Bundle Method: ubiquitous"
    echo "  Certificate Type: sni_custom"
}

# Function to update existing certificate
update_certificate() {
    local zone_id=$1
    local api_token=$2
    local cert_id=$3
    local cert_file=$4
    local key_file=$5
    local cert_name=$6
    
    print_status "$BLUE" "🔄 Updating existing SSL certificate..."
    
    # Read certificate and key content
    local cert_content=$(cat "$cert_file")
    local key_content=$(cat "$key_file")
    
    # FIXED: Create JSON payload with correct format for Cloudflare API
    local payload=$(jq -n \
        --arg certificate "$cert_content" \
        --arg private_key "$key_content" \
        --arg bundle_method "ubiquitous" \
        --arg type "sni_custom" \
        '{
            certificate: $certificate,
            private_key: $private_key,
            bundle_method: $bundle_method,
            type: $type
        }')
    
    # FIXED: Use the correct API endpoint for custom certificates
    local response=$(curl -s -X PATCH "https://api.cloudflare.com/client/v4/zones/$zone_id/custom_certificates/$cert_id" \
        -H "Authorization: Bearer $api_token" \
        -H "Content-Type: application/json" \
        -d "$payload")
    
    local success=$(echo "$response" | jq -r '.success // false')
    
    if [[ "$success" != "true" ]]; then
        local error_msg=$(echo "$response" | jq -r '.errors[0].message // "Unknown error"')
        print_status "$RED" "❌ Certificate update failed: $error_msg"
        echo ""
        echo "Full response:"
        echo "$response" | jq '.'
        exit 1
    fi
    
    print_status "$GREEN" "✅ Certificate updated successfully!"
    echo "  Certificate ID: $cert_id"
    echo "  Certificate Bundle Method: ubiquitous"
    echo "  Certificate Type: sni_custom"
}

# Main function
main() {
    # Default values
    local zone_id="${CF_ZONE_ID:-}"
    local api_token="${CF_API_TOKEN:-}"
    local cert_file="${SSL_CERT_FILE:-public.key.pem}"
    local key_file="${SSL_KEY_FILE:-private.key.pem}"
    local cert_name=""
    local update_mode=false
    local existing_cert_id=""
    local verbose=false
    
    # Parse command line arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            -z|--zone-id)
                zone_id="$2"
                shift 2
                ;;
            -t|--token)
                api_token="$2"
                shift 2
                ;;
            -c|--cert-file)
                cert_file="$2"
                shift 2
                ;;
            -k|--key-file)
                key_file="$2"
                shift 2
                ;;
            -n|--cert-name)
                cert_name="$2"
                shift 2
                ;;
            -u|--update)
                update_mode=true
                shift
                ;;
            --existing-cert-id)
                existing_cert_id="$2"
                shift 2
                ;;
            -v|--verbose)
                verbose=true
                shift
                ;;
            -h|--help)
                usage
                exit 0
                ;;
            *)
                print_status "$RED" "Unknown option: $1"
                usage
                exit 1
                ;;
        esac
    done
    
    # Validate required parameters
    if [[ -z "$zone_id" || -z "$api_token" ]]; then
        print_status "$RED" "❌ Missing required parameters: zone-id and token"
        echo ""
        usage
        exit 1
    fi
    
    # Generate certificate name if not provided
    if [[ -z "$cert_name" ]]; then
        cert_name="porkbun-ssl-$(date +%Y%m%d-%H%M%S)"
    fi
    
    # Enable verbose output if requested
    if [[ "$verbose" == "true" ]]; then
        set -x
    fi
    
    # Start the process
    print_status "$GREEN" "🚀 Starting SSL certificate upload process..."
    echo "Log file: $LOG_FILE"
    echo ""
    
    # Run checks and validations
    check_prerequisites
    validate_cert_files "$cert_file" "$key_file"
    validate_cloudflare_creds "$zone_id" "$api_token"
    
    # Handle update vs new upload
    if [[ "$update_mode" == "true" ]]; then
        if [[ -z "$existing_cert_id" ]]; then
            # Try to find existing certificate
            if existing_cert_id=$(find_existing_cert "$zone_id" "$api_token" "$cert_name"); then
                print_status "$BLUE" "Found existing certificate: $existing_cert_id"
            else
                print_status "$YELLOW" "⚠️ No existing certificate found, creating new one instead"
                update_mode=false
            fi
        fi
        
        if [[ "$update_mode" == "true" ]]; then
            update_certificate "$zone_id" "$api_token" "$existing_cert_id" "$cert_file" "$key_file" "$cert_name"
        fi
    fi
    
    if [[ "$update_mode" == "false" ]]; then
        upload_certificate "$zone_id" "$api_token" "$cert_file" "$key_file" "$cert_name"
    fi
    
    print_status "$GREEN" "🎉 Process completed successfully!"
    echo ""
    echo "Next steps:"
    echo "1. Verify the certificate is visible in your Cloudflare dashboard"
    echo "2. Update your SSL/TLS settings if needed"
    echo "3. Test your domain's SSL configuration"
}

# Run main function with all arguments
main "$@"
