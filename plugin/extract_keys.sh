#!/bin/bash

input_file="/home/haco/Desktop/secret.txt"  # default input_file
# If input_file is given as a URL, fetch it using curl
if [[ "$input_file" =~ ^https?:// ]]; then
    temp_file=$(mktemp)
    curl -s "$input_file" -o "$temp_file"
    input_file="$temp_file"
fi

output_file="secretfinder.txt"

# Check if input file exists
if [ ! -f "$input_file" ]; then
    echo "Error: Input file not found: $input_file"
    exit 1
fi

# Initialize output file
> "$output_file"

# Define patterns for different keys
declare -A patterns=(
    ["facebook_access_token"]="EAACEdEose0cBA[0-9A-Za-z]+"
    ["rsa_private_key"]="-----BEGIN RSA PRIVATE KEY-----[a-zA-Z0-9\s/+=]+-----END RSA PRIVATE KEY-----"
    ["ssh_dsa_private_key"]="-----BEGIN DSA PRIVATE KEY-----[a-zA-Z0-9\s/+=]+-----END DSA PRIVATE KEY-----"
    ["json_web_token"]="eyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*"
    ["SSH_privKey"]="-----BEGIN OPENSSH PRIVATE KEY-----[a-zA-Z0-9\s/+=]+-----END OPENSSH PRIVATE KEY-----"
    ["authorization_bearer"]="bearer\s+[a-zA-Z0-9\-\._~\+\/]+=*"
    ["authorization_basic"]="basic [a-zA-Z0-9=:_\\+\\/-]{5,100}"
    ["google_api"]="AIza[0-9A-Za-z\\-_]{35}"
    ["amazon_mws_auth_token"]="amzn\.mws\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"
    ["firebase"]="AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}"
    ["google_captcha"]="6L[0-9A-Za-z-_]{38}"
    ["google_oauth"]="ya29\\.[0-9A-Za-z\\-_]+"
    
    ["firebase_api_key"]="AIza[0-9A-Za-z-_]{35}"
    ["checkout_key_test"]="pk_test_[0-9a-zA-Z]{24,99}"
    ["checkout_key_live"]="pk_live_[0-9a-zA-Z]{24,99}"
    ["braze_api_key"]="[a-f0-9]{32}-us[0-9]{1,2}"
    ["user_snap_space_api_key"]="[A-Z0-9]{8}-[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{12}"
    ["asana_access_token"]="[0-9]{16}:[0-9a-fA-F]{32}"
    ["azure_tenant"]="[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"
    ["github_ssh_key"]="ssh-rsa [A-Za-z0-9+/]+[=]{0,3}(\\n[A-Za-z0-9+/]+[=]{0,3})*"
    ["github_ssh_key"]="ssh-rsa [A-Za-z0-9+/]+[=]{0,3}"
    ["github_token"]="gh[ps]_[a-zA-Z0-9]{36}"
    ["gitlab_private_token"]="glpat-[0-9a-zA-Z-_]{20}"
    ["google_maps_key"]="AIza[0-9A-Za-z-_]{35}"
    ["paypal_key_sb"]="[A-Z0-9]{16}"
    ["paypal_key_live"]="[A-Z0-9]{16}"
    ["paypal_token_sb"]="access_token\$[a-zA-Z0-9]{24}\$[a-f0-9]{128}"
    ["paypal_token_live"]="access_token\$[a-zA-Z0-9]{24}\$[a-f0-9]{128}"
    ["salesforce_access_token"]="00D[a-zA-Z0-9]{12,15}"
    ["sendgrid_api_key"]="SG\.[a-zA-Z0-9-_]{22}\.[a-zA-Z0-9-_]{43}"
    ["slack_webhook"]="T[a-zA-Z0-9]{8}/B[a-zA-Z0-9]{8}/[a-zA-Z0-9]{24}"
    ["square_secret"]="sq0[a-z]{3}-[0-9A-Za-z-_]{43}"
    ["square_auth_token"]="EAAA[a-zA-Z0-9]{60}"
    ["twilio_sid_token"]="SK[0-9a-fA-F]{32}"
    ["twilio_account_sid"]="AC[a-zA-Z0-9]{32}"
    ["stripe_key_live"]="sk_live_[0-9a-zA-Z]{24,99}"
    ["zapier_webhook"]="hooks\.zapier\.com/hooks/catch/[0-9]{7,10}/[a-zA-Z0-9]{8}"
    ["heroku_api_key"]="[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"
    ["mailgun_api_key"]="key-[0-9a-zA-Z]{32}"
    ["stripe_api_key"]="sk_live_[0-9a-zA-Z]{24}"
    ["private_key"]="-----BEGIN PRIVATE KEY-----[a-zA-Z0-9\\s/+=]+-----END PRIVATE KEY-----"
    ["amazon_aws_access_key_id"]="AKIA[0-9A-Z]{16}"
    ["paypal_braintree_access_token"]="access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}"
)

# Debug mode
DEBUG=true

# Extract keys using patterns
for key_type in "${!patterns[@]}"; do
    if [[ "$DEBUG" == "true" ]]; then
        echo "Searching for $key_type..."
    fi
    
    # First try to find key-value pairs
    grep -oP "[\'\"]?${key_type}[\'\"]?\s*[=:]\s*[\'\"]?\K([^\'\"]+)" "$input_file" 2>/dev/null | while read -r match; do
        if [[ ! -z "$match" ]]; then
            echo "$key_type -> $match" >> "$output_file"
        fi
    done

    # Then try to find raw key patterns
    grep -oP "${patterns[$key_type]}" "$input_file" 2>/dev/null | while read -r match; do
        if [[ ! -z "$match" ]] && ! grep -q "$match" "$output_file"; then
            echo "$key_type -> $match" >> "$output_file"
        fi
    done
done

# Check if we found any keys
if [ ! -s "$output_file" ]; then
    echo "No keys found in the input file."
else
    echo "Keys extracted to $output_file"
    if [[ "$DEBUG" == "true" ]]; then
        echo "Found keys:"
        cat "$output_file"
    fi
fi
