#!/bin/bash

# === Configuration ===
default_output_file="secrets_found.txt" # Output for initial findings
key_test_output_file="found_keys.txt"   # Output for tested keys
debug=false                             # Set to true for verbose output
input_urls=()                           # Array for URLs/lines from -i
input_text_file=""                      # Variable for single file from -f
html_output=false                       # Flag for HTML report generation

# === Helper Functions ===

# Function to display usage information
usage() {
    echo "Usage: $0 [-i input_file/url | -f input_text_file] [-o output_file] [-H] [-d]"
    echo "  -i : Input file containing URLs/lines OR a single URL."
    echo "       If a file, each line is processed individually."
    echo "  -f : Input single text file to scan its entire content directly."
    echo "  -o : Base output file name (default: secrets_found)."
    echo "       Actual files will be <name>.txt and <name>_tested.txt"
    echo "       If -H is used, <name>.html will also be generated."
    echo "  -H : Generate HTML output report (based on initial findings)."
    echo "  -d : Enable debug mode (verbose output)."
    exit 1
}

# Function to download URL content or read file/text
# Uses curl for URLs, cat for files, echo for direct text
download_url() {
    local input="$1"
    if [[ -f "$input" ]]; then
        cat "$input"
    elif [[ "$input" == http* ]]; then
        # -s silent, -k insecure (ignore cert errors), -L follow redirects, -m timeout
        curl -skL -m 15 "$input"
    else
        # Assume input is raw text content passed directly
        echo "$input"
    fi
}

# Function to extract JS URLs from HTML content
extract_js_urls() {
    local content=$1
    # Extract src attributes ending in .js, ignore protocol-relative // links for simplicity
    # Also try to resolve relative paths if a base URL is known (complex, omitted for now)
    grep -oP 'src=["'\'']\K[^"'\'']+\.js' <<< "$content" | grep -v '^//'
    # Add more sophisticated extraction if needed (e.g., handling relative paths)
}

# Function to generate HTML report from the initial findings file
generate_html_report() {
    local findings_file="$1" # e.g., secrets_found.txt
    local html_report_file="$2" # e.g., secrets_found.html

    # Check if the findings file exists and is not empty
    if [[ ! -s "$findings_file" ]]; then
        echo "Warning: Cannot generate HTML report, '$findings_file' is empty or does not exist." >&2
        return
    fi

    cat > "$html_report_file" << EOF
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Secret Finder Report</title>
    <style>
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; line-height: 1.6; padding: 20px; background-color: #f4f7f6; color: #333; }
        h1 { color: #2c3e50; border-bottom: 2px solid #3498db; padding-bottom: 10px; }
        .secret-entry {
            background-color: #ffffff;
            border: 1px solid #dcdcdc;
            border-left: 5px solid #3498db;
            margin-bottom: 15px;
            padding: 15px;
            border-radius: 4px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.05);
            word-wrap: break-word; /* Ensure long keys wrap */
            overflow-wrap: break-word; /* Ensure long keys wrap */
        }
        .secret-type { font-weight: bold; color: #2980b9; display: block; margin-bottom: 5px; }
        .secret-value { font-family: 'Courier New', Courier, monospace; background-color: #ecf0f1; padding: 3px 6px; border-radius: 3px; display: inline-block; max-width: 100%; overflow-x: auto; }
        .no-secrets { color: #7f8c8d; font-style: italic; }
    </style>
</head>
<body>
    <h1>Secret Finder Report - Initial Findings</h1>
    <div id="results">
$(cat "$findings_file" | sed -e 's/&/\&amp;/g' -e 's/</\&lt;/g' -e 's/>/\&gt;/g' | while IFS= read -r line; do
    # Extract type and value more robustly
    key_type=$(echo "$line" | sed -n 's/^\(.*\) -> .*/\1/p')
    key_value=$(echo "$line" | sed -n 's/^.* -> \(.*\)/\1/p')
    echo "<div class='secret-entry'>"
    echo "<span class='secret-type'>${key_type:-Unknown Type}</span>"
    echo "<span class='secret-value'>${key_value:-Invalid Format}</span>"
    echo "</div>"
done)
    </div>
</body>
</html>
EOF
    echo "HTML report generated: $html_report_file"
}

# === Argument Parsing ===

# Use default base name unless overridden by -o
output_base_name="secrets_found"

while getopts "i:f:o:Hd" opt; do
    case $opt in
        i)
            if [[ -n "$input_text_file" ]]; then
                echo "Error: Cannot use both -i and -f options." >&2; usage
            fi
            # Check if the argument is a file or a direct URL/string
            if [[ -f "$OPTARG" ]]; then
                # Read lines from file into the array
                readarray -t input_urls < "$OPTARG"
            else
                # Treat as a single URL or line
                input_urls+=("$OPTARG")
            fi
            ;;
        f)
            if [[ ${#input_urls[@]} -gt 0 ]]; then
                 echo "Error: Cannot use both -i and -f options." >&2; usage
            fi
            input_text_file="$OPTARG"
            if [[ ! -f "$input_text_file" ]]; then
                echo "Error: Input text file not found: $input_text_file" >&2; exit 1
            fi
            ;;
        o) output_base_name="$OPTARG";;
        H) html_output=true;;
        d) debug=true;;
        \?) usage;; # Use \? for portability
        :) echo "Option -$OPTARG requires an argument." >&2; usage;;
    esac
done
shift $((OPTIND-1)) # Remove parsed options

# Set actual output filenames based on the base name
output_file="${output_base_name}.txt"
key_test_output_file="${output_base_name}_tested.txt"
html_report_file="${output_base_name}.html"

# Verify that some input was provided
if [[ ${#input_urls[@]} -eq 0 ]] && [[ -z "$input_text_file" ]]; then
    echo "Error: No input specified. Use -i (URL/file-list) or -f (single-file)." >&2
    usage
fi

# === Secret Extraction Patterns ===
declare -A patterns=(
    ["facebook_access_token"]="EAACEdEose0cBA[0-9A-Za-z]+"
    ["rsa_private_key"]="-----BEGIN RSA PRIVATE KEY-----[a-zA-Z0-9\s/+=]+-----END RSA PRIVATE KEY-----"
    ["ssh_dsa_private_key"]="-----BEGIN DSA PRIVATE KEY-----[a-zA-Z0-9\s/+=]+-----END DSA PRIVATE KEY-----"
    ["json_web_token"]="eyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*"
    ["SSH_privKey"]="-----BEGIN OPENSSH PRIVATE KEY-----[a-zA-Z0-9\s/+=]+-----END OPENSSH PRIVATE KEY-----"
    ["authorization_bearer"]="bearer\s+[a-zA-Z0-9\-\._~\+\/]+=*"
    ["authorization_basic"]="basic [a-zA-Z0-9=:_\\+\\/-]{5,100}"
    ["google_api"]="AIza[0-9A-Za-z\\-_]{35}(?![a-zA-Z0-9-_]*')"
    ["amazon_mws_auth_token"]="amzn\.mws\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"
    ["amazon_aws_access_key_id"]="AKIA[0-9A-Z]{16}"
    ["amazon_aws_secret_access_key"]="[a-zA-Z0-9/+=]{40}" # Basic pattern, might need refinement
    ["amazon_aws_session_token"]="FwoGZXIvYXdzEJ[a-zA-Z0-9/+=]+" # Example prefix, adjust if needed
    ["google_captcha"]="6L[0-9A-Za-z-_]{38}"
    ["google_oauth"]="ya29\\.[0-9A-Za-z\\-_]+"
    ["firebase_api_key"]="(?:AIza[0-9A-Za-z-_]{35}|apiKey: ?'([^']+)')"
    ["firebase_config_apikey"]="apiKey: ?[\"'](AIza[0-9A-Za-z\\-_]{35})[\"']" # Extract from config object
    ["checkout_key"]="(?:pk_[0-9a-zA-Z]{24,99}|checkoutKey: ?'([^']+)')"
    ["checkout_config_key"]="checkoutKey: ?[\"'](pk_(?:test|live)_[0-9a-zA-Z]{24,99})[\"']"
    ["braze_api_key"]="[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}"
    ["user_snap_space_api_key"]="spaceApiKey:[\"']([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})[\"']"
    ["asana_access_token"]="[0-9]{16}:[0-9a-fA-F]{32}"
    ["azure_tenant"]="[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"
    ["github_ssh_key"]="ssh-rsa AAAA[0-9A-Za-z+/]+[=]{0,3}" # More specific start
    ["github_token"]="gh[ps]_[a-zA-Z0-9]{36}"
    ["gitlab_private_token"]="glpat-[0-9a-zA-Z-_]{20}"
    ["salesforce_access_token"]="00D[a-zA-Z0-9]{12,15}" # Might need refinement based on actual token format
    ["sendgrid_api_key"]="SG\.[a-zA-Z0-9-_]{22}\.[a-zA-Z0-9-_]{43}"
    ["slack_webhook"]="https://hooks\.slack\.com/services/T[a-zA-Z0-9]{8,}/B[a-zA-Z0-9]{8,}/[a-zA-Z0-9]{24}"
    ["slack_api_token"]="xox[pbar]-[0-9]{10,13}-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{32}"
    ["square_secret"]="sq0[a-z]{3}-[0-9A-Za-z-_]{43}"
    ["square_auth_token"]="EAAA[a-zA-Z0-9]{60}"
    ["twilio_sid_token"]="SK[0-9a-fA-F]{32}"
    ["twilio_account_sid"]="AC[a-zA-Z0-9]{32}"
    ["stripe_key_live"]="sk_live_[0-9a-zA-Z]{24,99}"
    ["stripe_key_test"]="sk_test_[0-9a-zA-Z]{24,99}"
    ["stripe_publishable_key"]="pk_(?:test|live)_[0-9a-zA-Z]{24,99}" # Same as checkout, context matters
    ["zapier_webhook"]="https://hooks\.zapier\.com/hooks/catch/[0-9]{7,10}/[a-zA-Z0-9]{8}"
    ["heroku_api_key"]="[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"
    ["mailgun_api_key"]="key-[0-9a-zA-Z]{32}"
    ["private_key"]="-----BEGIN PRIVATE KEY-----[a-zA-Z0-9\s/+=]+-----END PRIVATE KEY-----"
    ["paypal_braintree_access_token"]="access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}"
    ["cloudflare_api_token"]="CFPAT-[0-9A-Za-z]{43}"
    ["dropbox_api_token"]="sl\.[A-Za-z0-9]{64}"
    ["firebase_custom_token"]="eyJ[A-Za-z0-9\-_=]+\.[A-Za-z0-9\-_=]+\.[A-Za-z0-9\-_=]+" # Same as JWT, context matters
    ["instagram_access_token"]="IGQV[A-Za-z0-9]+"
    ["securitytrails_key"]="st_[0-9A-Za-z]{32}"
    ["recaptcha_site_key"]="siteKey: ?'([^']+)'"
    ["recaptcha_site_key_mobile"]="siteKeyMobile: ?'([^']+)'"
    ["amplitude_key"]="key: ?'([^']+)'"
    ["sentry_dsn"]="sentryDsn: ?'([^']+)'"
    ["firebase_appId"]="appId:\"[0-9]+:[0-9]+:[a-z0-9]+:[a-z0-9]+\""
    ["firebase_databaseURL"]="databaseURL:\"https://[a-zA-Z0-9-]+\.firebaseio\.com\""
    ["openai_key"]="sk-[a-zA-Z0-9]{48}"
    ["google_ai_key"]="AIza[0-9A-Za-z\\-_]{35}" # Same as google_api
    ["anthropic_key"]="sk-ant-api[0-9]{2}-[a-zA-Z0-9\-_]{95}" # Example format
    ["cohere_key"]="[a-zA-Z0-9]{40}" # Example format
    ["shodan_key"]="[a-zA-Z0-9]{32}"
    ["twitter_api_secret"]="[a-zA-Z0-9]{50}" # Example format
    ["twitter_bearer_token"]="AAAA[a-zA-Z0-9%]{100,}" # Example format
    ["spotify_access_token"]="BQ[a-zA-Z0-9\-_]+" # Example format
)

# === Secret Finding Phase ===

echo "Starting secret finding phase..."
# Initialize the first output file (overwrite if exists)
> "$output_file"

# --- Processing Logic ---
if [[ ${#input_urls[@]} -gt 0 ]]; then
    # --- Processing for -i (URLs or file with URLs/lines) ---
    processed_count=0
    total_inputs=${#input_urls[@]}
    echo "Processing $total_inputs inputs from -i list..."

    for input_item in "${input_urls[@]}"; do
        ((processed_count++))
        # Trim whitespace and skip empty lines
        input_item=$(echo "$input_item" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//') # Trim leading/trailing whitespace
        [[ -z "$input_item" ]] && { $debug && echo "Skipping empty input line."; continue; }

        $debug && echo "Processing input $processed_count/$total_inputs: $input_item"

        # Download content (handles file path, URL, or direct text)
        content=$(download_url "$input_item")
        if [[ -z "$content" ]]; then
            $debug && echo "Warning: No content retrieved for $input_item"
            continue
        fi

        # If content looks like HTML, try to extract and process JS files
        # Use simple check for <html> tag
        if grep -qi "<html" <<< "$content"; then
            if [[ $debug == true ]]; then
                echo "Detected HTML for $input_item, extracting JS URLs..."
            fi
            readarray -t js_urls < <(extract_js_urls "$content")
            if [[ ${#js_urls[@]} -gt 0 ]]; then
                $debug && echo "Found ${#js_urls[@]} potential JS URLs."
                for js_url in "${js_urls[@]}"; do
                    # Construct absolute URL if needed (basic example)
                    if [[ ! "$js_url" == http* && "$input_item" == http* ]]; then
                        base_url=$(echo "$input_item" | grep -oP '^https?://[^/]+')
                        # Handle relative paths starting with /
                        if [[ "$js_url" == /* ]]; then
                            js_url="${base_url}${js_url}"
                        else
                            # Basic handling for relative paths in the same dir (needs improvement for ../)
                            base_dir=$(dirname "$input_item")
                            js_url="${base_dir}/${js_url}"
                        fi
                    fi
                    $debug && echo "  Fetching JS content from: $js_url"
                    js_content=$(download_url "$js_url")
                    if [[ -n "$js_content" ]]; then
                         $debug && echo "  Appending JS content (length: ${#js_content})"
                         content+=$'\n'"$js_content" # Append JS content
                    else
                         $debug && echo "  Warning: Failed to fetch JS content from $js_url"
                    fi
                done
            else
                 $debug && echo "No JS URLs found in HTML."
            fi
        fi

        # Search for patterns in the combined content (original + JS if any)
        found_in_item=false
        for key_type in "${!patterns[@]}"; do
            $debug && echo "  Searching for $key_type in content from $input_item..."
            # Use grep with PCRE (-P) and only matching (-o)
            # Use <<< for here-string to avoid issues with content starting with '-'
            # Capture results into an array to avoid issues with the while loop subshell
            readarray -t matches < <(grep -oP "${patterns[$key_type]}" <<< "$content" 2>/dev/null)
            if [[ ${#matches[@]} -gt 0 ]]; then
                for match in "${matches[@]}"; do
                    # Check if this exact match was already found (basic deduplication)
                    if ! grep -Fxq "$key_type -> $match" "$output_file"; then
                        echo "$key_type -> $match" >> "$output_file"
                        $debug && echo "    Found $key_type: $match"
                        found_in_item=true
                    fi
                done
            fi
        done
         $debug && ! $found_in_item && echo "  No new secrets found for $input_item."

    done
    echo "Finished processing $total_inputs inputs from -i list."
    # --- End of -i processing loop ---

elif [[ -n "$input_text_file" ]]; then
    # --- Processing logic for -f (single text file) ---
    echo "Processing single text file: $input_text_file"

    # Read the entire file content directly
    content=$(<"$input_text_file") # Efficient way to read whole file

    if [[ -z "$content" ]]; then
         echo "Warning: Input file '$input_text_file' is empty."
    else
        $debug && echo "File content loaded (length: ${#content}). Searching for secrets..."
        # Search for patterns directly in the file content
        found_in_file=false
        for key_type in "${!patterns[@]}"; do
            $debug && echo "  Searching for $key_type in $input_text_file..."
            readarray -t matches < <(grep -oP "${patterns[$key_type]}" <<< "$content" 2>/dev/null)
             if [[ ${#matches[@]} -gt 0 ]]; then
                for match in "${matches[@]}"; do
                     if ! grep -Fxq "$key_type -> $match" "$output_file"; then
                        echo "$key_type -> $match" >> "$output_file"
                        $debug && echo "    Found $key_type: $match"
                        found_in_file=true
                    fi
                done
            fi
        done
         $debug && ! $found_in_file && echo "  No new secrets found in $input_text_file."
    fi
    echo "Finished processing $input_text_file."
    # --- End of -f processing logic ---
fi

# --- Post-processing for Secret Finding Phase ---

# Check if any secrets were found and report
if [[ -s "$output_file" ]]; then
    echo "Initial secret finding completed. Potential secrets saved to: $output_file"
    # Generate HTML report if requested
    if [[ $html_output == true ]]; then
        generate_html_report "$output_file" "$html_report_file"
    fi
else
    echo "No potential secrets found in the provided input(s)."
    # Exit here if no secrets found, as testing phase is pointless
    exit 0
fi


# === Key Testing Phase ===
echo ""
echo "----------------------------------"
echo "Starting key testing phase..."

# Set the input file for testing phase explicitly
key_test_input_file="$output_file" # Use the findings from the first phase

# Initialize the key testing output file
echo "API Key Testing Results" > "$key_test_output_file"
echo "==================================" >> "$key_test_output_file"
echo "Input source: $key_test_input_file" >> "$key_test_output_file"
echo "Timestamp: $(date)" >> "$key_test_output_file"
echo "" >> "$key_test_output_file"

# --- Key Testing Helper Functions ---

# Function to update key status in the testing output file
# Uses pipe | as sed delimiter to avoid issues with keys containing /
update_status() {
    local key="$1"
    local status="$2"
    # Escape potential regex special characters in the key for sed
    local escaped_key=$(sed -e 's/[&\\/|*^$]/\\&/g' <<< "$key")
    # Use | as delimiter. Match the line precisely.
    sed -i "s|Value: $escaped_key$|Value: $escaped_key [Status: $status]|" "$key_test_output_file"
}

# Function to extract keys of a specific type and call the test function
extract_and_test() {
    local pattern_label="$1" # The label used in the findings file (e.g., "google_api")
    local key_type_desc="$2" # Description for the output file (e.g., "Google API Keys")
    local test_function="$3" # Name of the bash function to call for testing

    # Check if the test function actually exists
    if ! declare -F "$test_function" > /dev/null; then
        echo "Warning: Test function '$test_function' not found. Skipping tests for '$key_type_desc'." >> "$key_test_output_file"
        echo "" >> "$key_test_output_file"
        return
    fi

    echo "=== $key_type_desc ===" >> "$key_test_output_file"
    found_keys_for_type=false

    # Grep for the specific label at the beginning of the line in the findings file
    grep "^$pattern_label ->" "$key_test_input_file" | while IFS= read -r line; do
        # Extract the value after " -> "
        if [[ $line =~ ^.*\ -\>\ (.*)$ ]]; then
            key_value="${BASH_REMATCH[1]}"
            # Avoid testing empty values if regex somehow matched incorrectly
            if [[ -n "$key_value" ]]; then
                echo "Value: $key_value" >> "$key_test_output_file"
                found_keys_for_type=true
                # Test the key immediately
                $test_function "$key_value"
            fi
        fi
    done

    # Add a message if no keys of this type were found in the input file
     if ! $found_keys_for_type; then
         echo "No keys of this type found in $key_test_input_file." >> "$key_test_output_file"
     fi

    echo "" >> "$key_test_output_file"
}

# --- Individual Key Test Functions ---
# (Includes timeouts [-m 5] for curl calls)

test_google_key() {
    local key="$1"; local status="INVALID"
    response=$(curl -s -m 5 -H "referer: http://example.com" \
         "https://maps.googleapis.com/maps/api/directions/json?origin=Stockholm&destination=Kalmar&key=$key")
    if [[ $response != *"error_message"* && $response == *"routes"* ]]; then status="VALID"; fi
    update_status "$key" "$status"
}

test_aws_key() {
    local key="$1"; local status="INVALID"
    # Requires AWS CLI configured, but attempts basic check even without full config
    export AWS_ACCESS_KEY_ID="$key"
    export AWS_SECRET_ACCESS_KEY="dummy_secret_for_test" # Need a placeholder
    export AWS_DEFAULT_REGION="us-east-1"
    response=$(aws sts get-caller-identity --output text 2>&1)
    if [[ $response == *"InvalidClientTokenId"* ]]; then status="INVALID";
    elif [[ $response == *"SignatureDoesNotMatch"* ]]; then status="VALID-NEEDS-SECRET";
    elif [[ $response == *"Account"* ]]; then status="VALID"; # Successful call
    else status="UNKNOWN"; fi
    unset AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_DEFAULT_REGION
    update_status "$key" "$status"
}

test_aws_secret_key() {
    local secret="$1"; local status="INVALID"
    export AWS_ACCESS_KEY_ID="dummy_access_key_for_test"
    export AWS_SECRET_ACCESS_KEY="$secret"
    export AWS_DEFAULT_REGION="us-east-1"
    response=$(aws sts get-caller-identity --output text 2>&1)
    if [[ $response == *"InvalidClientTokenId"* ]]; then status="VALID-NEEDS-ACCESS-KEY"; # Secret might be ok if Access Key is wrong
    elif [[ $response == *"SignatureDoesNotMatch"* ]]; then status="INVALID"; # Secret is likely wrong
    elif [[ $response == *"Account"* ]]; then status="VALID"; # Should not happen with dummy access key, but check anyway
    else status="UNKNOWN"; fi
    unset AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_DEFAULT_REGION
    update_status "$secret" "$status"
}


test_heroku_key() {
    local key="$1"; local status="INVALID"
    response=$(curl -s -m 5 -X GET \
        -H "Accept: application/vnd.heroku+json; version=3" \
        -H "Authorization: Bearer $key" \
        "https://api.heroku.com/account")
    if [[ $response == *"\"id\":"* ]]; then status="VALID"; fi
    update_status "$key" "$status"
}

test_twilio_sid() {
    local sid="$1"; local status="INVALID"
    # Test requires a valid token, so we check if the SID format is recognized
    response=$(curl -s -m 5 -X GET "https://api.twilio.com/2010-04-01/Accounts/$sid.json" \
        -u "$sid:dummy_token_for_test")
    if [[ $response == *"\"status\": \"active\""* || $response == *"\"status\": \"suspended\""* ]]; then status="VALID-SID-NEEDS-TOKEN";
    elif [[ $response == *"authenticate"* ]]; then status="VALID-SID-NEEDS-TOKEN"; # Also indicates SID exists
    elif [[ $response == *"not found"* || $response == *"Resource not found"* ]]; then status="INVALID";
    else status="UNKNOWN"; fi
    update_status "$sid" "$status"
}

test_twilio_sid_token() {
    local key="$1"; local status="INVALID"
    # Testing SID tokens (SK...) is harder without knowing the associated Account SID
    # We can make a generic API call that might work with just the key/secret pair
    # This is a placeholder - a better test might involve a specific API endpoint
    # For now, mark as POTENTIALLY-VALID if format matches, actual testing is complex.
    if [[ "$key" =~ ^SK[0-9a-fA-F]{32}$ ]]; then status="POTENTIALLY-VALID"; fi
    update_status "$key" "$status"
}


test_facebook_token() {
    local token="$1"; local status="INVALID"
    response=$(curl -s -m 5 "https://graph.facebook.com/v13.0/me?access_token=$token")
    if [[ $response == *"\"id\":"* ]]; then status="VALID"; fi
    update_status "$token" "$status"
}

test_firebase_api_key() {
    local key="$1"; local status="INVALID"
    # Test against a common Firebase service like Dynamic Links or Firestore (requires project setup)
    # Using Dynamic Links as an example
    local data='{"longDynamicLink": "https://example.page.link/?link=https://www.example.com/"}' # Generic example
    response=$(curl -s -m 5 -X POST "https://firebasedynamiclinks.googleapis.com/v1/shortLinks?key=$key" \
        -H 'Content-Type: application/json' -d "$data")
    # Check for specific error message indicating invalid key
    if [[ $response != *"API key not valid"* && $response != *"invalid API key"* ]]; then
        # If no invalid key error, it might be valid but lack permissions, or be valid.
        status="POTENTIALLY-VALID"
        if [[ $response == *"shortLink"* ]]; then status="VALID"; fi # Definitively valid if it works
    fi
    update_status "$key" "$status"
}

test_firebase_custom_token() {
    local token="$1"; local status="INVALID"
    # This tests if the token *format* is accepted by the endpoint. Doesn't guarantee validity for a specific project.
    response=$(curl -s -m 5 -X POST \
        -H "Content-Type: application/json" \
        -d "{\"token\":\"$token\",\"returnSecureToken\":true}" \
        "https://identitytoolkit.googleapis.com/v1/accounts:signInWithCustomToken?key=dummyKey") # Dummy API key needed for endpoint structure
    if [[ $response == *"idToken"* ]]; then status="VALID-FORMAT"; # Token format accepted
    elif [[ $response == *"INVALID_CUSTOM_TOKEN"* ]]; then status="INVALID";
    else status="UNKNOWN"; fi
    update_status "$token" "$status"
}

test_github_token() {
    local token="$1"; local status="INVALID"
    response=$(curl -s -m 5 -H "Authorization: token $token" "https://api.github.com/user")
    if [[ $response == *"\"login\":"* ]]; then status="VALID"; fi
    update_status "$token" "$status"
}

test_instagram_token() {
    local token="$1"; local status="INVALID"
    # Instagram Graph API requires permissions, basic check:
    response=$(curl -s -m 5 "https://graph.instagram.com/me?fields=id&access_token=$token")
    if [[ $response == *"\"id\":"* ]]; then status="VALID"; fi
    update_status "$token" "$status"
}

test_salesforce_token() {
    local token="$1"; local status="INVALID"
    # Requires knowing the instance URL, trying common login URL
    response=$(curl -s -m 5 -H "Authorization: Bearer $token" "https://login.salesforce.com/services/oauth2/userinfo")
    if [[ $response == *"\"user_id\":"* ]]; then status="VALID"; fi
    update_status "$token" "$status"
}

test_zendesk_token() {
    local token="$1"; local status="INVALID"
    # Requires knowing the Zendesk domain, cannot test generically
    status="UNKNOWN-NEEDS-DOMAIN"
    update_status "$token" "$status"
}

test_openai_key() {
    local key="$1"; local status="INVALID"
    response=$(curl -s -m 5 -H "Authorization: Bearer $key" "https://api.openai.com/v1/models")
    if [[ $response == *"\"object\": \"list\""* && $response == *"\"data\""* ]]; then status="VALID"; fi
    update_status "$key" "$status"
}

test_google_ai_key() {
    local key="$1"; local status="INVALID"
    # Test against Generative Language API (Gemini)
    response=$(curl -s -m 5 "https://generativelanguage.googleapis.com/v1beta/models?key=$key")
    if [[ $response == *"\"models\""* ]]; then status="VALID"; fi
    update_status "$key" "$status"
}

test_anthropic_key() {
    local key="$1"; local status="INVALID"
    response=$(curl -s -m 5 -H "x-api-key: $key" -H "anthropic-version: 2023-06-01" "https://api.anthropic.com/v1/messages" -d '{"model": "claude-3-opus-20240229", "max_tokens": 1, "messages": [{"role": "user", "content": "test"}]}')
    # Check for authentication error specifically
    if [[ $response != *"authentication_error"* ]]; then status="POTENTIALLY-VALID"; fi
    update_status "$key" "$status"
}

test_cohere_key() {
    local key="$1"; local status="INVALID"
    response=$(curl -s -m 5 -H "Authorization: Bearer $key" "https://api.cohere.ai/v1/models")
    if [[ $response == *"\"models\""* ]]; then status="VALID"; fi
    update_status "$key" "$status"
}

test_twitter_api_secret() {
    local secret="$1"; local status="INVALID"
    # Testing API secret alone is difficult. Usually used with API key.
    status="UNKNOWN-NEEDS-API-KEY"
    update_status "$secret" "$status"
}

test_twitter_bearer_token() {
    local token="$1"; local status="INVALID"
    # Test against v2 endpoint
    response=$(curl -s -m 5 -H "Authorization: Bearer $token" "https://api.twitter.com/2/tweets/search/recent?query=test")
    # Look for specific auth errors
    if [[ $response != *"Unauthorized"* && $response != *"Authentication credentials"* ]]; then status="POTENTIALLY-VALID"; fi
    update_status "$token" "$status"
}

test_spotify_access_token() {
    local token="$1"; local status="INVALID"
    response=$(curl -s -m 5 -H "Authorization: Bearer $token" "https://api.spotify.com/v1/me")
    if [[ $response == *"\"id\":"* ]]; then status="VALID"; fi
    update_status "$token" "$status"
}

test_square_secret() {
    local secret="$1"; local status="INVALID"
    # Test against locations endpoint (common check)
    response=$(curl -s -m 5 -H "Authorization: Bearer $secret" -H "Square-Version: 2023-10-18" "https://connect.squareup.com/v2/locations")
    if [[ $response == *"\"locations\""* ]]; then status="VALID"; fi
    update_status "$secret" "$status"
}

test_slack_api_token() {
    local token="$1"; local status="INVALID"
    response=$(curl -s -m 5 -H "Authorization: Bearer $token" "https://slack.com/api/auth.test")
    if [[ $response == *"\"ok\":true"* ]]; then status="VALID"; fi
    update_status "$token" "$status"
}

test_recaptcha_site_key() {
    local key="$1"; local status="INVALID"
    # Site keys (6L...) are public, cannot be validated server-side like secret keys.
    # Mark as public info.
    status="PUBLIC-INFO"
    update_status "$key" "$status"
}

test_recaptcha_site_key_mobile() {
    # Same as above, site keys are public.
    local key="$1"; local status="PUBLIC-INFO"
    update_status "$key" "$status"
}

test_braze_api_key() {
    local key="$1"; local status="INVALID"
    # Requires knowing the Braze instance URL (e.g., rest.iad-01.braze.com)
    status="UNKNOWN-NEEDS-INSTANCE-URL"
    update_status "$key" "$status"
}

test_checkout_key() {
    local key="$1"; local status="INVALID"
    # Public keys (pk_...) cannot be validated directly without a transaction attempt.
    if [[ "$key" == pk_* ]]; then status="PUBLIC-KEY"; else status="UNKNOWN"; fi
    update_status "$key" "$status"
}

test_amplitude_key() {
    local key="$1"; local status="INVALID"
    # Amplitude keys are typically public for client-side use.
    status="PUBLIC-KEY"
    update_status "$key" "$status"
}

test_user_snap_space_api_key() {
    local key="$1"; local status="INVALID"
    # Requires authentication, likely needs more than just the space key.
    status="UNKNOWN-COMPLEX-AUTH"
    update_status "$key" "$status"
}

test_azure_tenant() {
    local key="$1"; local status="INVALID"
    # Check the OpenID configuration endpoint
    response=$(curl -s -m 5 "https://login.microsoftonline.com/$key/v2.0/.well-known/openid-configuration")
    if [[ $response == *"tenant_region_scope"* ]]; then status="VALID-TENANT-ID"; fi
    update_status "$key" "$status"
}

test_shodan_key() {
    local key="$1"; local status="INVALID"
    response=$(curl -s -m 5 "https://api.shodan.io/api-info?key=$key")
    if [[ $response == *"\"plan\":"* ]]; then status="VALID"; fi
    update_status "$key" "$status"
}

test_cloudflare_token() {
    local key="$1"; local status="INVALID"
    response=$(curl -s -m 5 -H "Authorization: Bearer $key" "https://api.cloudflare.com/client/v4/user/tokens/verify")
    if [[ $response == *"\"success\":true"* ]]; then status="VALID"; fi
    update_status "$key" "$status"
}

test_dropbox_token() {
    local key="$1"; local status="INVALID"
    response=$(curl -s -m 5 -X POST "https://api.dropboxapi.com/2/users/get_current_account" -H "Authorization: Bearer $key")
    # Check for account_id or specific auth error
    if [[ $response == *"account_id"* ]]; then status="VALID";
    elif [[ $response == *"invalid_access_token"* ]]; then status="INVALID";
    else status="UNKNOWN"; fi
    update_status "$key" "$status"
}

test_securitytrails_key() {
    local key="$1"; local status="INVALID"
    response=$(curl -s -m 5 -H "APIKEY: $key" "https://api.securitytrails.com/v1/ping")
    if [[ $response == *"\"success\":true"* ]]; then status="VALID"; fi
    update_status "$key" "$status"
}

test_sentry_dsn() {
    local key="$1"; local status="INVALID"
    # DSNs are typically public for client-side error reporting.
    status="PUBLIC-DSN"
    update_status "$key" "$status"
}

test_firebase_databaseURL() {
    local url="$1"; local status="INVALID"
    # Validate format and try a basic .json request (might require auth)
    if [[ "$url" == https://*.firebaseio.com ]]; then
        status="VALID-URL-FORMAT"
        # Optional: Try fetching root (may fail due to permissions)
        # response=$(curl -s -m 3 "${url}/.json?print=silent")
        # if [[ $? -eq 0 && $response != *"error"* ]]; then status="VALID-URL-ACCESSIBLE"; fi
    fi
    update_status "$url" "$status"
}

test_firebase_appId() {
    local id="$1"; local status="INFO"
    # App IDs are configuration info, not secrets.
    status="CONFIG-INFO"
    update_status "$id" "$status"
}


# --- Main Key Testing Execution ---

# Extract and test keys for each type defined in the patterns and having a test function
# Use the labels from the patterns array as the first argument to extract_and_test
extract_and_test "google_api" "Google API Keys" test_google_key
extract_and_test "amazon_aws_access_key_id" "AWS Access Keys" test_aws_key
extract_and_test "amazon_aws_secret_access_key" "AWS Secret Keys" test_aws_secret_key
extract_and_test "heroku_api_key" "Heroku API Keys" test_heroku_key
extract_and_test "twilio_account_sid" "Twilio Account SIDs" test_twilio_sid
extract_and_test "twilio_sid_token" "Twilio SID Tokens (SK...)" test_twilio_sid_token
extract_and_test "facebook_access_token" "Facebook Access Tokens" test_facebook_token
extract_and_test "firebase_api_key" "Firebase API Keys (Standalone)" test_firebase_api_key
extract_and_test "firebase_config_apikey" "Firebase API Keys (from Config)" test_firebase_api_key # Use same test
extract_and_test "firebase_custom_token" "Firebase Custom Tokens" test_firebase_custom_token
extract_and_test "github_token" "GitHub Tokens" test_github_token
extract_and_test "instagram_access_token" "Instagram Access Tokens" test_instagram_token
extract_and_test "salesforce_access_token" "Salesforce Access Tokens" test_salesforce_token
extract_and_test "zendesk_access_token" "Zendesk Access Tokens" test_zendesk_token # Will mark as UNKNOWN
extract_and_test "openai_key" "OpenAI API Keys" test_openai_key
extract_and_test "google_ai_key" "Google AI API Keys" test_google_ai_key
extract_and_test "anthropic_key" "Anthropic API Keys" test_anthropic_key
extract_and_test "cohere_key" "Cohere API Keys" test_cohere_key
extract_and_test "twitter_api_secret" "Twitter API Secrets" test_twitter_api_secret # Will mark as UNKNOWN
extract_and_test "twitter_bearer_token" "Twitter Bearer Tokens" test_twitter_bearer_token
extract_and_test "spotify_access_token" "Spotify Access Tokens" test_spotify_access_token
extract_and_test "square_secret" "Square Secrets" test_square_secret
extract_and_test "slack_api_token" "Slack API Tokens" test_slack_api_token
extract_and_test "recaptcha_site_key" "reCAPTCHA Site Keys (from Config)" test_recaptcha_site_key # Will mark as PUBLIC
extract_and_test "google_captcha" "reCAPTCHA Site Keys (Standalone)" test_recaptcha_site_key # Use same test
extract_and_test "recaptcha_site_key_mobile" "reCAPTCHA Mobile Site Keys" test_recaptcha_site_key_mobile # Will mark as PUBLIC
extract_and_test "braze_api_key" "Braze API Keys" test_braze_api_key # Will mark as UNKNOWN
extract_and_test "checkout_key" "Checkout Keys (pk_...)" test_checkout_key # Will mark as PUBLIC
extract_and_test "checkout_config_key" "Checkout Keys (from Config)" test_checkout_key # Use same test
extract_and_test "amplitude_key" "Amplitude Keys" test_amplitude_key # Will mark as PUBLIC
extract_and_test "user_snap_space_api_key" "UserSnap Space API Keys" test_user_snap_space_api_key # Will mark as UNKNOWN
extract_and_test "sentry_dsn" "Sentry DSNs" test_sentry_dsn # Will mark as PUBLIC
extract_and_test "firebase_appId" "Firebase App IDs" test_firebase_appId # Will mark as INFO
extract_and_test "firebase_databaseURL" "Firebase Database URLs" test_firebase_databaseURL # Will mark as VALID-URL-FORMAT
extract_and_test "azure_tenant" "Azure Tenant IDs" test_azure_tenant # Will mark as VALID-TENANT-ID
extract_and_test "cloudflare_api_token" "Cloudflare API Tokens" test_cloudflare_token
extract_and_test "dropbox_api_token" "Dropbox API Tokens" test_dropbox_token
extract_and_test "securitytrails_key" "SecurityTrails API Keys" test_securitytrails_key
extract_and_test "shodan_key" "Shodan API Keys" test_shodan_key


# --- Final Cleanup and Output for Testing Phase ---

# Remove empty sections (where no keys of a type were found)
# This sed command looks for a "=== Title ===" line followed immediately by a blank line and deletes both.
sed -i '/^===.*===$/{N;/^\n$/d}' "$key_test_output_file"

echo "Key testing phase complete."
echo "Detailed testing results saved to: $key_test_output_file"
echo ""
echo "--- Tested Key Summary ---"
cat "$key_test_output_file"
echo "--- End of Summary ---"


# === Firebase Data Fetching (Optional Example) ===

# Function to attempt fetching data using found Firebase credentials
fetch_firebase_data() {
    local api_key="$1"
    local db_url="$2"
    local output_file="$3" # File to append results to

    echo "" >> "$output_file"
    echo "--- Firebase Data Fetch Attempt ---" >> "$output_file"
    echo "Using API Key: $api_key" >> "$output_file"
    echo "Using DB URL: $db_url" >> "$output_file"

    # Construct endpoint (using '.json' as the default path for Firebase Realtime Database)
    local endpoint="${db_url}/.json?auth=${api_key}"
    echo "Attempting to fetch from: ${endpoint}" >> "$output_file"

    local result
    # Use timeout for the curl request
    result=$(curl -s -m 10 "$endpoint")
    local curl_exit_code=$?

    if [[ $curl_exit_code -ne 0 ]]; then
         echo "Error: curl command failed with exit code $curl_exit_code." >> "$output_file"
         echo "Failed to fetch data from Firebase." >> "$output_file"
    elif [[ -z "$result" ]]; then
        echo "Result: No data returned or empty response (check permissions or URL)." >> "$output_file"
    elif [[ "$result" == *"error"* || "$result" == *"Permission denied"* ]]; then
        echo "Result: Received an error response (likely permission denied)." >> "$output_file"
        echo "Response snippet: $(echo "$result" | head -c 200)" >> "$output_file" # Show beginning of error
    else
        echo "Result: Successfully fetched data!" >> "$output_file"
        echo "--- Fetched Data Start ---" >> "$output_file"
        # Try to pretty-print if jq is available
        if command -v jq >/dev/null 2>&1; then
            echo "$result" | jq . >> "$output_file"
        else
            echo "$result" >> "$output_file"
        fi
         echo "--- Fetched Data End ---" >> "$output_file"
    fi
     echo "---------------------------------" >> "$output_file"
     # Also print to console
     echo "Firebase fetch attempt logged to $output_file"
}

# Attempt Firebase fetch only if potentially valid keys/URLs were found
# Extract the *first* potentially valid Firebase API key and Database URL found during testing
firebase_api_key_found=$(grep '\[Status: \(POTENTIALLY-\)*VALID.*\]' "$key_test_output_file" | grep -m 1 -E "^Value: (AIza[0-9A-Za-z\\-_]{35})" | sed -nE 's/^Value: (AIza[0-9A-Za-z\\-_]{35}).*/\1/p')
firebase_databaseURL_found=$(grep '\[Status: VALID-URL-FORMAT.*\]' "$key_test_output_file" | grep -m 1 -E "^Value: (https://[a-zA-Z0-9-]+\.firebaseio\.com)" | sed -nE 's/^Value: (https:\/\/[a-zA-Z0-9-]+\.firebaseio\.com).*/\1/p')

if [[ -n "$firebase_api_key_found" && -n "$firebase_databaseURL_found" ]]; then
    echo ""
    echo "Found potentially valid Firebase credentials. Attempting to fetch data..."
    fetch_firebase_data "$firebase_api_key_found" "$firebase_databaseURL_found" "$key_test_output_file" # Append to test results file
else
    $debug && echo "Did not find both a potentially valid Firebase API key and Database URL in tested results. Skipping data fetch."
fi

echo ""
echo "Script finished."
