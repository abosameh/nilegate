#!/bin/bash
#awk -F'src="|"' '/script/{for(i=1;i<=NF;i++) if($i~/\.js/) print $i}' 2.txt
# === Secret Finder Section (from secret_finder.sh) ===
#!/bin/bash

# Configuration
output_file="secrets_found.txt"
debug=true
input_urls=()
html_output=false

# Function to display usage
usage() {
    echo "Usage: $0 [-i input_file/url] [-o output_file] [-H] [-d]"
    echo "  -i : Input file or URL"
    echo "  -o : Output file (default: secrets_found.txt)"
    echo "  -H : Generate HTML output"
    echo "  -d : Debug mode"
    exit 1
}
# curl -s https://www.coinhako.com/ | grep -oP '(?<=href=")[^"]+(?=")' | grep -E '\.js$'
# Function to download URL content
download_url() {
    local input="$1"
    if [[ -f "$input" ]]; then
        cat "$input"
    elif [[ "$input" == http* ]]; then
        curl -sk "$input"
    else
        # Assume input is raw text content
        echo "$input"
    fi
}

# Function to extract JS URLs from HTML
extract_js_urls() {
    local content=$1
    grep -oP 'src=["'\'']\K[^"'\'']+\.js' <<< "$content" | grep -v '^//'
}

# Function to generate HTML report
generate_html_report() {
    local output=$1
    cat > "$output" << EOF
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <style>
        body { font-family: Arial, sans-serif; }
        .secret { 
            margin: 10px;
            padding: 10px;
            border: 1px solid #ccc;
            background-color: #f9f9f9;
        }
        .type { font-weight: bold; color: #2c3e50; }
        .match { background-color: #fff3cd; padding: 2px 5px; }
    </style>
    <title>Secret Finder Report</title>
</head>
<body>
    <h1>Secret Finder Report</h1>
    <div id="results">
$(cat "$output_file" | while read line; do
    echo "<div class='secret'>"
    echo "<span class='type'>$line</span>"
    echo "</div>"
done)
    </div>
</body>
</html>
EOF
}

# Parse arguments
while getopts "i:o:Hd" opt; do
    case $opt in
        i) 
            # If input is a file, read all URLs into the array
            if [[ -f "$OPTARG" ]]; then
                readarray -t input_urls < "$OPTARG"
            else
                input_urls+=("$OPTARG")
            fi
            ;;
        o) output_file="$OPTARG";;
        H) html_output=true;;
        d) debug=true;;
        ?) usage;;
    esac
done

# Verify we have input
if [ ${#input_urls[@]} -eq 0 ]; then
    echo "Error: No input URLs provided"
    usage
fi

# Define patterns for different keys
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
        ["amazon_aws_session_token"]="FwoGZXIvYXdzEJj//////////wEaDGJ7Lj7KJ7rKvFJ7yLrK+J"
	["google_captcha"]="6L[0-9A-Za-z-_]{38}"
	["google_oauth"]="ya29\\.[0-9A-Za-z\\-_]+"
	["firebase_api_key"]="(?:AIza[0-9A-Za-z-_]{35}|apiKey: ?'([^']+)')"
	["checkout_key"]="(?:pk_[0-9a-zA-Z]{24,99}|checkoutKey: ?'([^']+)')"
	["braze_api_key"]="[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}"
	["user_snap_space_api_key"]="spaceApiKey:\"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\""
	["asana_access_token"]="[0-9]{16}:[0-9a-fA-F]{32}"
	["azure_tenant"]="[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"
	["github_ssh_key"]="ssh-rsa [A-Za-z0-9+/]+[=]{0,3}"
	["github_token"]="gh[ps]_[a-zA-Z0-9]{36}"
	["gitlab_private_token"]="glpat-[0-9a-zA-Z-_]{20}"
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
	["cloudflare_api_token"]="CFPAT-[0-9A-Za-z]{43}"  
        ["dropbox_api_token"]="sl\.[A-Za-z0-9]{64}"  
        ["firebase_custom_token"]="eyJ[A-Za-z0-9\-_=]+\.[A-Za-z0-9\-_=]+\.[A-Za-z0-9\-_=]+"  
        ["instagram_access_token"]="IGQV[A-Za-z0-9]+"  
        ["securitytrails_key"]="st_[0-9A-Za-z]{32}"  
        ["recaptcha_site_key"]="siteKey: ?'([^']+)'"
        ["recaptcha_site_key_mobile"]="siteKeyMobile: ?'([^']+)'"
        ["amplitude_key"]="key: ?'([^']+)'"
        ["sentry_dsn"]="sentryDsn: ?'([^']+)'"
        ["firebase_appId"]="appId:\"[0-9]+:[0-9]+:[a-z0-9]+:[a-z0-9]+\""
        ["firebase_databaseURL"]="databaseURL:\"https://[a-zA-Z0-9-]+\.firebaseio\.com\""
        

    
)

# Debugging: Log the patterns being used
if [[ $debug == true ]]; then
    echo "Patterns being used for extraction:"
    for key_type in "${!patterns[@]}"; do
        echo "$key_type: ${patterns[$key_type]}"
    done
fi

# Initialize output file
> "$output_file"

# Process each input URL/file
for input in "${input_urls[@]}"; do
    # Trim whitespace and skip empty lines
    input=$(echo "$input" | tr -d '[:space:]')
    [[ -z "$input" ]] && continue

    if [[ $debug == true ]]; then
        echo "Processing: $input"
    fi

    # Read content from file or URL (download_url already uses cat if not an HTTP URL)
    content=$(download_url "$input")

    # Debugging: Log the content being processed
    if [[ $debug == true ]]; then
        echo "Content being processed for $input:"
        echo "$content"
    fi

    # If content is HTML, perform JS extraction; otherwise (for plain text files) skip this branch.
    if grep -q "<html" <<< "$content"; then
        # Extract JS URLs if it's HTML
        readarray -t js_urls < <(extract_js_urls "$content")
        for js_url in "${js_urls[@]}"; do
            $debug && echo "Found JS: $js_url"
            js_content=$(download_url "$js_url")
            [[ -n "$js_content" ]] && content+=$'\n'"$js_content"
        done
    fi

    # The plain text (including already extracted keys) is processed here.
    for key_type in "${!patterns[@]}"; do
        $debug && echo "Searching for $key_type..."
        grep -oP "${patterns[$key_type]}" <<< "$content" 2>/dev/null | while read -r match; do
            [[ -n "$match" ]] && {
                echo "$key_type -> $match" >> "$output_file"
                $debug && echo "Found $key_type: $match"
            }
        done
    done
done

# Generate HTML report if requested
if [[ $html_output == true ]]; then
    html_file="${output_file%.*}.html"
    generate_html_report "$html_file"
    echo "HTML report generated: $html_file"
fi

if [[ -s "$output_file" ]]; then
    echo "Found secrets have been saved to: $output_file"
else
    echo "No secrets found."
fi

# ...existing code...

# === End of Secret Finder Section ===

# Separator between secret finding and key testing
echo "Secret finding completed. Now testing keys..."

# === Key Testing Section (from keyhack3.sh) ===
# Replace the dynamic assignment with a fixed assignment
input_file="secrets_found.txt"    # Was: input_file="${1:-secrets_found.txt}"
output_file="found_keys.txt"

# Initialize output file
echo "API Key Detection and Testing Results" > "$output_file"
echo "==================================" >> "$output_file"
echo "" >> "$output_file"

# ...existing code from keyhack3.sh...
# Function definitions and tests
update_status() {
    local key="$1"
    local status="$2"
    sed -i "s|\(Value: $key\)$|\1 [Status: $status]|" "$output_file"
}
extract_and_test() {
    local pattern="$1"
    local key_type="$2"
    local test_function="$3"
    
    echo "=== $key_type ===" >> "$output_file"
    grep -i "$pattern.*->" "$input_file" | while read -r line; do
        if [[ $line =~ .*\-\>[[:space:]]*(.*)$ ]]; then
            key_value="${BASH_REMATCH[1]}"
            echo "Value: $key_value" >> "$output_file"
            $test_function "$key_value"
        fi
    done
    echo "" >> "$output_file"
}
test_google_key() {
    local key="$1"
    response=$(curl -s -m 5 -H "referer: http://example.com" \
         "https://maps.googleapis.com/maps/api/directions/json?origin=Stockholm&destination=Kalmar&key=$key")
    
    if [[ $response == *"error_message"* ]]; then
        update_status "$key" "INVALID"
    else
        update_status "$key" "VALID"
    fi
}
test_aws_key() {
    local key="$1"
    export AWS_ACCESS_KEY_ID="$key"
    export AWS_SECRET_ACCESS_KEY="dummy_secret"
    export AWS_DEFAULT_REGION="us-east-1"

    response=$(aws sts get-caller-identity 2>&1)
    
    if [[ $response == *"InvalidClientTokenId"* ]]; then
        update_status "$key" "INVALID"
    elif [[ $response == *"SignatureDoesNotMatch"* ]]; then
        update_status "$key" "VALID-NEEDS-SECRET"
    else
        update_status "$key" "POTENTIALLY-VALID"
    fi
    
    unset AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_DEFAULT_REGION
}
test_heroku_key() {
    local key="$1"
    response=$(curl -s -m 5 -X GET \
        -H "Accept: application/vnd.heroku+json; version=3" \
        -H "Authorization: Bearer $key" \
        "https://api.heroku.com/account")
    
    if [[ $response == *"id"* ]]; then
        update_status "$key" "VALID"
    else
        update_status "$key" "INVALID"
    fi
}
test_twilio_sid() {
    local sid="$1"
    response=$(curl -s -m 5 -X GET "https://api.twilio.com/2010-04-01/Accounts/$sid.json" \
        -u "$sid:dummy_token")
    
    if [[ $response == *"authenticate"* ]]; then
        update_status "$sid" "VALID-NEEDS-TOKEN"
    elif [[ $response == *"not found"* ]]; then
        update_status "$sid" "INVALID"
    else
        update_status "$sid" "UNKNOWN"
    fi
}
test_facebook_token() {
    local token="$1"
    response=$(curl -s -m 5 "https://graph.facebook.com/v13.0/me?access_token=$token")
    if [[ $response == *"id"* ]]; then
        update_status "$token" "VALID"
    else
        update_status "$token" "INVALID"
    fi
}
test_firebase_token() {
    local token="$1"
    response=$(curl -s -m 5 -X POST \
        -H "Content-Type: application/json" \
        -d "{\"token\":\"$token\"}" \
        "https://identitytoolkit.googleapis.com/v1/accounts:signInWithCustomToken")
    if [[ $response == *"idToken"* ]]; then
        update_status "$token" "VALID"
    else
        update_status "$token" "INVALID"
    fi
}
test_github_token() {
    local token="$1"
    response=$(curl -s -m 5 -H "Authorization: token $token" \
        "https://api.github.com/user")
    if [[ $response == *"login"* ]]; then
        update_status "$token" "VALID"
    else
        update_status "$token" "INVALID"
    fi
}
test_instagram_token() {
    local token="$1"
    response=$(curl -s -m 5 "https://graph.instagram.com/me?access_token=$token")
    if [[ $response == *"id"* ]]; then
        update_status "$token" "VALID"
    else
        update_status "$token" "INVALID"
    fi
}
test_salesforce_token() {
    local token="$1"
    response=$(curl -s -m 5 -H "Authorization: Bearer $token" \
        "https://login.salesforce.com/services/oauth2/userinfo")
    if [[ $response == *"user_id"* ]]; then
        update_status "$token" "VALID"
    else
        update_status "$token" "INVALID"
    fi
}
test_zendesk_token() {
    local token="$1"
    response=$(curl -s -m 5 -H "Authorization: Bearer $token" \
        "https://api.zendesk.com/api/v2/users/me")
    if [[ $response == *"email"* ]]; then
        update_status "$token" "VALID"
    else
        update_status "$token" "INVALID"
    fi
}
test_openai_key() {
    local key="$1"
    response=$(curl -s -m 5 -H "Authorization: Bearer $key" \
        -H "Content-Type: application/json" \
        "https://api.openai.com/v1/models")
    
    if [[ $response == *"data"* ]]; then
        update_status "$key" "VALID-OPENAI"
    else
        update_status "$key" "INVALID"
    fi
}
test_google_ai_key() {
    local key="$1"
    response=$(curl -s -m 5 -H "Authorization: Bearer $key" \
        "https://generativelanguage.googleapis.com/v1/models")
    
    if [[ $response == *"models"* ]]; then
        update_status "$key" "VALID-GOOGLE-AI"
    else
        update_status "$key" "INVALID"
    fi
}
test_anthropic_key() {
    local key="$1"
    response=$(curl -s -m 5 -H "x-api-key: $key" \
        -H "Content-Type: application/json" \
        "https://api.anthropic.com/v1/models")
    
    if [[ $response == *"models"* ]]; then
        update_status "$key" "VALID-ANTHROPIC"
    else
        update_status "$key" "INVALID"
    fi
}
test_cohere_key() {
    local key="$1"
    response=$(curl -s -m 5 -H "Authorization: Bearer $key" \
        -H "Content-Type: application/json" \
        "https://api.cohere.ai/v1/models")
    
    if [[ $response == *"models"* ]]; then
        update_status "$key" "VALID-COHERE"
    else
        update_status "$key" "INVALID"
    fi
}
test_firebase_api_key() {
    local key="$1"
    local data='{"longDynamicLink": "https://sub.example.com/?link=https://example.org"}'
    response=$(curl -s -m 5 -X POST "https://firebasedynamiclinks.googleapis.com/v1/shortLinks?key=$key" -H 'Content-Type: application/json' -d "$data")
    
    if [[ $response != *"API key not valid"* ]]; then
        update_status "$key" "VALID-FIREBASE-API"
    else
        update_status "$key" "INVALID"
    fi
}
test_twitter_api_secret() {
    local secret="$1"
    response=$(curl -s -m 5 -u "$secret" \
        "https://api.twitter.com/1.1/account/verify_credentials.json")
    
    if [[ $response == *"screen_name"* ]]; then
        update_status "$secret" "VALID-TWITTER-API-SECRET"
    else
        update_status "$secret" "INVALID"
    fi
}
test_twitter_bearer_token() {
    local token="$1"
    response=$(curl -s -m 5 -H "Authorization: Bearer $token" \
        "https://api.twitter.com/2/tweets")
    
    if [[ $response == *"data"* ]]; then
        update_status "$token" "VALID-TWITTER-BEARER-TOKEN"
    else
        update_status "$token" "INVALID"
    fi
}
test_spotify_access_token() {
    local token="$1"
    response=$(curl -s -m 5 -H "Authorization: Bearer $token" \
        "https://api.spotify.com/v1/me")
    
    if [[ $response == *"id"* ]]; then
        update_status "$token" "VALID-SPOTIFY-ACCESS-TOKEN"
    else
        update_status "$token" "INVALID"
    fi
}
test_square_secret() {
    local secret="$1"
    response=$(curl -s -m 5 -H "Authorization: Bearer $secret" \
        "https://connect.squareup.com/v2/locations")
    
    if [[ $response == *"locations"* ]]; then
        update_status "$secret" "VALID-SQUARE-SECRET"
    else
        update_status "$secret" "INVALID"
    fi
}
test_slack_api_token() {
    local token="$1"
    response=$(curl -s -m 5 -H "Authorization: Bearer $token" \
        "https://slack.com/api/auth.test")
    
    if [[ $response == *"ok\":true"* ]]; then
        update_status "$token" "VALID-SLACK-API-TOKEN"
    else
        update_status "$token" "INVALID"
    fi
}
test_recaptcha_site_key() {
    local key="$1"
    response=$(curl -s -m 5 "https://www.google.com/recaptcha/api/siteverify?secret=$key&response=dummy_response")
    
    if [[ $response == *"invalid-input-secret"* ]]; then
        update_status "$key" "INVALID"
    else
        update_status "$key" "VALID"
    fi
}
test_braze_api_key() {
    local key="$1"
    response=$(curl -s -m 5 -H "Authorization: Bearer $key" \
        "https://rest.iad-05.braze.com/users/export/ids")
    
    if [[ $response == *"error"* ]]; then
        update_status "$key" "INVALID"
    else
        update_status "$key" "VALID"
    fi
}
test_checkout_key() {
    local key="$1"
    response=$(curl -s -m 5 -H "Authorization: Bearer $key" \
        "https://api.checkout.com/payments")
    
    if [[ $response == *"error"* ]]; then
        update_status "$key" "INVALID"
    else
        update_status "$key" "VALID"
    fi
}
test_amplitude_key() {
    local key="$1"
    response=$(curl -s -m 5 -H "Authorization: Bearer $key" \
        "https://amplitude.com/api/2/usersearch")
    
    if [[ $response == *"error"* ]]; then
        update_status "$key" "INVALID"
    else
        update_status "$key" "VALID"
    fi
}
test_user_snap_space_api_key() {
    local key="$1"
    response=$(curl -s -m 5 -H "Authorization: Bearer $key" \
        "https://api.usersnap.com/api/v1/projects")
    
    if [[ $response == *"error"* ]]; then
        update_status "$key" "INVALID"
    else
        update_status "$key" "VALID"
    fi
}

# New function for testing Azure Tenant
test_azure_tenant() {
    local key="$1"
    response=$(curl -s -m 5 "https://login.microsoftonline.com/$key/v2.0/.well-known/openid-configuration")
    if [[ $response == *"tenant_region_scope"* ]]; then
        update_status "$key" "VALID"
    else
        update_status "$key" "INVALID"
    fi
}

# Add new function for testing AWS Secret Access Key
test_aws_secret_key() {
    local secret="$1"
    export AWS_ACCESS_KEY_ID="DUMMY"
    export AWS_SECRET_ACCESS_KEY="$secret"
    export AWS_DEFAULT_REGION="us-east-1"
    response=$(aws sts get-caller-identity 2>&1)
    if [[ $response == *"InvalidClientTokenId"* ]]; then
        update_status "$secret" "INVALID"
    elif [[ $response == *"SignatureDoesNotMatch"* ]]; then
        update_status "$secret" "VALID-NEEDS-ACCESS_KEY"
    else
        update_status "$secret" "POTENTIALLY-VALID"
    fi
    unset AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_DEFAULT_REGION
}

# In the Key Testing Section, add a test function for Shodan API Keys:
test_shodan_key() {
    local key="$1"
    response=$(curl -s -m 5 "https://api.shodan.io/api-info?key=$key")
    if [[ $response == *"plan"* ]]; then
        update_status "$key" "VALID"
    else
        update_status "$key" "INVALID"
    fi
}

# In the Key Testing Section, add a test function for Cloudflare API Tokens:
test_cloudflare_token() {
    local key="$1"
    response=$(curl -s -m 5 -H "Authorization: Bearer $key" "https://api.cloudflare.com/client/v4/user/tokens/verify")
    if [[ $response == *"\"success\":true"* ]]; then
        update_status "$key" "VALID"
    else
        update_status "$key" "INVALID"
    fi
}

# In the Key Testing Section, add a test function for Dropbox API Tokens:
test_dropbox_token() {
    local key="$1"
    response=$(curl -s -m 5 -X POST "https://api.dropboxapi.com/2/users/get_current_account" \
         -H "Authorization: Bearer $key" \
         -H "Content-Type: application/json")
    if [[ $response == *"account_id"* ]]; then
        update_status "$key" "VALID"
    else
        update_status "$key" "INVALID"
    fi
}

# In the Key Testing Section, add a test function for Firebase Custom Tokens:
test_firebase_custom_token() {
    local token="$1"
    response=$(curl -s -m 5 -X POST \
         -H "Content-Type: application/json" \
         -d "{\"token\":\"$token\"}" \
         "https://identitytoolkit.googleapis.com/v1/accounts:signInWithCustomToken")
    if [[ $response == *"idToken"* ]]; then
        update_status "$token" "VALID"
    else
        update_status "$token" "INVALID"
    fi
}

# In the Key Testing Section, add a test function for SecurityTrails API Keys:
test_securitytrails_key() {
    local key="$1"
    response=$(curl -s -m 5 -H "apikey: $key" "https://api.securitytrails.com/v1/domain/securitytrails.com")
    if [[ $response == *"domain"* ]]; then
        update_status "$key" "VALID"
    else
        update_status "$key" "INVALID"
    fi
}

# New test function for recaptcha_site_key_mobile
test_recaptcha_site_key_mobile() {
    local key="$1"
    response=$(curl -s -m 5 "https://www.google.com/recaptcha/api/siteverify?secret=$key&response=dummy_response")
    if [[ $response == *"invalid-input-secret"* ]]; then
        update_status "$key" "INVALID"
    else
        update_status "$key" "VALID"
    fi
}

# New test function for sentry_dsn
test_sentry_dsn() {
    local key="$1"
    response=$(curl -s -m 5 "$key")
    if [[ $response == *"sentry"* ]]; then
        update_status "$key" "VALID"
    else
        update_status "$key" "INVALID"
    fi
}

# Add new test function for firebase_databaseURL
test_firebase_databaseURL() {
    local url="$1"
    # Validate that the URL starts with "https://"
    if [[ "$url" == https://* ]]; then
        update_status "$url" "VALID"
    else
        update_status "$url" "INVALID"
    fi
}

# Add new test function for firebase_appId
test_firebase_appId() {
    local id="$1"
    # Simple validation: if length greater than 10, consider it valid
    if [[ ${#id} -gt 10 ]]; then
        update_status "$id" "VALID"
    else
        update_status "$id" "INVALID"
    fi
}

# New function to fetch data from Firebase Realtime Database
fetch_firebase_data() {
    local api_key="$1"
    local db_url="$2"
    # Construct endpoint (using '.json' as the default path for Firebase Realtime Database)
    local endpoint="${db_url}/.json?auth=${api_key}"
    echo "Fetching Firebase data from: ${endpoint}"
    local result
    result=$(curl -s "$endpoint")
    if [[ -n "$result" ]]; then
        if command -v jq >/dev/null 2>&1; then
            echo "$result" | jq
        else
            echo "$result"
        fi
    else
        echo "Failed to fetch data from Firebase. Please check the API key and database URL."
    fi
}

echo "Starting API key hunting and testing..."

# Extract and test keys for each type
extract_and_test "google_api" "Google API Keys" test_google_key
extract_and_test "amazon_aws_access_key_id" "AWS Access Keys" test_aws_key
extract_and_test "heroku.*api.*key" "Heroku API Keys" test_heroku_key
extract_and_test "twilio_account_sid" "Twilio Account SIDs" test_twilio_sid
extract_and_test "facebook_access_token" "Facebook Access Tokens" test_facebook_token
extract_and_test "firebase_custom_token" "Firebase Custom Tokens" test_firebase_custom_token
extract_and_test "firebase_id_token" "Firebase ID Tokens" test_firebase_token
extract_and_test "github_token" "GitHub Tokens" test_github_token
extract_and_test "instagram_access_token" "Instagram Access Tokens" test_instagram_token
extract_and_test "salesforce_access_token" "Salesforce Access Tokens" test_salesforce_token
extract_and_test "zendesk_access_token" "Zendesk Access Tokens" test_zendesk_token
extract_and_test "openai.*key" "OpenAI API Keys" test_openai_key
extract_and_test "google.*ai.*key" "Google AI API Keys" test_google_ai_key
extract_and_test "anthropic.*key" "Anthropic API Keys" test_anthropic_key
extract_and_test "cohere.*key" "Cohere API Keys" test_cohere_key
extract_and_test "firebase_api_key" "Firebase API Keys" test_firebase_api_key
extract_and_test "twitter_api_secret" "Twitter API Secrets" test_twitter_api_secret
extract_and_test "twitter_bearer_token" "Twitter Bearer Tokens" test_twitter_bearer_token
extract_and_test "spotify_access_token" "Spotify Access Tokens" test_spotify_access_token
extract_and_test "square_secret" "Square Secrets" test_square_secret
extract_and_test "slack_api_token" "Slack API Tokens" test_slack_api_token
extract_and_test "recaptcha_site_key" "reCAPTCHA Site Keys" test_recaptcha_site_key
# New extraction for recaptcha_site_key_mobile
extract_and_test "recaptcha_site_key_mobile" "reCAPTCHA Mobile Site Keys" test_recaptcha_site_key_mobile
extract_and_test "braze_api_key" "Braze API Keys" test_braze_api_key
extract_and_test "checkout_key" "Checkout Keys" test_checkout_key
extract_and_test "amplitude_key" "Amplitude Keys" test_amplitude_key
extract_and_test "user_snap_space_api_key" "UserSnap Space API Keys" test_user_snap_space_api_key
# New extraction for sentry_dsn
extract_and_test "sentry_dsn" "Sentry DSNs" test_sentry_dsn
# New extraction for Firebase App ID
extract_and_test "firebase_appId" "Firebase App IDs" test_firebase_appId
# New extraction for Firebase Database URLs
extract_and_test "firebase_databaseURL" "Firebase Database URLs" test_firebase_databaseURL
# New extraction for Azure Tenant keys
extract_and_test "azure_tenant" "Azure Tenant" test_azure_tenant
# Add extraction for Cloudflare API Tokens:
extract_and_test "cloudflare_api_token" "Cloudflare API Tokens" test_cloudflare_token
# Add extraction for Dropbox API Tokens:
extract_and_test "dropbox_api_token" "Dropbox API Tokens" test_dropbox_token
# Add extraction for SecurityTrails API Keys:
extract_and_test "securitytrails_key" "SecurityTrails API Keys" test_securitytrails_key

sed -i '/===.*===/{N;/===.*===\n$/d}' "$output_file"
echo "Process complete. Results saved to $output_file"
cat "$output_file"


# After key testing, extract Firebase keys directly from the secrets file
grep "^firebase_api_key ->" secrets_found.txt
grep "^firebase_databaseURL ->" secrets_found.txt

# Correct extraction of Firebase keys
firebase_api_key_found=$(grep "^firebase_api_key ->" secrets_found.txt | head -n 1 | sed -nE "s/^firebase_api_key -> ([A-Za-z0-9_-]{39})[[:space:]]*$/\1/p")
firebase_databaseURL_found=$(grep "^firebase_databaseURL ->" secrets_found.txt | head -n 1 | sed -nE "s/^firebase_databaseURL -> databaseURL:\"(https:\/\/[a-zA-Z0-9-]+\.firebaseio\.com)\"[[:space:]]*$/\1/p")

echo "Extracted Firebase API key: '$firebase_api_key_found'"
echo "Extracted Firebase Database URL: '$firebase_databaseURL_found'"

# Ensure both keys are found before calling fetch_firebase_data
if [[ -n "$firebase_api_key_found" && -n "$firebase_databaseURL_found" ]]; then
    fetch_firebase_data "$firebase_api_key_found" "$firebase_databaseURL_found"
else
    echo "Firebase API key and/or Database URL not found in secrets."
fi

# Updated fetch_firebase_data function
fetch_firebase_data() {
    local api_key="$1"
    local db_url="$2"
    # Construct endpoint (using '.json' as the default path for Firebase Realtime Database)
    local endpoint="${db_url}/.json?auth=${api_key}"
    echo "Fetching Firebase data from: ${endpoint}"
    local result
    result=$(curl -s "$endpoint")
    if [[ -n "$result" ]]; then
        if command -v jq >/dev/null 2>&1; then
            echo "$result" | jq
        else
            echo "$result"
        fi
    else
        echo "Failed to fetch data from Firebase. Please check the API key and database URL."
    fi
}

# ...existing code...
