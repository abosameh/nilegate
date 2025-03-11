#!/bin/bash

input_file="${1:-secretfinder.txt}"
output_file="found_keys.txt"

# Initialize output file
echo "API Key Detection and Testing Results" > "$output_file"
echo "==================================" >> "$output_file"
echo "" >> "$output_file"

# Function to update key status in the output file
update_status() {
    local key="$1"
    local status="$2"
    sed -i "s/\(Value: $key\)$/\1 [Status: $status]/" "$output_file"
}

# Function to extract and test keys
extract_and_test() {
    local pattern="$1"
    local key_type="$2"
    local test_function="$3"
    
    echo "=== $key_type ===" >> "$output_file"
    grep -i "$pattern.*->" "$input_file" | while read -r line; do
        if [[ $line =~ .*\-\>[[:space:]]*(.*)$ ]]; then
            key_value="${BASH_REMATCH[1]}"
            echo "Value: $key_value" >> "$output_file"
            # Test the key immediately after finding it
            $test_function "$key_value"
        fi
    done
    echo "" >> "$output_file"
}

# Test functions for different API keys
test_google_key() {
    local key="$1"
    response=$(curl -s -H "referer: http://example.com" \
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
    response=$(curl -s -X GET \
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
    response=$(curl -s -X GET "https://api.twilio.com/2010-04-01/Accounts/$sid.json" \
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
    response=$(curl -s "https://graph.facebook.com/v13.0/me?access_token=$token")
    if [[ $response == *"id"* ]]; then
        update_status "$token" "VALID"
    else
        update_status "$token" "INVALID"
    fi
}

test_firebase_token() {
    local token="$1"
    response=$(curl -s -X POST \
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
    response=$(curl -s -H "Authorization: token $token" \
        "https://api.github.com/user")
    if [[ $response == *"login"* ]]; then
        update_status "$token" "VALID"
    else
        update_status "$token" "INVALID"
    fi
}

test_instagram_token() {
    local token="$1"
    response=$(curl -s "https://graph.instagram.com/me?access_token=$token")
    if [[ $response == *"id"* ]]; then
        update_status "$token" "VALID"
    else
        update_status "$token" "INVALID"
    fi
}

test_salesforce_token() {
    local token="$1"
    response=$(curl -s -H "Authorization: Bearer $token" \
        "https://login.salesforce.com/services/oauth2/userinfo")
    if [[ $response == *"user_id"* ]]; then
        update_status "$token" "VALID"
    else
        update_status "$token" "INVALID"
    fi
}

test_zendesk_token() {
    local token="$1"
    response=$(curl -s -H "Authorization: Bearer $token" \
        "https://api.zendesk.com/api/v2/users/me")
    if [[ $response == *"email"* ]]; then
        update_status "$token" "VALID"
    else
        update_status "$token" "INVALID"
    fi
}

# Add new AI key test functions
test_openai_key() {
    local key="$1"
    response=$(curl -s -H "Authorization: Bearer $key" \
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
    response=$(curl -s -H "Authorization: Bearer $key" \
        "https://generativelanguage.googleapis.com/v1/models")
    
    if [[ $response == *"models"* ]]; then
        update_status "$key" "VALID-GOOGLE-AI"
    else
        update_status "$key" "INVALID"
    fi
}

test_anthropic_key() {
    local key="$1"
    response=$(curl -s -H "x-api-key: $key" \
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
    response=$(curl -s -H "Authorization: Bearer $key" \
        -H "Content-Type: application/json" \
        "https://api.cohere.ai/v1/models")
    
    if [[ $response == *"models"* ]]; then
        update_status "$key" "VALID-COHERE"
    else
        update_status "$key" "INVALID"
    fi
}

# Main process
echo "Starting API key hunting and testing..."

# Extract and test keys for each type
extract_and_test "google_api" "Google API Keys" test_google_key
extract_and_test "amazon_aws_access_key_id" "AWS Access Keys" test_aws_key
extract_and_test "heroku.*api.*key" "Heroku API Keys" test_heroku_key
extract_and_test "twilio_account_sid" "Twilio Account SIDs" test_twilio_sid
extract_and_test "facebook_access_token" "Facebook Access Tokens" test_facebook_token
extract_and_test "firebase_custom_token" "Firebase Custom Tokens" test_firebase_token
extract_and_test "firebase_id_token" "Firebase ID Tokens" test_firebase_token
extract_and_test "github_token" "GitHub Tokens" test_github_token
extract_and_test "instagram_access_token" "Instagram Access Tokens" test_instagram_token
extract_and_test "salesforce_access_token" "Salesforce Access Tokens" test_salesforce_token
extract_and_test "zendesk_access_token" "Zendesk Access Tokens" test_zendesk_token

# Add new AI key patterns to extract and test
extract_and_test "openai.*key" "OpenAI API Keys" test_openai_key
extract_and_test "google.*ai.*key" "Google AI API Keys" test_google_ai_key
extract_and_test "anthropic.*key" "Anthropic API Keys" test_anthropic_key
extract_and_test "cohere.*key" "Cohere API Keys" test_cohere_key

# Remove empty sections
sed -i '/===.*===/{N;/===.*===\n$/d}' "$output_file"

echo "Process complete. Results saved to $output_file"
cat "$output_file"
