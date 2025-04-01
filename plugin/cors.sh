#!/bin/bash

url_file="$1"
report_file="cors_vulnerable_urls.txt"

# Check if the argument is provided
if [ -z "$url_file" ]; then
    echo "Usage: ./script.sh <url_file>"
    exit 1
fi

# Read URLs from the file into an array
mapfile -t urls < "$url_file"

# Create or clear the report file
> "$report_file"

for url in "${urls[@]}"
do
    # Remove *. prefix and extract domain from URL
    url=$(echo "$url" | sed 's/^\*\.//')
    domain=$(echo "$url" | sed 's/https\?:\/\///' | sed 's/\/.*/\//' | sed 's/\(.*\).*/\1/')
    dirdomain=$(printf $domain | awk -F[.] '{for (i=1; i<NF-1; i++) printf $i"."; print $(NF-1)}')
    # Define origins array with the extracted domain
    origins=(
        "https://evil.com"
        "null"
        "https://${dirdomain}.evil.com"
        "http://${dirdomain}.evil.com"
        "*"
        "https://evil.${dirdomain}.com"
        "https://${dirdomain}.evil.com:123"
    )

    # Test http:// prefix
    http_url="http://$url"
    for origin in "${origins[@]}"
    do
        response=$(curl -s -o /dev/null -D - -H "Origin: $origin" "$http_url")
        cors_header=$(echo "$response" | grep -i 'access-control-allow-origin')
        allow_methods=$(echo "$response" | grep -i 'access-control-allow-methods')
        allow_headers=$(echo "$response" | grep -i 'access-control-allow-headers')
        allow_credentials=$(echo "$response" | grep -i 'access-control-allow-credentials')

        if [ ! -z "$cors_header" ]; then
            echo "Found CORS headers for: $http_url"
            echo "URL: $http_url" >> "$report_file"

            # Check if allow_credentials is true
            if [[ "$allow_credentials" == *"true"* ]]; then
                echo "Severity: High" >> "$report_file"
            else
                echo "Severity: Medium" >> "$report_file"
            fi

            echo "CORS Headers found:" >> "$report_file"
            [ ! -z "$cors_header" ] && echo "$cors_header" >> "$report_file"
            [ ! -z "$allow_methods" ] && echo "$allow_methods" >> "$report_file"
            [ ! -z "$allow_headers" ] && echo "$allow_headers" >> "$report_file"
            [ ! -z "$allow_credentials" ] && echo "$allow_credentials" >> "$report_file"
            echo "----------------------------------------" >> "$report_file"
        else
            echo "No CORS headers found for: $http_url"
        fi
    done

    # Test https:// prefix
    https_url="https://$url"
    for origin in "${origins[@]}"
    do
        response=$(curl -s -o /dev/null -D - -H "Origin: $origin" "$https_url")
        cors_header=$(echo "$response" | grep -i 'access-control-allow-origin')
        allow_methods=$(echo "$response" | grep -i 'access-control-allow-methods')
        allow_headers=$(echo "$response" | grep -i 'access-control-allow-headers')
        allow_credentials=$(echo "$response" | grep -i 'access-control-allow-credentials')

        if [ ! -z "$cors_header" ]; then
            echo "Found CORS headers for: $https_url"
            echo "URL: $https_url" >> "$report_file"

            # Check if allow_credentials is true
            if [[ "$allow_credentials" == *"true"* ]]; then
                echo "Severity: High" >> "$report_file"
            else
                echo "Severity: Medium" >> "$report_file"
            fi

            echo "CORS Headers found:" >> "$report_file"
            [ ! -z "$cors_header" ] && echo "$cors_header" >> "$report_file"
            [ ! -z "$allow_methods" ] && echo "$allow_methods" >> "$report_file"
            [ ! -z "$allow_headers" ] && echo "$allow_headers" >> "$report_file"
            [ ! -z "$allow_credentials" ] && echo "$allow_credentials" >> "$report_file"
            echo "----------------------------------------" >> "$report_file"
        else
            echo "No CORS headers found for: $https_url"
        fi
    done
done
