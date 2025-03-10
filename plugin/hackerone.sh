#!/bin/bash

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

print_status() {
    echo -e "${GREEN}[+]${NC} $1"
}

print_error() {
    echo -e "${RED}[-]${NC} $1"
}

# Check for required tools
for tool in curl jq; do
    if ! command -v $tool &> /dev/null; then
        print_error "$tool is required but not installed."
        exit 1
    fi
done

# Create output directory
OUTPUT_DIR="hackerone_targets"
mkdir -p "$OUTPUT_DIR"

# Initialize files
> "$OUTPUT_DIR/domains.txt"
> "$OUTPUT_DIR/domains_with_bounties.txt"
> "$OUTPUT_DIR/source_code.txt"
> "$OUTPUT_DIR/source_code_with_bounties.txt"

page=1
while true; do
    print_status "Fetching page $page..."
    
    response=$(curl -s "https://hackerone.com/programs/search?query=type:hackerone&sort=published_at:descending&page=$page")
    
    # Validate response structure
    if ! echo "$response" | jq -e '.results' >/dev/null 2>&1; then
        print_error "Invalid response received for page $page"
        break
    fi

    # Check if we've reached the end or got empty results
    results=$(echo "$response" | jq -r '.results')
    if [ "$results" == "[]" ] || [ "$results" == "null" ]; then
        print_status "No more results to process"
        break
    fi

    # Process each program with validation
    echo "$response" | jq -r '.results[] | select(.url != null) | .url' | while read -r program_url; do
        if [ -z "$program_url" ]; then
            continue
        fi
        
        handle=$(echo "$program_url" | cut -d'/' -f2)
        print_status "Processing program: $handle"

        # Fetch scope using GraphQL
        scope_query='{
            "query": "query TeamAssets($handle: String!) { team(handle: $handle) { in_scope_assets: structured_scopes(archived: false, eligible_for_submission: true) { edges { node { asset_identifier asset_type eligible_for_bounty } } } } }",
            "variables": {"handle": "'$handle'"}
        }'

        graphql_response=$(curl -s -H "Content-Type: application/json" \
             -d "$scope_query" \
             "https://hackerone.com/graphql")

        # Validate GraphQL response
        if ! echo "$graphql_response" | jq -e '.data.team.in_scope_assets' >/dev/null 2>&1; then
            print_error "Invalid GraphQL response for $handle"
            continue
        fi

        # Process domains with error handling
        echo "$graphql_response" | \
        jq -r '[ .data.team.in_scope_assets.edges[]? | select(.node != null) | 
            select(.node.asset_type == "Domain" or .node.asset_type == "URL") | 
            .node | select(.asset_identifier != null) | 
            (.asset_identifier | split(",")[]? | select(. != null) | sub("^\\s+"; "") | sub("\\s+$"; "")) + "," + 
            (if .eligible_for_bounty == null then "false" else (.eligible_for_bounty | tostring) end) ] | .[]?' 2>/dev/null | \
        while IFS=, read -r domain bounty; do
            if [ ! -z "$domain" ]; then
                echo "$domain" >> "$OUTPUT_DIR/domains.txt"
                if [ "$bounty" = "true" ]; then
                    echo "$domain" >> "$OUTPUT_DIR/domains_with_bounties.txt"
                fi
            fi
        done

        # Process source code targets with error handling
        echo "$graphql_response" | \
        jq -r '[ .data.team.in_scope_assets.edges[]? | select(.node != null) | 
            select(.node.asset_type == "SOURCE_CODE") | 
            .node | select(.asset_identifier != null) | 
            (.asset_identifier | split(",")[]? | select(. != null) | sub("^\\s+"; "") | sub("\\s+$"; "")) + "," + 
            (if .eligible_for_bounty == null then "false" else (.eligible_for_bounty | tostring) end) ] | .[]?' 2>/dev/null | \
        while IFS=, read -r repo bounty; do
            if [ ! -z "$repo" ]; then
                # Format repository URL
                if [[ "$repo" =~ ^(git|www) ]]; then
                    repo="https://$repo"
                elif [[ ! "$repo" =~ ^https?:// ]]; then
                    repo="https://github.com/$repo"
                fi
                echo "$repo" >> "$OUTPUT_DIR/source_code.txt"
                if [ "$bounty" = "true" ]; then
                    echo "$repo" >> "$OUTPUT_DIR/source_code_with_bounties.txt"
                fi
            fi
        done
    done

    ((page++))
done

# Remove duplicates
for file in "$OUTPUT_DIR"/*.txt; do
    sort -u "$file" -o "$file"
done

print_status "Results saved in $OUTPUT_DIR:"
print_status "Total domains: $(wc -l < "$OUTPUT_DIR/domains.txt")"
print_status "Domains with bounties: $(wc -l < "$OUTPUT_DIR/domains_with_bounties.txt")"
print_status "Source code repositories: $(wc -l < "$OUTPUT_DIR/source_code.txt")"
print_status "Source code with bounties: $(wc -l < "$OUTPUT_DIR/source_code_with_bounties.txt")"
