#!/bin/bash

USER_AGENT="Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
TIMEOUT=30
OUTPUT_FILE=""
SINGLE_URL=""
VERBOSE=false
MAX_DEPTH=1
CURRENT_DEPTH=1
declare -A SCANNED_URLS

# Add logging function
log_verbose() {
    if [ "$VERBOSE" = true ]; then
        echo "[*] $1" >&2
    fi
}

# Updated help function
show_help() {
    echo "Usage: $0 [-o output_file] [-u url] [-v] [-d depth] [input_file]"
    echo "  -o, --output    Write output to file instead of stdout"
    echo "  -u, --url       Scan a single URL"
    echo "  -v, --verbose   Enable verbose logging"
    echo "  -d, --depth     Maximum depth for JavaScript scanning (default: 1)"
    echo "Or pipe URLs to the script"
    exit 1
}

# Updated argument parsing
while [[ $# -gt 0 ]]; do
    case $1 in
        -o|--output)
            OUTPUT_FILE="$2"
            shift 2
            ;;
        -u|--url)
            SINGLE_URL="$2"
            shift 2
            ;;
        -v|--verbose)
            VERBOSE=true
            shift
            ;;
        -d|--depth)
            MAX_DEPTH="$2"
            shift 2
            ;;
        -h|--help)
            show_help
            ;;
        *)
            INPUT_FILE="$1"
            shift
            ;;
    esac
done

# Add URL tracking function
is_url_scanned() {
    local url="$1"
    [[ -n "${SCANNED_URLS[$url]}" ]]
}

add_scanned_url() {
    local url="$1"
    SCANNED_URLS[$url]=1
}

process_js_url() {
    local js_url="$1"
    local current_depth="$2"
    
    if is_url_scanned "$js_url" || [[ $current_depth -gt $MAX_DEPTH ]]; then
        return
    fi
    
    add_scanned_url "$js_url"
    log_verbose "Scanning JavaScript at depth $current_depth: $js_url"
    
    # Extract URLs from JavaScript file
    local new_urls=$(curl -sk -A "$USER_AGENT" --max-time "$TIMEOUT" "$js_url" | \
        grep -o -E '(src="|data-script-src="|["'\'']/)[^"'\'']*\.js[^"'\'']*' | \
        sed 's/src="//g; s/data-script-src="//g; s/["'\'']//g' | \
        grep -E '\.js($|\?|#|")' | \
        grep -v '[+{}]' | \
        grep -v "'" | \
        grep -v 'baseConfig\|config\.' | \
        grep -v '\\/')
    
    if [ -n "$new_urls" ]; then
        while read -r url; do
            process_url "$url" $((current_depth + 1))
        done <<< "$new_urls"
    fi
}

process_url() {
    local url="$1"
    local depth="${2:-1}"
    local domain=$(echo "$url" | awk -F/ '{print $3}')
    local scheme=$(echo "$url" | awk -F: '{print $1}')
    
    log_verbose "Processing URL: $url at depth $depth"

    # Fetch the webpage and extract script sources
    curl -sk -A "$USER_AGENT" --max-time "$TIMEOUT" "$url" | \
    grep -o -E '(src="|data-script-src=")[^"]*\.js[^"]*"|[^"]*\.js[^"]*' | \
    sed 's/src="//g; s/data-script-src="//g; s/"//g' | \
    grep -E '\.js($|\?|#|")' | \
    grep -v '[+{}]' | \
    grep -v "'" | \
    grep -v 'baseConfig\|config\.' | \
    grep -v '\\/' | while read -r js; do
        # Process each JavaScript URL
        if [[ $js =~ ^[[:space:]]*$ ]] || [[ ${#js} -lt 4 ]]; then
            continue
        fi
        
        log_verbose "Processing JavaScript: $js"
        local full_url=""
        if [[ $js == http://* ]] || [[ $js == https://* ]]; then
            full_url="$js"
            log_verbose "Full URL found: $js"
        elif [[ $js == //* ]]; then
            full_url="${scheme}:${js}"
            log_verbose "Protocol-relative URL found: $js"
        elif [[ $js == /* ]]; then
            full_url="${scheme}://${domain}${js}"
            log_verbose "Root-relative URL found: $js"
        elif [[ $js == ./* ]]; then
            js=${js#./}
            full_url="${scheme}://${domain}/${js}"
            log_verbose "Directory-relative URL found: $js"
        elif [[ $js == *js* ]] && [[ $js != *"="* ]] && [[ $js != *"("* ]] && [[ $js != *")"* ]]; then
            full_url="${scheme}://${domain}/${js}"
            log_verbose "Relative URL found: $js"
        fi
        
        if [ -n "$full_url" ]; then
            echo "$full_url"
            # Process JavaScript file recursively if depth allows
            if [ "$depth" -lt "$MAX_DEPTH" ]; then
                process_js_url "$full_url" "$depth"
            fi
        fi
    done | sort -u
    log_verbose "Finished processing $url"
}

# Modified main script with single URL support
if [ -n "$SINGLE_URL" ]; then
    # Process single URL
    if [ -n "$OUTPUT_FILE" ]; then
        process_url "$SINGLE_URL" > "$OUTPUT_FILE"
    else
        process_url "$SINGLE_URL"
    fi
elif [ -p /dev/stdin ]; then
    # Reading from pipe
    if [ -n "$OUTPUT_FILE" ]; then
        while IFS= read -r line; do
            [ -n "$line" ] && process_url "$line"
        done > "$OUTPUT_FILE"
    else
        while IFS= read -r line; do
            [ -n "$line" ] && process_url "$line"
        done
    fi
else
    # Reading from file if specified
    if [ -n "$INPUT_FILE" ]; then
        if [ -n "$OUTPUT_FILE" ]; then
            while IFS= read -r line; do
                [ -n "$line" ] && process_url "$line"
            done < "$INPUT_FILE" > "$OUTPUT_FILE"
        else
            while IFS= read -r line; do
                [ -n "$line" ] && process_url "$line"
            done < "$INPUT_FILE"
        fi
    else
        show_help
    fi
fi
