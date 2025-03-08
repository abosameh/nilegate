#!/bin/bash

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Print colored messages
print_status() {
    echo -e "${GREEN}[+]${NC} $1"
}

print_error() {
    echo -e "${RED}[-]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[!]${NC} $1"
}

# Check if running as root
if [ "$EUID" -eq 0 ]; then 
    print_error "Please don't run as root. Use normal user with sudo privileges."
    exit 1
fi

# Store current directory
INSTALL_DIR=$(pwd)
plugin_DIR=$(pwd)/plugin

# Create necessary directories
print_status "Creating necessary directories..."
mkdir -p "$HOME/tools"
mkdir -p "$HOME/wordlists"
mkdir -p "$plugin_DIR"

# Copy scripts to their locations
print_status "Installing recon script..."
if [ -f "recon.sh" ] && [ -f "recon_tools_manager.sh" ]; then
    chmod +x "recon.sh"
    chmod +x "recon_tools_manager.sh"
    sudo ln -sf "$INSTALL_DIR/recon.sh" /usr/local/bin/recon
    sudo ln -sf "$INSTALL_DIR/recon_tools_manager.sh" /usr/local/bin/recon-tools
    print_status "Scripts installed successfully"
    print_status "Running recon-tools..."
    bash recon_tools_manager.sh
else
    print_error "Required scripts not found in current directory"
    print_error "Make sure both recon.sh and recon_tools_manager.sh exist"
    exit 1
fi

print_status "Installing plugin tools scripts..."

cd $plugin_DIR
if [ -f "cors.sh" ] && [ -f "cms_scan.sh" ] && [ -f "reconlfi.sh" ]; then
    chmod +x "cors.sh"
    chmod +x "cms_scan.sh"
    chmod +x "reconlfi.sh"
    sudo ln -sf "$plugin_DIR/cors.sh" /usr/local/bin/cors
    sudo ln -sf "$plugin_DIR/cms_scan.sh" /usr/local/bin/cms_scan
    sudo ln -sf "$plugin_DIR/reconlfi.sh" /usr/local/bin/reconlfi
    done
    print_status "Plugin tools scripts installed successfully"
else
    print_error "Plugin directory not found or empty"
    mkdir -p "$plugin_DIR"
    print_warning "Created empty plugin directory at $plugin_DIR"
fi


print_status "Installation completed successfully!"
print_warning "Then run 'recon-tools' to install all required tools"
bash recon-tools
