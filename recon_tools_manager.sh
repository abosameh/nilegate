#!/bin/bash

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Function to print colored status messages
print_status() {
    echo -e "${GREEN}[+]${NC} $1"
}

print_error() {
    echo -e "${RED}[-]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[!]${NC} $1"
}

# Function to check if a command exists
check_command() {
    if command -v "$1" &> /dev/null; then
        return 0
    else
        return 1
    fi
}

# Function to check if a Python package is installed
check_python_package() {
    source "$VENV_DIR/bin/activate" 2>/dev/null
    if pip list | grep -F "$1" &> /dev/null; then
        return 0
    else
        return 1
    fi
}

# Function to check if a directory exists
check_directory() {
    if [ -d "$1" ]; then
        return 0
    else
        return 1
    fi
}

# Function to check all tools
check_tools() {
    local missing_tools=0

    echo "Checking base directories..."
    check_directory "$TOOLS_DIR" || ((missing_tools++))
    check_directory "$WORDLISTS_DIR" || ((missing_tools++))

    echo -e "\nChecking Go installation..."
    check_command "go" || ((missing_tools++))

    echo -e "\nChecking Rust installation..."
    check_command "cargo" || ((missing_tools++))

    # Check Go tools
    echo -e "\nChecking Go-based tools..."
    for tool in "${go_binaries[@]}"; do
        if check_command "$tool"; then
            print_status "$tool is installed"
        else
            print_error "$tool is not installed"
            ((missing_tools++))
        fi
    done

    # Check Rust tools
    echo -e "\nChecking Rust-based tools..."
    for tool in "${rust_tools[@]}"; do
        if check_command "$tool"; then
            print_status "$tool is installed"
        else
            print_error "$tool is not installed"
            ((missing_tools++))
        fi
    done

    # Check Python tools
    echo -e "\nChecking Python-based tools..."
    for tool in "${python_tools[@]}"; do
        if check_python_package "$tool"; then
            print_status "$tool is installed"
        else
            print_error "$tool is not installed"
            ((missing_tools++))
        fi
    done

    # Check system tools
    echo -e "\nChecking system tools..."
    for tool in "${system_tools[@]}"; do
        if check_command "$tool"; then
            print_status "$tool is installed"
        else
            print_error "$tool is not installed"
            ((missing_tools++))
        fi
    done

    # Check GitHub tools
    echo -e "\nChecking GitHub tools..."
    for tool in "${github_tools[@]}"; do
        if [ -f "$tool" ]; then
            print_status "$(basename $tool) is installed"
        else
            print_error "$(basename $tool) is not installed"
            ((missing_tools++))
        fi
    done

    # Check wordlists
    echo -e "\nChecking wordlists..."
    for wordlist in "${wordlists[@]}"; do
        if [ -f "$wordlist" ]; then
            print_status "$(basename $wordlist) exists"
        else
            print_error "$(basename $wordlist) is missing"
            ((missing_tools++))
        fi
    done

    # Check config directories
    echo -e "\nChecking configuration directories..."
    for dir in "${config_dirs[@]}"; do
        if check_directory "$(eval echo $dir)"; then
            print_status "Directory $dir exists"
        else
            print_error "Directory $dir does not exist"
            ((missing_tools++))
        fi
    done

    echo -e "\nSummary:"
    if [ $missing_tools -eq 0 ]; then
        print_status "All tools are installed correctly!"
        return 0
    else
        print_error "$missing_tools tools/components are missing"
        return $missing_tools
    fi
}

# Function to install tools
install_tools() {
    if [ "$EUID" -eq 0 ]; then 
        print_warning "Running as root is not recommended. Please run as normal user with sudo privileges."
        exit 1
    fi

    print_status "Starting installation process..."

    # Create base directories
    mkdir -p "$TOOLS_DIR"
    mkdir -p "$WORDLISTS_DIR"
    cd "$TOOLS_DIR"

    # Install system requirements
    print_status "Installing system requirements..."
    sudo apt-get install -y \
        git wget curl build-essential gcc make ruby \
        python3 python3-pip libpcap-dev unzip chromium \
        nmap masscan dirb nikto wapiti whatweb \
        sqlmap wpscan joomscan skipfish \
        ruby-dev libsqlite3-dev nodejs npm lolcat 

    # Install nrich
    if ! check_command "nrich"; then
    print_status "Installing nrich..."
    wget https://gitlab.com/api/v4/projects/33695681/packages/generic/nrich/latest/nrich_latest_x86_64.deb
    sudo dpkg -i nrich_latest_x86_64.deb
    fi
   # Install trufflehog
    if ! check_command "trufflehog"; then
        print_status "Installing trufflehog..."
        curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh | sh -s -- -b /usr/local/bin
    fi
    # Install Go if not present
    if ! check_command "go"; then
        print_status "Installing Go..."
        wget https://go.dev/dl/go1.21.0.linux-amd64.tar.gz
        rm -rf /usr/local/go && tar -C /usr/local -xzf go1.21.0.linux-amd64.tar.gz
        echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc
        echo 'export GOPATH=$HOME/go' >> ~/.bashrc
        source ~/.bashrc
        rm go1.21.0.linux-amd64.tar.gz
    fi

    # Install Rust if not present
    if ! check_command "cargo"; then
        print_status "Installing Rust..."
        curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
        source $HOME/.cargo/env
    fi

    # Install Go tools
    print_status "Installing Go tools..."
    for tool in "${go_tools[@]}"; do
        print_status "Installing $tool..."
        go install -v "$tool@latest"
    done

    # Install Rust tools
    print_status "Installing Rust tools..."
    for tool in "${rust_tools[@]}"; do
        if ! check_command "$tool"; then
            print_status "Installing $tool..."
            cargo install $tool
        fi
    done

    # Create and activate virtual environment for Python tools
    print_status "Setting up Python virtual environment..."
    sudo apt-get install -y python3-venv python3-pip
    python3 -m venv "$VENV_DIR"
    source "$VENV_DIR/bin/activate"

    # Install Python tools
    print_status "Installing Python tools..."
    pip3 install --upgrade pip
    for tool in "${python_tools[@]}"; do
        if ! check_python_package "$tool"; then
            print_status "Installing $tool..."
            pip3 install $tool
        fi
    done

    # Install GitHub tools
    cd "$TOOLS_DIR"

    # Install findomain, trufflehog, and teler if not present
    if ! check_command "findomain"; then
        print_status "Installing findomain..."
        curl -LO https://github.com/findomain/findomain/releases/latest/download/findomain-linux.zip
        unzip findomain-linux.zip
        chmod +x findomain
        sudo mv findomain /usr/local/bin/
    fi


    if ! check_command "teler"; then
        print_status "Installing teler..."
        git clone https://github.com/kitabisa/teler
        cd teler
        make build
        sudo ./bin/teler /usr/local/bin
    fi
    # Install other GitHub tools
    github_repos=(
        "https://github.com/Tuhinshubhra/CMSeeK.git"
        "https://github.com/GerbenJavado/LinkFinder.git"
        "https://github.com/m4ll0k/SecretFinder.git"
        "https://github.com/obheda12/GitDorker.git"
        "https://github.com/FortyNorthSecurity/EyeWitness.git"
        "https://github.com/j3ssie/osmedeus.git"
        "https://github.com/rezasp/joomscan.git"
        "https://github.com/punk-security/dnsReaper.git"
        "https://github.com/UndeadSec/SwaggerSpy.git"
        "https://github.com/Josue87/EmailFinder.git"
        "https://github.com/devanshbatham/OpenRedireX.git"
        "https://github.com/eslam3kl/SQLiDetector.git"
        "https://github.com/commixproject/commix.git"
        "https://github.com/MandConsultingGroup/porch-pirate.git"
        "https://github.com/abosameh/earlybird.git"
        "https://github.com/intigriti/misconfig-mapper.git"
        "https://github.com/inc0d3/moodlescan.git"
        "https://github.com/s0md3v/Corsy.git"
        "https://github.com/MattKeeley/Spoofy.git"
        "https://github.com/abosameh/CloudHunter.git"
        "https://github.com/faiyazahmad07/xss_vibes.git"
        
    )

    for repo in "${github_repos[@]}"; do
        repo_name=$(basename $repo .git)
        if [ ! -d "$TOOLS_DIR/$repo_name" ]; then
            print_status "Cloning $repo_name..."
            git clone $repo
            cd "$repo_name"
            if [ -f "requirements.txt" ]; then
                source "$VENV_DIR/bin/activate"
                pip install -r requirements.txt
                deactivate
            fi
            if [ -f "setup.sh" ]; then
                bash setup.sh
            fi
            if [ -f "install.sh" ]; then
                bash install.sh
            fi
            if [ -f "joomscan.pl" ]; then
                perl joomscan.pl
            fi
            if [ -f "setup.py" ]; then
                python3 setup.py
            fi
            if [ -f "main.go" ]; then
                go build -o misconfig-mapper
        chmod +x ./misconfig-mapper
            fi
            cd ..
        fi
    done

    # Add this to create wrapper scripts for Python tools
    print_status "Creating wrapper scripts for Python tools..."
    mkdir -p "$HOME/.local/bin"
    
    for tool in "${python_tools[@]}"; do
        cat > "$HOME/.local/bin/$tool" << EOF
#!/bin/bash
source "$VENV_DIR/bin/activate"
$VENV_DIR/bin/$tool "\$@"
deactivate
EOF
        chmod +x "$HOME/.local/bin/$tool"
    done

    # Add PATH update if not already present
    if ! grep -q "$HOME/.local/bin" "$HOME/.bashrc"; then
        echo 'export PATH="$HOME/.local/bin:$PATH"' >> "$HOME/.bashrc"
        print_status "Added ~/.local/bin to PATH. Please restart your terminal or run: source ~/.bashrc"
    fi

    # Download wordlists
    print_status "Downloading wordlists..."
    cd "$WORDLISTS_DIR"
    for wordlist in "${wordlists[@]}"; do
        if [ ! -f "$wordlist" ]; then
            case $(basename $wordlist) in
                "subdomain_megalist.txt")
                    wget https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/deepmagic.com-prefixes-top50000.txt -O $wordlist
                    ;;
                "dns_wordlist.txt")
                    wget https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/dns-Jhaddix.txt -O $wordlist
                    ;;
                "resolvers.txt")
                    wget https://raw.githubusercontent.com/abosameh/bug/refs/heads/main/resolvers.txt -O $wordlist
                    ;;
                "directory_wordlist.txt")
                    wget https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/directory-list-2.3-medium.txt -O $wordlist
                    ;;
                    
                 "lfi_wordlist.txt")
                    wget https://gist.githubusercontent.com/six2dez/a89a0c7861d49bb61a09822d272d5395/raw -O $wordlist
                    ;;
                 "ssti-payloads.txt")
                    wget https://raw.githubusercontent.com/abosameh/bug/main/ssti-payloads.txt -O $wordlist
                    ;;
                 "xss-payloads.txt")
                    wget https://raw.githubusercontent.com/abosameh/bug/main/xss-payloads.txt -O $wordlist
                    ;;
                 "Open-Redirect-payloads.txt")
                    wget https://raw.githubusercontent.com/abosameh/bug/refs/heads/main/Open-Redirect-payloads.txt -O $wordlist
                    ;;
                 "httpxpath.txt")
                    wget https://raw.githubusercontent.com/abosameh/bug/main/httpxpath.txt -O $wordlist
                    ;;
                     "payloads.txt")
                    wget https://raw.githubusercontent.com/abosameh/lfirecon/main/payloads.txt -O $wordlist
                    ;;
                    
                    
                    
                    
            esac
        fi
    done

    # Create configuration directories and files
    mkdir -p ~/.gf ~/.config/nuclei ~/.config/subfinder

    # Download GF patterns if not present
    if [ ! -d "~/.gf/Gf-Patterns" ]; then
        print_status "Downloading GF patterns..."
        git clone https://github.com/1ndianl33t/Gf-Patterns ~/.gf/
    fi

    # Update Nuclei templates
    print_status "Updating Nuclei templates..."
    nuclei -update-templates

    # Create subfinder config
    if [ ! -f "~/.config/subfinder/config.yaml" ]; then
        print_status "Creating subfinder config..."
        cat > ~/.config/subfinder/config.yaml << EOF
resolvers:
  - 1.1.1.1
  - 8.8.8.8
  - 8.8.4.4
  - 1.0.0.1
sources:
  - alienvault
  - anubis
  - bufferover
  - certspotter
  - censys
  - chaos
  - crtsh
  - dnsdumpster
  - hackertarget
  - intelx
  - passivetotal
  - securitytrails
  - shodan
  - spyse
  - sublist3r
  - threatcrowd
  - threatminer
  - virustotal
EOF
    fi

    print_status "Installation completed!"
    print_warning "Remember to configure API keys for tools that require them"
}

# Define tool arrays
TOOLS_DIR="$HOME/tools"
WORDLISTS_DIR="$HOME/wordlists"
VENV_DIR="$HOME/.recon_venv"

go_tools=(
    "github.com/projectdiscovery/subfinder/v2/cmd/subfinder"
    "github.com/projectdiscovery/httpx/cmd/httpx"
    "github.com/projectdiscovery/nuclei/v2/cmd/nuclei"
    "github.com/projectdiscovery/naabu/v2/cmd/naabu"
    "github.com/projectdiscovery/dnsx/cmd/dnsx"
    "github.com/projectdiscovery/katana/cmd/katana"
    "github.com/projectdiscovery/tlsx/cmd/tlsx"
    "github.com/projectdiscovery/asnmap/cmd/asnmap"
    "github.com/projectdiscovery/chaos-client/cmd/chaos"
    "github.com/projectdiscovery/mapcidr/cmd/mapcidr"
    "github.com/projectdiscovery/cdncheck/cmd/cdncheck"
    "github.com/projectdiscovery/interactsh/cmd/interactsh-client"
    "github.com/tomnomnom/assetfinder"
    "github.com/tomnomnom/gf"
    "github.com/tomnomnom/waybackurls"
    "github.com/tomnomnom/unfurl"
    "github.com/lc/gau/v2/cmd/gau"
    "github.com/hakluke/hakrawler"
    "github.com/ffuf/ffuf/v2"
    "github.com/OJ/gobuster/v3"
    "github.com/hahwul/dalfox/v2"
    "github.com/dwisiswant0/crlfuzz/cmd/crlfuzz"
    "github.com/d3mondev/puredns/v2"
    "github.com/Josue87/gotator"
    "github.com/sensepost/gowitness"
    "github.com/003random/getJS"
    "github.com/lc/subjs"
    "github.com/PentestPad/subzy"
    "github.com/j3ssie/osmedeus"
    "github.com/edoardottt/cariddi/cmd/cariddi"
    "github.com/ferreiraklet/airixss"
    "github.com/tomnomnom/meg"
    "github.com/bp0lr/gauplus"
    "github.com/takshal/freq"
    "github.com/rix4uni/Gxss"
    "github.com/projectdiscovery/shuffledns/cmd/shuffledns"
    "github.com/projectdiscovery/alterx/cmd/alterx"
    "github.com/projectdiscovery/tlsx/cmd/tlsx"
    "github.com/Hackmanit/TInjA"
    "github.com/edoardottt/pphack/cmd/pphack"
    "github.com/edoardottt/Hackmanit/Web-Cache-Vulnerability-Scanner"
    "github.com/edoardottt/tomnomnom/gron"
    "github.com/dubs3c/urldedupe"
    "github.com/projectdiscovery/uncover/cmd/uncover"
    "github.com/mrco24/open-redirect"
    "github.com/abosameh/lfirecon"
    "github.com/detectify/page-fetch"
    "github.com/behf/dnsgen"
)

go_binaries=(
    "subfinder"
    "httpx"
    "nuclei"
    "naabu"
    "dnsx"
    "katana"
    "tlsx"
    "asnmap"
    "chaos"
    "mapcidr"
    "cdncheck"
    "interactsh-client"
    "assetfinder"
    "gf"
    "waybackurls"
    "unfurl"
    "gau"
    "hakrawler"
    "ffuf"
    "gobuster"
    "dalfox"
    "crlfuzz"
    "puredns"
    "gotator"
    "gowitness"
    "getJS"
    "subjs"
    "subzy"
    "osmedeus"
    "cariddi"
    "airixss"
    "meg"
    "gauplus"
    "freq"
    "Gxss"
    "shuffledns"
    "alterx"
    "tlsx"
    "TInjA"
    "pphack"
    "Web-Cache-Vulnerability-Scanner"
    "gron"
    "urldedupe"
    "uncover"
    "open-redirect"
    "lfirecon"
    "page-fetch"
    "dnsgen"
)

rust_tools=(
    "feroxbuster"
    "rustscan"
)

python_tools=(
    "arjun"
    "xsstrike"
    "droopescan"
    "wafw00f"
    "webtech"
    "semgrep"
    "waymore"
    "porch-pirate"
    "dirsearch"
    "jsbeautifier"
    "argparse"
    "requests"
    "lxml"
    "emailfinder"
    "json"
    "colorama"
    "trufflehog3"
    "aiohttp"
    "tqdm"
    "bhedak"
)

system_tools=(
    "nmap"
    "masscan"
    "dirb"
    "nikto"
    "wapiti"
    "whatweb"
    "sqlmap"
    "wpscan"
    "skipfish"
    "lolcat"
)

github_tools=(
    "$HOME/tools/CMSeeK/cmseek.py"
    "$HOME/tools/LinkFinder/linkfinder.py"
    "$HOME/tools/SecretFinder/SecretFinder.py"
    "$HOME/tools/GitDorker/GitDorker.py"
    "$HOME/tools/EyeWitness/Python/EyeWitness.py"
    "$HOME/tools/joomscan/joomscan.pl"
    "$HOME/tools/dnsReaper/main.py"
    "$HOME/tools/SwaggerSpy/swaggerspy.py"
    "$HOME/tools/EmailFinder/setup.py"
    "$HOME/tools/OpenRedireX/setup.sh"
    "$HOME/tools/SQLiDetector/sqlidetector.py"
    "$HOME/tools/commix/commix.py"
    "$HOME/tools/porch-pirate/setup.py"
    "$HOME/tools/earlybird/install.sh"
    "$HOME/tools/misconfig-mapper/misconfig-mapper"
    "$HOME/tools/moodlescan/moodlescan.py"
     "$HOME/tools/Corsy/corsy.py"
     "$HOME/tools/Spoofy/spoofy.py"
     "$HOME/tools/CloudHunter/cloudhunter.py"
     "$HOME/tools/xss_vibes/main.py"
)

wordlists=(
    "$HOME/wordlists/subdomain_megalist.txt"
    "$HOME/wordlists/dns_wordlist.txt"
    "$HOME/wordlists/resolvers.txt"
    "$HOME/wordlists/directory_wordlist.txt"
    "$HOME/wordlists/lfi_wordlist.txt"
    "$HOME/wordlists/ssti-payloads.txt"
    "$HOME/wordlists/xss-payloads.txt"
    "$HOME/wordlists/Open-Redirect-payloads.txt"
    "$HOME/wordlists/httpxpath.txt"
    "$HOME/wordlists/payloads.txt"
   
)

config_dirs=(
    "~/.gf"
    "~/.config/nuclei"
    "~/.config/subfinder"
)

# Main menu
while true; do
    echo -e "\n${GREEN}Recon Tools Manager${NC}"
    echo "1. Check installed tools"
    echo "2. Install/Update tools"
    echo "3. Exit"
    read -p "Select an option (1-3): " choice

    case $choice in
        1)
            check_tools
            ;;
        2)
            install_tools
            ;;
        3)
            print_status "Exiting..."
            exit 0
            ;;
        *)
            print_error "Invalid option"
            ;;
    esac
done
