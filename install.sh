#!/bin/bash
set -e

# Overthrone installer for Linux/macOS
# Usage: curl -fsSL https://raw.githubusercontent.com/Karmanya03/Overthrone/main/install.sh | bash

REPO="Karmanya03/Overthrone"
INSTALL_DIR="$HOME/.local/bin"
BINARY_NAME="overthrone"
SHORTHAND="ovt"

# Color helpers using printf (portable -- works on bash, zsh, dash, sh)
RED='\033[1;31m'
GREEN='\033[1;32m'
YELLOW='\033[1;33m'
BLUE='\033[1;34m'
MAGENTA='\033[1;35m'
CYAN='\033[1;36m'
WHITE='\033[1;37m'
GRAY='\033[0;90m'
BOLD='\033[1m'
NC='\033[0m'

# Progress bar renderer
# Usage: draw_progress <percent> <width>
draw_progress() {
    local pct=$1
    local width=${2:-40}
    local filled=$(( pct * width / 100 ))
    local empty=$(( width - filled ))

    printf "\r      ${CYAN}["
    for ((i=0; i<filled; i++)); do printf "█"; done
    for ((i=0; i<empty; i++)); do printf "░"; done
    printf "]${NC} ${WHITE}%3d%%${NC}" "$pct"
}

# Fancy spinner for indeterminate operations
spinner() {
    local pid=$1
    local msg=$2
    local spin chars i
    chars='⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏'
    i=0
    while kill -0 "$pid" 2>/dev/null; do
        printf "\r      ${MAGENTA}%s${NC} %s" "${chars:i++%${#chars}:1}" "$msg"
        sleep 0.1
    done
    printf "\r      ${GREEN}%s${NC} %s\n" "+" "$msg"
}

printf "\n"
printf "  ${RED}  ██████╗ ██╗   ██╗███████╗██████╗ ████████╗██╗  ██╗██████╗  ██████╗ ███╗   ██╗███████╗${NC}\n"
printf "  ${RED} ██╔═══██╗██║   ██║██╔════╝██╔══██╗╚══██╔══╝██║  ██║██╔══██╗██╔═══██╗████╗  ██║██╔════╝${NC}\n"
printf "  ${RED} ██║   ██║██║   ██║█████╗  ██████╔╝   ██║   ███████║██████╔╝██║   ██║██╔██╗ ██║█████╗  ${NC}\n"
printf "  ${RED} ██║   ██║╚██╗ ██╔╝██╔══╝  ██╔══██╗   ██║   ██╔══██║██╔══██╗██║   ██║██║╚██╗██║██╔══╝  ${NC}\n"
printf "  ${RED} ╚██████╔╝ ╚████╔╝ ███████╗██║  ██║   ██║   ██║  ██║██║  ██║╚██████╔╝██║ ╚████║███████╗${NC}\n"
printf "  ${RED}  ╚═════╝   ╚═══╝  ╚══════╝╚═╝  ╚═╝   ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝╚══════╝${NC}\n"
printf "\n"
printf "  ${WHITE}${BOLD}Active Directory Exploitation Framework${NC}\n"
printf "  ${GRAY}Every throne falls.${NC} 👑⚔️\n"
printf "\n"
printf "  ${CYAN}══════════════════════════════════════════════════════════${NC}\n"
printf "\n"

# ─────────────────────────────────────────────────────────────
# Step 1: Detect platform
# ─────────────────────────────────────────────────────────────
printf "  ${YELLOW}[1/5]${NC} ${WHITE}Detecting platform...${NC}\n"

OS=$(uname -s)
ARCH=$(uname -m)

case "$OS" in
    Linux*)
        if [ "$ARCH" = "x86_64" ]; then
            PLATFORM="linux-x86_64"
        elif [ "$ARCH" = "aarch64" ] || [ "$ARCH" = "arm64" ]; then
            PLATFORM="linux-aarch64"
        else
            printf "      ${RED}x Unsupported architecture: ${WHITE}$ARCH${NC}\n"
            exit 1
        fi
        ;;
    Darwin*)
        if [ "$ARCH" = "x86_64" ]; then
            PLATFORM="macos-x86_64"
        elif [ "$ARCH" = "arm64" ]; then
            PLATFORM="macos-aarch64"
        else
            printf "      ${RED}x Unsupported architecture: ${WHITE}$ARCH${NC}\n"
            exit 1
        fi
        ;;
    *)
        printf "      ${RED}x Unsupported OS: ${WHITE}$OS${NC}\n"
        exit 1
        ;;
esac

printf "      ${GREEN}+${NC} Platform:  ${WHITE}$PLATFORM${NC}\n"
printf "      ${GREEN}+${NC} OS:        ${WHITE}$OS${NC}\n"
printf "      ${GREEN}+${NC} Arch:      ${WHITE}$ARCH${NC}\n"
printf "\n"

# ─────────────────────────────────────────────────────────────
# Step 2: Detect latest release
# ─────────────────────────────────────────────────────────────
printf "  ${YELLOW}[2/5]${NC} ${WHITE}Checking latest release...${NC}\n"

API_URL="https://api.github.com/repos/$REPO/releases/latest"

if command -v curl &> /dev/null; then
    RELEASE_JSON=$(curl -fsSL "$API_URL" 2>/dev/null) || true
elif command -v wget &> /dev/null; then
    RELEASE_JSON=$(wget -qO- "$API_URL" 2>/dev/null) || true
else
    printf "      ${RED}x Neither ${WHITE}curl${RED} nor ${WHITE}wget${RED} found. Please install one of them.${NC}\n"
    exit 1
fi

TAG_NAME=$(echo "$RELEASE_JSON" | grep '"tag_name"' | head -1 | sed 's/.*"tag_name"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/')

if [ -z "$TAG_NAME" ]; then
    printf "      ${RED}x Failed to detect latest release.${NC}\n"
    printf "      ${GRAY}Check ${BLUE}https://github.com/$REPO/releases${NC}\n"
    exit 1
fi

printf "      ${GREEN}+${NC} Latest:    ${WHITE}$TAG_NAME${NC}\n"
printf "\n"

# ─────────────────────────────────────────────────────────────
# Step 3: Download binary with progress bar
# ─────────────────────────────────────────────────────────────
printf "  ${YELLOW}[3/5]${NC} ${WHITE}Downloading binary...${NC}\n"

DOWNLOAD_URL="https://github.com/$REPO/releases/download/$TAG_NAME/overthrone-$PLATFORM"

mkdir -p "$INSTALL_DIR"

# Get file size for progress calculation
if command -v curl &> /dev/null; then
    FILE_SIZE=$(curl -sI -L "$DOWNLOAD_URL" 2>/dev/null | grep -i 'content-length' | tail -1 | sed 's/[^0-9]//g')
elif command -v wget &> /dev/null; then
    FILE_SIZE=$(wget --spider -S "$DOWNLOAD_URL" 2>&1 | grep -i 'content-length' | tail -1 | sed 's/[^0-9]//g')
fi

if [ -n "$FILE_SIZE" ] && [ "$FILE_SIZE" -gt 0 ] 2>/dev/null; then
    FILE_SIZE_MB=$(echo "scale=1; $FILE_SIZE / 1048576" | bc 2>/dev/null || echo "?")
    printf "      ${GRAY}URL: $DOWNLOAD_URL${NC}\n"
    printf "      ${GRAY}Size: ~${FILE_SIZE_MB} MB${NC}\n"
    printf "\n"

    # Download with real-time progress bar
    if command -v curl &> /dev/null; then
        curl -L "$DOWNLOAD_URL" -o "$INSTALL_DIR/$BINARY_NAME" 2>/dev/null | while IFS= read -r line; do
            if echo "$line" | grep -q '%'; then
                pct=$(echo "$line" | grep -oE '[0-9]+' | tail -1)
                if [ -n "$pct" ] && [ "$pct" -ge 0 ] && [ "$pct" -le 100 ] 2>/dev/null; then
                    draw_progress "$pct" 40
                fi
            fi
        done
        printf "\n"
    elif command -v wget &> /dev/null; then
        # wget: simulate progress from output
        wget -q --show-progress "$DOWNLOAD_URL" -O "$INSTALL_DIR/$BINARY_NAME" 2>&1 | while IFS= read -r line; do
            if echo "$line" | grep -q '%'; then
                pct=$(echo "$line" | grep -oE '[0-9]+' | tail -1)
                if [ -n "$pct" ] && [ "$pct" -ge 0 ] && [ "$pct" -le 100 ] 2>/dev/null; then
                    draw_progress "$pct" 40
                fi
            fi
        done
        printf "\n"
    fi
else
    # Can't determine file size -- download with spinner
    printf "      ${GRAY}URL: $DOWNLOAD_URL${NC}\n"
    printf "\n"

    if command -v curl &> /dev/null; then
        curl -# -L "$DOWNLOAD_URL" -o "$INSTALL_DIR/$BINARY_NAME" 2>&1 | while IFS= read -r line; do
            if echo "$line" | grep -q '%'; then
                pct=$(echo "$line" | grep -oE '[0-9]+' | tail -1)
                if [ -n "$pct" ] && [ "$pct" -ge 0 ] && [ "$pct" -le 100 ] 2>/dev/null; then
                    draw_progress "$pct" 40
                fi
            fi
        done
        printf "\n"
    elif command -v wget &> /dev/null; then
        wget --show-progress -q "$DOWNLOAD_URL" -O "$INSTALL_DIR/$BINARY_NAME"
    fi
fi

# Verify download succeeded
if [ ! -s "$INSTALL_DIR/$BINARY_NAME" ]; then
    printf "      ${RED}x Download failed or file is empty.${NC}\n"
    printf "      ${GRAY}Check ${BLUE}$DOWNLOAD_URL${NC}\n"
    rm -f "$INSTALL_DIR/$BINARY_NAME"
    exit 1
fi

printf "\n"

# ─────────────────────────────────────────────────────────────
# Step 4: Install binary + create symlink
# ─────────────────────────────────────────────────────────────
printf "  ${YELLOW}[4/5]${NC} ${WHITE}Installing...${NC}\n"

chmod +x "$INSTALL_DIR/$BINARY_NAME"
ln -sf "$INSTALL_DIR/$BINARY_NAME" "$INSTALL_DIR/$SHORTHAND"

printf "      ${GREEN}+${NC} Binary:    ${WHITE}$INSTALL_DIR/$BINARY_NAME${NC}\n"
printf "      ${GREEN}+${NC} Shorthand: ${WHITE}$INSTALL_DIR/$SHORTHAND${NC}\n"
printf "\n"

# Verify installation
if [ -x "$INSTALL_DIR/$BINARY_NAME" ]; then
    INSTALLED_VERSION=$("$INSTALL_DIR/$BINARY_NAME" -V 2>&1 | head -1)
    printf "      ${GREEN}+${NC} Version:   ${WHITE}${INSTALLED_VERSION}${NC}\n"
else
    printf "      ${RED}x Binary not executable after install.${NC}\n"
    exit 1
fi
printf "\n"

# ─────────────────────────────────────────────────────────────
# Step 5: Post-install checks
# ─────────────────────────────────────────────────────────────
printf "  ${YELLOW}[5/5]${NC} ${WHITE}Post-install checks...${NC}\n"

WARNINGS=0

# Check PATH
if [[ ":$PATH:" != *":$INSTALL_DIR:"* ]]; then
    printf "      ${YELLOW}!${NC}  ${WHITE}$INSTALL_DIR${NC} is not in your PATH.\n"
    printf "      ${GRAY}   Add to ~/.bashrc or ~/.zshrc:${NC}\n"
    printf "\n"
    printf "      ${GREEN}export PATH=\"\$HOME/.local/bin:\$PATH\"${NC}\n"
    printf "\n"
    WARNINGS=$((WARNINGS + 1))
else
    printf "      ${GREEN}+${NC} PATH includes $INSTALL_DIR\n"
fi

# Check for smbclient
if ! command -v smbclient &> /dev/null; then
    printf "      ${YELLOW}!${NC}  ${WHITE}smbclient${NC} not found (needed for legacy SMB operations)\n"
    if [ "$OS" = "Linux" ]; then
        if command -v apt &> /dev/null; then
            printf "      ${GRAY}   Install: ${GREEN}sudo apt install smbclient${NC}\n"
        elif command -v pacman &> /dev/null; then
            printf "      ${GRAY}   Install: ${GREEN}sudo pacman -S samba${NC}\n"
        elif command -v dnf &> /dev/null; then
            printf "      ${GRAY}   Install: ${GREEN}sudo dnf install samba-client${NC}\n"
        fi
    elif [ "$OS" = "Darwin" ]; then
        printf "      ${GRAY}   Install: ${GREEN}brew install samba${NC}\n"
    fi
    WARNINGS=$((WARNINGS + 1))
else
    printf "      ${GREEN}+${NC} smbclient found\n"
fi

printf "\n"

# ─────────────────────────────────────────────────────────────
# Done!
# ─────────────────────────────────────────────────────────────
printf "  ${CYAN}══════════════════════════════════════════════════════════${NC}\n"
printf "\n"
printf "  ${GREEN}${BOLD}Installation complete!${NC}\n"
printf "\n"
printf "      ${WHITE}Run:${NC}  overthrone --help\n"
printf "      ${WHITE}Or:${NC}   ovt --help\n"
printf "\n"

if [ "$WARNINGS" -gt 0 ]; then
    printf "  ${YELLOW}^ $WARNINGS warning(s) above -- check before first use.${NC}\n"
    printf "\n"
fi

printf "  ${GRAY}Every throne falls.${NC} 👑⚔️\n"
printf "\n"
