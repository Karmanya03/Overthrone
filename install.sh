#!/bin/bash
set -e

# Overthrone installer for Linux/macOS
# Usage: curl -fsSL https://raw.githubusercontent.com/Karmanya03/Overthrone/main/install.sh | bash

REPO="Karmanya03/Overthrone"
INSTALL_DIR="$HOME/.local/bin"
BINARY_NAME="overthrone"
SHORTHAND="ovt"

echo ""
echo "  \033[1;31m  ██████╗ ███████╗███╗   ███╗██╗ ██████╗ \033[0m"
echo "  \033[1;31m  ██╔══██╗██╔════╝████╗ ████║██║██╔═══██╗\033[0m"
echo "  \033[1;31m  ██████╔╝█████╗  ██╔████╔██║██║██║   ██║\033[0m"
echo "  \033[1;31m  ██╔══██╗██╔══╝  ██║╚██╔╝██║██║██║   ██║\033[0m"
echo "  \033[1;31m  ██║  ██║███████╗██║ ╚═╝ ██║██║╚██████╔╝\033[0m"
echo "  \033[1;31m  ╚═╝  ╚═╝╚══════╝╚═╝     ╚═╝╚═╝ ╚═════╝ \033[0m"
echo ""
echo "  \033[1;37mActive Directory Exploitation Framework\033[0m"
echo "  \033[0;90mEvery throne falls.\033[0m"
echo ""
echo "---------------------------------------------------"
echo ""

# Detect platform
OS=$(uname -s)
ARCH=$(uname -m)

case "$OS" in
    Linux*)
        if [ "$ARCH" = "x86_64" ]; then
            PLATFORM="linux-x86_64"
        elif [ "$ARCH" = "aarch64" ] || [ "$ARCH" = "arm64" ]; then
            PLATFORM="linux-aarch64"
        else
            echo "  \033[1;31m[X]\033[0m Unsupported architecture: $ARCH"
            exit 1
        fi
        ;;
    Darwin*)
        if [ "$ARCH" = "x86_64" ]; then
            PLATFORM="macos-x86_64"
        elif [ "$ARCH" = "arm64" ]; then
            PLATFORM="macos-aarch64"
        else
            echo "  \033[1;31m[X]\033[0m Unsupported architecture: $ARCH"
            exit 1
        fi
        ;;
    *)
        echo "  \033[1;31m[X]\033[0m Unsupported OS: $OS"
        exit 1
        ;;
esac

echo "  \033[1;34m[*]\033[0m Detected platform:  \033[1;37m$PLATFORM\033[0m"
echo ""

# Get latest release tag from GitHub API
API_URL="https://api.github.com/repos/$REPO/releases/latest"

if command -v curl &> /dev/null; then
    RELEASE_JSON=$(curl -fsSL "$API_URL")
elif command -v wget &> /dev/null; then
    RELEASE_JSON=$(wget -qO- "$API_URL")
else
    echo "  \033[1;31m[X]\033[0m Neither curl nor wget found. Please install one of them."
    exit 1
fi

# Extract tag name from JSON (no jq dependency)
TAG_NAME=$(echo "$RELEASE_JSON" | grep '"tag_name"' | head -1 | sed 's/.*"tag_name"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/')

if [ -z "$TAG_NAME" ]; then
    echo "  \033[1;31m[X]\033[0m Failed to detect latest release."
    echo "      Check https://github.com/$REPO/releases"
    exit 1
fi

echo "  \033[1;32m[+]\033[0m Latest release:    \033[1;37m$TAG_NAME\033[0m"
echo ""

# Build download URL from the resolved tag
DOWNLOAD_URL="https://github.com/$REPO/releases/download/$TAG_NAME/overthrone-$PLATFORM"

# Create install directory
mkdir -p "$INSTALL_DIR"

echo "  \033[1;34m[*]\033[0m Downloading..."
echo "      \033[0;90m$DOWNLOAD_URL\033[0m"
echo ""

# Download binary with progress
if command -v curl &> /dev/null; then
    curl -# -L "$DOWNLOAD_URL" -o "$INSTALL_DIR/$BINARY_NAME" 2>&1 | while IFS= read -r line; do
        if echo "$line" | grep -q '%'; then
            printf "\r      \033[1;33m%s\033[0m" "$line"
        fi
    done
    echo ""
elif command -v wget &> /dev/null; then
    wget --show-progress -q "$DOWNLOAD_URL" -O "$INSTALL_DIR/$BINARY_NAME"
fi

echo ""
echo "  \033[1;34m[*]\033[0m Installing..."

# Make executable
chmod +x "$INSTALL_DIR/$BINARY_NAME"

# Create shorthand symlink
ln -sf "$INSTALL_DIR/$BINARY_NAME" "$INSTALL_DIR/$SHORTHAND"

echo "  \033[1;32m[+]\033[0m Binary:    \033[1;37m$INSTALL_DIR/$BINARY_NAME\033[0m"
echo "  \033[1;32m[+]\033[0m Shorthand: \033[1;37m$INSTALL_DIR/$SHORTHAND\033[0m"
echo ""

# Check if install dir is in PATH
if [[ ":$PATH:" != *":$INSTALL_DIR:"* ]]; then
    echo "  \033[1;33m[!]\033[0m \033[1;37m$INSTALL_DIR\033[0m is not in your PATH."
    echo "      Add this to your shell config (~/.bashrc, ~/.zshrc, etc.):"
    echo ""
    echo "      \033[0;32mexport PATH=\"\$HOME/.local/bin:\$PATH\"\033[0m"
    echo ""
fi

# Check for smbclient
if ! command -v smbclient &> /dev/null; then
    echo "  \033[1;33m[!]\033[0m smbclient not found (required for SMB operations)"
    if [ "$OS" = "Linux" ]; then
        if command -v apt &> /dev/null; then
            echo "      Install with: \033[0;32msudo apt install smbclient\033[0m"
        elif command -v pacman &> /dev/null; then
            echo "      Install with: \033[0;32msudo pacman -S samba\033[0m"
        elif command -v dnf &> /dev/null; then
            echo "      Install with: \033[0;32msudo dnf install samba-client\033[0m"
        fi
    elif [ "$OS" = "Darwin" ]; then
        echo "      Install with: \033[0;32mbrew install samba\033[0m"
    fi
    echo ""
fi

echo "---------------------------------------------------"
echo ""
echo "  \033[1;32m[+]\033[0m \033[1;37mInstallation complete!\033[0m"
echo ""
echo "      Run: \033[1;37moverthrone --help\033[0m"
echo "      Or:  \033[1;37movt --help\033[0m"
echo ""
echo "  \033[0;90mEvery throne falls. \033[1;33m👑⚔️\033[0m"
echo ""
