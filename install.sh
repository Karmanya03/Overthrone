#!/bin/bash
set -e

# Overthrone installer for Linux/macOS
# Usage: curl -fsSL https://raw.githubusercontent.com/Karmanya03/Overthrone/main/install.sh | bash

REPO="Karmanya03/Overthrone"
INSTALL_DIR="$HOME/.local/bin"
BINARY_NAME="overthrone"
SHORTHAND="ovt"

echo "🔥 Installing Overthrone..."

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
            echo "❌ Unsupported architecture: $ARCH"
            exit 1
        fi
        ;;
    Darwin*)
        if [ "$ARCH" = "x86_64" ]; then
            PLATFORM="macos-x86_64"
        elif [ "$ARCH" = "arm64" ]; then
            PLATFORM="macos-aarch64"
        else
            echo "❌ Unsupported architecture: $ARCH"
            exit 1
        fi
        ;;
    *)
        echo "❌ Unsupported OS: $OS"
        exit 1
        ;;
esac

echo "📦 Detected platform: $PLATFORM"

# Get latest release URL
DOWNLOAD_URL="https://github.com/$REPO/releases/latest/download/overthrone-$PLATFORM"
if [ "$OS" = "Darwin" ] || [ "$OS" = "Linux" ]; then
    DOWNLOAD_URL="${DOWNLOAD_URL}"
else
    DOWNLOAD_URL="${DOWNLOAD_URL}.exe"
fi

# Create install directory
mkdir -p "$INSTALL_DIR"

# Download binary
echo "⬇️  Downloading from $DOWNLOAD_URL..."
if command -v curl &> /dev/null; then
    curl -fsSL "$DOWNLOAD_URL" -o "$INSTALL_DIR/$BINARY_NAME"
elif command -v wget &> /dev/null; then
    wget -q "$DOWNLOAD_URL" -O "$INSTALL_DIR/$BINARY_NAME"
else
    echo "❌ Neither curl nor wget found. Please install one of them."
    exit 1
fi

# Make executable
chmod +x "$INSTALL_DIR/$BINARY_NAME"

# Create shorthand symlink
ln -sf "$INSTALL_DIR/$BINARY_NAME" "$INSTALL_DIR/$SHORTHAND"

echo "✅ Installed to $INSTALL_DIR/$BINARY_NAME"
echo "✅ Shorthand: $INSTALL_DIR/$SHORTHAND"

# Check if install dir is in PATH
if [[ ":$PATH:" != *":$INSTALL_DIR:"* ]]; then
    echo ""
    echo "⚠️  $INSTALL_DIR is not in your PATH."
    echo "   Add this line to your shell config (~/.bashrc, ~/.zshrc, etc.):"
    echo ""
    echo "   export PATH=\"\$HOME/.local/bin:\$PATH\""
    echo ""
fi

# Check for smbclient
if ! command -v smbclient &> /dev/null; then
    echo ""
    echo "⚠️  smbclient not found (required for SMB operations)"
    if [ "$OS" = "Linux" ]; then
        if command -v apt &> /dev/null; then
            echo "   Install with: sudo apt install smbclient"
        elif command -v pacman &> /dev/null; then
            echo "   Install with: sudo pacman -S samba"
        elif command -v dnf &> /dev/null; then
            echo "   Install with: sudo dnf install samba-client"
        fi
    elif [ "$OS" = "Darwin" ]; then
        echo "   Install with: brew install samba"
    fi
fi

echo ""
echo "🎯 Installation complete!"
echo "   Run: overthrone --help"
echo "   Or:  ovt --help"
echo ""
echo "Every throne falls. 👑⚔️"
