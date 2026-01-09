#!/bin/bash
set -e

# gitraf installer
#
# Quick install (requires Go 1.21+):
#   git clone https://git.rafayel.dev/gitraf.git && cd gitraf && ./install.sh
#
# Or manually:
#   git clone https://git.rafayel.dev/gitraf.git
#   cd gitraf && go build -o gitraf . && sudo mv gitraf /usr/local/bin/

REPO_URL="https://git.rafayel.dev/gitraf.git"
INSTALL_DIR="${INSTALL_DIR:-$HOME/.local/bin}"

echo "Installing gitraf..."

# Check for Go
if ! command -v go &> /dev/null; then
    echo "Error: Go is not installed. Please install Go first:"
    echo "  https://go.dev/doc/install"
    exit 1
fi

# Check Go version (need 1.21+)
GO_VERSION=$(go version | grep -oE 'go[0-9]+\.[0-9]+' | sed 's/go//')
GO_MAJOR=$(echo "$GO_VERSION" | cut -d. -f1)
GO_MINOR=$(echo "$GO_VERSION" | cut -d. -f2)
if [ "$GO_MAJOR" -lt 1 ] || ([ "$GO_MAJOR" -eq 1 ] && [ "$GO_MINOR" -lt 21 ]); then
    echo "Error: Go 1.21+ required, found $GO_VERSION"
    exit 1
fi

# Check if running from within the repo
if [ -f "main.go" ] && [ -f "go.mod" ]; then
    echo "Building from current directory..."
    BUILD_DIR="."
else
    echo "Cloning repository..."
    TMP_DIR=$(mktemp -d)
    trap "rm -rf $TMP_DIR" EXIT
    git clone --quiet "$REPO_URL" "$TMP_DIR/gitraf"
    BUILD_DIR="$TMP_DIR/gitraf"
fi

echo "Building..."
cd "$BUILD_DIR"
go build -o gitraf .

echo "Installing to $INSTALL_DIR..."
mkdir -p "$INSTALL_DIR"
mv gitraf "$INSTALL_DIR/"
chmod +x "$INSTALL_DIR/gitraf"

# Check if INSTALL_DIR is in PATH
if [[ ":$PATH:" != *":$INSTALL_DIR:"* ]]; then
    echo ""
    echo "Note: $INSTALL_DIR is not in your PATH."
    echo "Add it by running:"
    echo ""
    if [[ "$SHELL" == *"zsh"* ]]; then
        echo "  echo 'export PATH=\"\$HOME/.local/bin:\$PATH\"' >> ~/.zshrc"
        echo "  source ~/.zshrc"
    else
        echo "  echo 'export PATH=\"\$HOME/.local/bin:\$PATH\"' >> ~/.bashrc"
        echo "  source ~/.bashrc"
    fi
fi

echo ""
echo "gitraf installed successfully!"
echo ""
echo "Next steps - configure your server:"
echo "  gitraf config init <public_url> <tailnet_url>"
echo ""
echo "Example:"
echo "  gitraf config init https://git.example.com myserver.tail12345.ts.net"
echo ""
echo "Then run 'gitraf status' to verify your connection."
