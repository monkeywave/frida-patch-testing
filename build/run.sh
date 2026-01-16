#!/bin/bash
# Frida Patch Testing Framework - Host Launcher
# Run this script from the frida-patch-testing directory

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${GREEN}Frida Patch Testing Framework${NC}"
echo "================================"

# Check for config.yaml
CONFIG_FILE="$PROJECT_DIR/config.yaml"
if [ ! -f "$CONFIG_FILE" ]; then
    echo -e "${YELLOW}[WARN]${NC} config.yaml not found"
    echo "Copying config.default.yaml to config.yaml..."
    cp "$PROJECT_DIR/config.default.yaml" "$CONFIG_FILE"
fi

# Build Docker image
echo -e "\n${GREEN}Building Docker image...${NC}"
docker build -t frida-patch-builder "$SCRIPT_DIR"

# Run the build
echo -e "\n${GREEN}Starting build...${NC}"
docker run --rm \
    -v "$PROJECT_DIR/config.yaml:/config/config.yaml:ro" \
    -v "$PROJECT_DIR/patches:/patches:ro" \
    -v "$PROJECT_DIR/output:/output" \
    frida-patch-builder

echo -e "\n${GREEN}Build complete!${NC}"
echo "Output files are in: $PROJECT_DIR/output/"
