#!/bin/bash
# Frida Patch Testing Framework - Repository Clone Helper
#
# Usage: clone-repos.sh <repo-url> <target-dir> [branch]

set -e

REPO_URL="$1"
TARGET_DIR="$2"
BRANCH="$3"

# Colors
BLUE='\033[0;34m'
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m'

log_info() { echo -e "${BLUE}[CLONE]${NC} $1"; }
log_success() { echo -e "${GREEN}[CLONE]${NC} $1"; }
log_error() { echo -e "${RED}[CLONE]${NC} $1"; }

if [ -z "$REPO_URL" ] || [ -z "$TARGET_DIR" ]; then
    log_error "Usage: clone-repos.sh <repo-url> <target-dir> [branch]"
    exit 1
fi

# Remove existing directory if present
if [ -d "$TARGET_DIR" ]; then
    log_info "Removing existing directory: $TARGET_DIR"
    rm -rf "$TARGET_DIR"
fi

log_info "Cloning $REPO_URL"

if [ -n "$BRANCH" ]; then
    log_info "Using branch: $BRANCH"
    git clone --branch "$BRANCH" --depth 1 "$REPO_URL" "$TARGET_DIR"
else
    git clone --depth 1 "$REPO_URL" "$TARGET_DIR"
fi

log_success "Cloned to: $TARGET_DIR"
