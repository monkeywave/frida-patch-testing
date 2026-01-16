#!/bin/bash
# Frida Patch Testing Framework - Patch Application Script
#
# Usage: apply-patches.sh <component> <patches-dir> <target-dir>
#
# Applies all .patch files from patches-dir to target-dir in alphabetical order
# Uses `patch -p1` command (compatible with git format-patch output)

set -e

COMPONENT="$1"
PATCHES_DIR="$2"
TARGET_DIR="$3"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log_info() { echo -e "${BLUE}[PATCH]${NC} $1"; }
log_success() { echo -e "${GREEN}[PATCH]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[PATCH]${NC} $1"; }
log_error() { echo -e "${RED}[PATCH]${NC} $1"; }

if [ -z "$COMPONENT" ] || [ -z "$PATCHES_DIR" ] || [ -z "$TARGET_DIR" ]; then
    log_error "Usage: apply-patches.sh <component> <patches-dir> <target-dir>"
    exit 1
fi

if [ ! -d "$PATCHES_DIR" ]; then
    log_info "No patches directory for $COMPONENT"
    exit 0
fi

if [ ! -d "$TARGET_DIR" ]; then
    log_error "Target directory does not exist: $TARGET_DIR"
    exit 1
fi

# Find all .patch files, sorted alphabetically
PATCH_FILES=$(find "$PATCHES_DIR" -maxdepth 1 -name "*.patch" -type f 2>/dev/null | sort)

if [ -z "$PATCH_FILES" ]; then
    log_info "No patches found for $COMPONENT"
    exit 0
fi

# Count patches
PATCH_COUNT=$(echo "$PATCH_FILES" | wc -l | tr -d ' ')
log_info "Found $PATCH_COUNT patch(es) for $COMPONENT"

# Apply each patch
cd "$TARGET_DIR"
APPLIED=0

for patch_file in $PATCH_FILES; do
    patch_name=$(basename "$patch_file")
    log_info "Applying: $patch_name"

    # Try dry-run first to check if patch applies cleanly
    if patch -p1 --dry-run < "$patch_file" >/dev/null 2>&1; then
        patch -p1 < "$patch_file"
        log_success "Applied: $patch_name"
        APPLIED=$((APPLIED + 1))
    else
        log_warn "Patch may already be applied or doesn't match exactly"
        log_warn "Trying with --forward flag..."

        # Try with --forward to skip already-applied hunks
        if patch -p1 --forward < "$patch_file" 2>/dev/null; then
            log_success "Applied (with --forward): $patch_name"
            APPLIED=$((APPLIED + 1))
        else
            log_error "Cannot apply patch: $patch_name"
            log_error "The patch may not match the current source version"
            log_error "Please regenerate the patch for the current Frida version"
            exit 1
        fi
    fi
done

log_success "Applied $APPLIED/$PATCH_COUNT patches for $COMPONENT"
