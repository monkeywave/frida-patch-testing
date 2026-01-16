#!/bin/bash
# Frida Patch Testing Framework - Main Build Script
# This script runs inside the Docker container

set -e  # Exit on error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

log_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

error_exit() {
    log_error "$1"
    exit 1
}

# Paths
BUILD_DIR="/build"
FRIDA_DIR="/build/frida"
CONFIG_FILE="/config/config.yaml"
PATCHES_DIR="/patches"
OUTPUT_DIR="/output"

echo ""
echo "=============================================="
echo "  Frida Patch Testing Framework"
echo "=============================================="
echo ""

# Parse configuration
log_info "Parsing configuration..."
if [ ! -f "$CONFIG_FILE" ]; then
    log_error "Configuration file not found: $CONFIG_FILE"
    log_info "Please create config.yaml (copy from config.default.yaml)"
    exit 1
fi

# Source parsed config
eval "$(python3 /build/scripts/parse-config.py "$CONFIG_FILE")"

# Force OUTPUT_DIR to /output for Docker volume mount (config may override with relative path)
OUTPUT_DIR="/output"

# Detect architecture
detect_arch() {
    ARCH=$(uname -m)
    case "${ARCH}" in
        x86_64)
            FRIDA_ARCH="x86_64"
            FRIDA_HOST="x86_64"
            ;;
        aarch64|arm64)
            FRIDA_ARCH="aarch64"
            FRIDA_HOST="arm64"
            ;;
        *)
            error_exit "Unsupported architecture: ${ARCH}"
            ;;
    esac
    log_info "Detected architecture: ${ARCH} (Frida host: ${FRIDA_HOST})"
}

detect_arch

# Clone Frida repository
log_info "=== Cloning Frida repository ==="
if [ -d "$FRIDA_DIR" ]; then
    log_info "Removing existing Frida directory..."
    rm -rf "$FRIDA_DIR"
fi

if [ "$FRIDA_VERSION" = "latest" ]; then
    log_info "Cloning latest Frida..."
    git clone --recurse-submodules --depth=1 "$FRIDA_REPO" "$FRIDA_DIR" \
        || error_exit "Failed to clone Frida repository"
else
    log_info "Cloning Frida version: $FRIDA_VERSION"
    git clone --recurse-submodules --branch "$FRIDA_VERSION" --depth=1 "$FRIDA_REPO" "$FRIDA_DIR" \
        || error_exit "Failed to clone Frida repository"
fi

cd "$FRIDA_DIR"
log_info "Current commit: $(git rev-parse --short HEAD)"

# Process each component
log_info "=== Processing components ==="
for component in frida-gum frida-core frida-python frida-tools; do
    component_var=$(echo "$component" | tr '-' '_' | tr '[:lower:]' '[:upper:]')
    source_var="${component_var}_SOURCE"
    patches_var="${component_var}_PATCHES"
    repo_var="${component_var}_REPO"
    branch_var="${component_var}_BRANCH"

    source_type="${!source_var:-official}"
    patches_enabled="${!patches_var:-true}"
    custom_repo="${!repo_var:-}"
    custom_branch="${!branch_var:-}"

    log_info "Processing $component (source: $source_type)..."

    subproject_dir="$FRIDA_DIR/subprojects/$component"

    if [ "$source_type" = "custom" ] && [ -n "$custom_repo" ]; then
        # Use custom repository
        log_info "Using custom repository for $component: $custom_repo"

        if [ -d "$subproject_dir" ]; then
            rm -rf "$subproject_dir"
        fi

        if [ -n "$custom_branch" ]; then
            git clone --branch "$custom_branch" --depth=1 "$custom_repo" "$subproject_dir" \
                || error_exit "Failed to clone custom repository for $component"
        else
            git clone --depth=1 "$custom_repo" "$subproject_dir" \
                || error_exit "Failed to clone custom repository for $component"
        fi
        log_success "Cloned custom $component"

    elif [ "$patches_enabled" = "true" ]; then
        # Apply patches using patch command (not git apply)
        PATCH_DIR="$PATCHES_DIR/$component"

        if [ -d "$PATCH_DIR" ]; then
            PATCH_FILES=$(find "$PATCH_DIR" -maxdepth 1 -name "*.patch" -type f 2>/dev/null | sort)

            if [ -n "$PATCH_FILES" ]; then
                log_info "Applying patches for $component..."
                cd "$subproject_dir"

                for patch_file in $PATCH_FILES; do
                    patch_name=$(basename "$patch_file")
                    log_info "  Applying: $patch_name"

                    if patch -p1 --dry-run < "$patch_file" >/dev/null 2>&1; then
                        patch -p1 < "$patch_file" || error_exit "Failed to apply $patch_name"
                        log_success "  Applied: $patch_name"
                    else
                        log_warn "  Patch may already be applied, trying --forward..."
                        patch -p1 --forward < "$patch_file" 2>/dev/null || true
                    fi
                done

                cd "$FRIDA_DIR"
            else
                log_info "No patches found for $component"
            fi
        else
            log_info "No patch directory for $component"
        fi
    else
        log_info "Skipping patches for $component"
    fi
done

# Configure and build
log_info "=== Configuring Frida build ==="
cd "$FRIDA_DIR"

# Build configuration options
BUILD_OPTS="--enable-server"
if [ "$BUILD_DEBUG" = "true" ]; then
    BUILD_OPTS="$BUILD_OPTS --enable-debug"
fi

log_info "Running: ./configure $BUILD_OPTS"
./configure $BUILD_OPTS || error_exit "Configuration failed"

log_info "=== Building Frida ==="
log_info "This may take a while..."

# Run make - don't fail immediately if there's an error
# (frida-python may fail due to Python header issues but frida-server might succeed)
make || {
    log_warn "Make returned an error - checking if frida-server was built anyway..."
    # Check if frida-server was built despite the error
    if find build -name "frida-server*" -type f 2>/dev/null | grep -q .; then
        log_warn "frida-server appears to have been built - continuing with artifact copy"
    else
        error_exit "Build failed and frida-server was not built"
    fi
}

log_success "Frida build completed"

# Copy artifacts to output
log_info "=== Copying build outputs ==="
mkdir -p "$OUTPUT_DIR"

# Find frida-server binary
POSSIBLE_PATHS=(
    "build/frida-linux-${FRIDA_HOST}/subprojects/frida-core/server/frida-server-raw"
    "build/frida-linux-${FRIDA_HOST}/subprojects/frida-core/server/frida-server"
    "build/subprojects/frida-core/server/frida-server-raw"
    "build/subprojects/frida-core/server/frida-server"
    "build/frida-linux-${FRIDA_HOST}/bin/frida-server"
)

FRIDA_SERVER_BIN=""
for path in "${POSSIBLE_PATHS[@]}"; do
    if [ -f "$path" ]; then
        FRIDA_SERVER_BIN="$path"
        break
    fi
done

# If not found in expected locations, search for it
if [ -z "$FRIDA_SERVER_BIN" ]; then
    log_info "Searching for frida-server binary..."
    FRIDA_SERVER_BIN=$(find build -name "frida-server-raw" -type f 2>/dev/null | head -1)
    if [ -z "$FRIDA_SERVER_BIN" ]; then
        FRIDA_SERVER_BIN=$(find build -name "frida-server" -type f -executable 2>/dev/null | head -1)
    fi
fi

if [ -n "$FRIDA_SERVER_BIN" ] && [ -f "$FRIDA_SERVER_BIN" ]; then
    OUTPUT_NAME="frida-server-linux-${FRIDA_ARCH}"
    log_info "Source binary: $FRIDA_SERVER_BIN ($(stat -c%s "$FRIDA_SERVER_BIN" 2>/dev/null || stat -f%z "$FRIDA_SERVER_BIN") bytes)"
    log_info "Copying to: $OUTPUT_DIR/$OUTPUT_NAME"
    cp -v "$FRIDA_SERVER_BIN" "$OUTPUT_DIR/$OUTPUT_NAME"
    chmod +x "$OUTPUT_DIR/$OUTPUT_NAME"
    sync  # Ensure file is flushed to disk
    log_info "After copy - verifying file:"
    ls -la "$OUTPUT_DIR/$OUTPUT_NAME"
    log_success "Copied: $OUTPUT_NAME"

    # Get version info
    VERSION=$("$OUTPUT_DIR/$OUTPUT_NAME" --version 2>/dev/null || echo "unknown")
    log_info "Frida Version: $VERSION"
else
    log_error "Could not find frida-server binary!"
    find build -name "frida-server*" -type f 2>/dev/null || true
    error_exit "frida-server binary not found"
fi

# Copy frida-python module if requested
if echo "$BUILD_TARGETS" | grep -q "frida-python"; then
    log_info "Copying frida-python module..."
    PYTHON_MODULE=$(find build -name "_frida*.so" -type f 2>/dev/null | head -1)
    if [ -n "$PYTHON_MODULE" ] && [ -f "$PYTHON_MODULE" ]; then
        FRIDA_PYTHON_SRC="subprojects/frida-python/frida"
        if [ -d "$FRIDA_PYTHON_SRC" ]; then
            mkdir -p "$OUTPUT_DIR/python/frida"
            cp -r "$FRIDA_PYTHON_SRC"/*.py "$OUTPUT_DIR/python/frida/" 2>/dev/null || true
            cp "$PYTHON_MODULE" "$OUTPUT_DIR/python/frida/"
            log_success "Copied: frida Python module"
        fi
    else
        log_warn "frida-python module not found"
    fi
fi

# Install and copy frida-tools if requested
if echo "$BUILD_TARGETS" | grep -q "frida-tools"; then
    log_info "Installing frida-tools..."
    pip3 install ./subprojects/frida-python 2>/dev/null || log_warn "Could not install frida-python"
    pip3 install ./subprojects/frida-tools 2>/dev/null || log_warn "Could not install frida-tools"

    mkdir -p "$OUTPUT_DIR/tools"
    for tool in frida frida-ps frida-trace frida-discover frida-ls-devices frida-kill; do
        TOOL_PATH=$(which "$tool" 2>/dev/null || true)
        if [ -n "$TOOL_PATH" ] && [ -f "$TOOL_PATH" ]; then
            cp "$TOOL_PATH" "$OUTPUT_DIR/tools/"
            log_success "Copied: $tool"
        fi
    done
fi

# Summary
echo ""
log_success "=== Build Complete ==="
log_info "Architecture: ${FRIDA_ARCH}"
echo ""
log_info "Output files:"
ls -la "$OUTPUT_DIR/"
if [ -d "$OUTPUT_DIR/tools" ]; then
    echo ""
    log_info "CLI Tools:"
    ls -la "$OUTPUT_DIR/tools/"
fi
echo ""
log_success "All done! Outputs are in $OUTPUT_DIR/"
