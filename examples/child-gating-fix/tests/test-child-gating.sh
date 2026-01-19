#!/bin/bash
#
# test-child-gating.sh - Helper script to test child-gating with patched frida-server
#
# This script:
#   1. Checks for/compiles the test program
#   2. Checks if frida-server is running (optionally starts it)
#   3. Runs the child-gating test
#
# Usage:
#   ./test-child-gating.sh                    # Run with defaults
#   ./test-child-gating.sh --start-server     # Also start frida-server
#   ./test-child-gating.sh --server-path PATH # Specify frida-server location
#

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TEST_BINARY="$SCRIPT_DIR/test_fork"
TEST_SCRIPT="$SCRIPT_DIR/test_child_gating.py"
TEST_SOURCE="$SCRIPT_DIR/test_fork.c"

# Default frida-server paths to check
FRIDA_SERVER_PATHS=(
    "$SCRIPT_DIR/../../../output/frida-server-linux-x86_64"
    "/usr/local/bin/frida-server"
    "/usr/bin/frida-server"
)

# Options
START_SERVER=false
SERVER_PATH=""
TIMEOUT=60
VERBOSE=false

print_usage() {
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  -s, --start-server       Start frida-server if not running"
    echo "  -p, --server-path PATH   Path to frida-server binary"
    echo "  -t, --timeout SECONDS    Test timeout (default: 60)"
    echo "  -v, --verbose            Verbose output"
    echo "  -h, --help               Show this help"
    echo ""
    echo "Examples:"
    echo "  $0                           # Run test (frida-server must be running)"
    echo "  $0 --start-server            # Start server and run test"
    echo "  $0 -s -p /path/to/server     # Use specific server binary"
}

log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[OK]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -s|--start-server)
            START_SERVER=true
            shift
            ;;
        -p|--server-path)
            SERVER_PATH="$2"
            shift 2
            ;;
        -t|--timeout)
            TIMEOUT="$2"
            shift 2
            ;;
        -v|--verbose)
            VERBOSE=true
            shift
            ;;
        -h|--help)
            print_usage
            exit 0
            ;;
        *)
            log_error "Unknown option: $1"
            print_usage
            exit 1
            ;;
    esac
done

echo "============================================================"
echo "  FRIDA CHILD-GATING TEST HELPER"
echo "============================================================"
echo ""

# Step 1: Check/compile test binary
log_info "Checking test binary..."

if [ -f "$TEST_BINARY" ]; then
    log_success "Test binary found: $TEST_BINARY"
else
    log_info "Compiling test binary..."
    if [ ! -f "$TEST_SOURCE" ]; then
        log_error "Test source not found: $TEST_SOURCE"
        exit 1
    fi

    gcc -pthread -o "$TEST_BINARY" "$TEST_SOURCE"
    if [ $? -eq 0 ]; then
        log_success "Compiled: $TEST_BINARY"
    else
        log_error "Compilation failed"
        exit 1
    fi
fi

# Verify test binary works standalone
log_info "Verifying test binary works standalone..."
timeout 10 "$TEST_BINARY" > /dev/null 2>&1 || true
log_success "Test binary executes"

# Step 2: Check frida-server
log_info "Checking frida-server..."

find_frida_server() {
    if [ -n "$SERVER_PATH" ]; then
        if [ -f "$SERVER_PATH" ]; then
            echo "$SERVER_PATH"
            return 0
        fi
    fi

    for path in "${FRIDA_SERVER_PATHS[@]}"; do
        if [ -f "$path" ]; then
            echo "$path"
            return 0
        fi
    done

    # Try which
    which frida-server 2>/dev/null && return 0

    return 1
}

is_server_running() {
    pgrep -x frida-server > /dev/null 2>&1
    return $?
}

if is_server_running; then
    log_success "frida-server is already running"
    SERVER_PID=$(pgrep -x frida-server)
    log_info "Server PID: $SERVER_PID"
else
    log_warn "frida-server is not running"

    if [ "$START_SERVER" = true ]; then
        FOUND_SERVER=$(find_frida_server)
        if [ -z "$FOUND_SERVER" ]; then
            log_error "Cannot find frida-server binary"
            log_info "Checked paths:"
            for path in "${FRIDA_SERVER_PATHS[@]}"; do
                echo "    $path"
            done
            exit 1
        fi

        log_info "Starting frida-server: $FOUND_SERVER"
        log_info "Note: This requires root privileges"

        sudo "$FOUND_SERVER" &
        sleep 2

        if is_server_running; then
            log_success "frida-server started"
        else
            log_error "Failed to start frida-server"
            exit 1
        fi
    else
        log_error "frida-server is not running"
        log_info "Start it manually with: sudo frida-server &"
        log_info "Or run this script with --start-server"
        exit 1
    fi
fi

# Step 3: Verify frida connection
log_info "Verifying frida connection..."

if command -v frida-ps &> /dev/null; then
    if frida-ps > /dev/null 2>&1; then
        PROCESS_COUNT=$(frida-ps 2>/dev/null | wc -l)
        log_success "Connected to frida-server ($PROCESS_COUNT processes visible)"
    else
        log_error "Cannot connect to frida-server"
        exit 1
    fi
else
    log_warn "frida-ps not found, skipping connection test"
    log_info "Install with: pip3 install frida-tools"
fi

# Step 4: Check frida versions match
log_info "Checking frida versions..."

get_python_frida_version() {
    python3 -c "import frida; print(frida.__version__)" 2>/dev/null
}

get_server_version() {
    if is_server_running; then
        # Try to get version from running server via frida-ps
        frida-ps 2>/dev/null | head -1 > /dev/null && echo "running"
    fi
}

PYTHON_VERSION=$(get_python_frida_version)
if [ -n "$PYTHON_VERSION" ]; then
    log_info "frida-python version: $PYTHON_VERSION"
else
    log_error "frida-python not installed"
    log_info "Install with: pip3 install frida"
    exit 1
fi

# Step 5: Run the test
echo ""
echo "============================================================"
echo "  RUNNING CHILD-GATING TEST"
echo "============================================================"
echo ""

log_info "Test script: $TEST_SCRIPT"
log_info "Test binary: $TEST_BINARY"
log_info "Timeout: ${TIMEOUT}s"
echo ""

# Run with sudo if needed (for ptrace permissions)
if [ "$EUID" -eq 0 ]; then
    python3 "$TEST_SCRIPT" --test-binary "$TEST_BINARY" --timeout "$TIMEOUT"
else
    log_warn "Running without root - may need elevated privileges for ptrace"
    python3 "$TEST_SCRIPT" --test-binary "$TEST_BINARY" --timeout "$TIMEOUT"
fi

EXIT_CODE=$?

echo ""
if [ $EXIT_CODE -eq 0 ]; then
    log_success "Test completed successfully!"
else
    log_error "Test failed with exit code: $EXIT_CODE"
fi

exit $EXIT_CODE
