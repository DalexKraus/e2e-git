#!/bin/bash

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

PROJECT_NAME="fido2-hmac-deriver"
BINARY_NAME="fido2-hmac-deriver"
GO_MIN_VERSION="1.21"

echo -e "${BLUE}=== FIDO2 HMAC Deriver Build Script ===${NC}"
echo

print_status() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if Go is installed
check_go() {
    print_status "Checking Go installation..."
    
    if ! command -v go &> /dev/null; then
        print_error "Go is not installed or not in PATH"
        print_error "Please install Go from https://golang.org/dl/"
        exit 1
    fi
    
    GO_VERSION=$(go version | awk '{print $3}' | sed 's/go//')
    print_status "Found Go version: $GO_VERSION"
    
    # Simple version check
    if [[ "$(printf '%s\n' "$GO_MIN_VERSION" "$GO_VERSION" | sort -V | head -n1)" != "$GO_MIN_VERSION" ]]; then
        print_warning "Go version $GO_VERSION might be too old. Minimum recommended: $GO_MIN_VERSION"
    fi
}

# Check for libfido2 dependencies
check_libfido2() {
    print_status "Checking libfido2 dependencies..."
    
    # Check for pkg-config
    if ! command -v pkg-config &> /dev/null; then
        print_error "pkg-config is required but not installed"
        print_error "Install with: sudo apt-get install pkg-config"
        exit 1
    fi
    
    # Check for libfido2
    if ! pkg-config --exists libfido2; then
        print_error "libfido2 development libraries not found"
        print_error "Install with: sudo apt-get install libfido2-dev"
        exit 1
    fi
    
    LIBFIDO2_VERSION=$(pkg-config --modversion libfido2)
    print_status "Found libfido2 version: $LIBFIDO2_VERSION"
}

# Check for required system packages
check_system_deps() {
    print_status "Checking system dependencies..."
    
    # Check for build tools
    if ! command -v gcc &> /dev/null; then
        print_error "GCC compiler not found"
        print_error "Install with: sudo apt-get install build-essential"
        exit 1
    fi
    
    print_status "System dependencies OK"
}

# Clean previous builds
clean_build() {
    print_status "Cleaning previous builds..."
    
    if [ -f "$BINARY_NAME" ]; then
        rm "$BINARY_NAME"
        print_status "Removed existing binary"
    fi
    
    # Clean Go module cache if requested
    if [ "$1" = "--clean-cache" ]; then
        go clean -modcache
        print_status "Cleaned Go module cache"
    fi
}

# Download dependencies
download_deps() {
    print_status "Downloading Go dependencies..."
    
    go mod download
    go mod verify
    
    print_status "Dependencies downloaded and verified"
}

# Build the application
build_app() {
    print_status "Building $PROJECT_NAME..."
    
    # Set build flags
    BUILD_TIME=$(date -u '+%Y-%m-%d_%H:%M:%S')
    GIT_COMMIT=$(git rev-parse --short HEAD 2>/dev/null || echo "unknown")
    
    # Build with optimizations and static linking
    CGO_ENABLED=1 go build \
        -ldflags "-s -w -X main.BuildTime=$BUILD_TIME -X main.GitCommit=$GIT_COMMIT" \
        -o "$BINARY_NAME" \
        .
    
    chmod +x "$BINARY_NAME"
    
    print_status "Build completed successfully"
}

# Verify the build
verify_build() {
    print_status "Verifying build..."
    
    if [ ! -f "$BINARY_NAME" ]; then
        print_error "Binary not found after build"
        exit 1
    fi
    
    if [ ! -x "$BINARY_NAME" ]; then
        print_error "Binary is not executable"
        exit 1
    fi
    
    BINARY_SIZE=$(du -h "$BINARY_NAME" | cut -f1)
    print_status "Binary size: $BINARY_SIZE"
    
    # Test if binary can run (just a basic check)
    if ./"$BINARY_NAME" --help &> /dev/null; then
        print_status "Binary appears to be working"
    else
        print_warning "Binary help command failed - this might be normal if no devices are connected"
    fi
}

# Print usage information
print_usage() {
    echo "Usage: $0 [OPTIONS]"
    echo
    echo "Options:"
    echo "  --clean-cache   Clean Go module cache before building"
    echo "  --help          Show this help message"
    echo
}

# Main execution
main() {
    # Parse command line arguments
    case "${1:-}" in
        --help|-h)
            print_usage
            exit 0
            ;;
        --clean-cache)
            CLEAN_CACHE="--clean-cache"
            ;;
        "")
            # No arguments, proceed normally
            ;;
        *)
            print_error "Unknown option: $1"
            print_usage
            exit 1
            ;;
    esac
    
    # Execute build steps
    check_go
    check_libfido2
    check_system_deps
    clean_build $CLEAN_CACHE
    download_deps
    build_app
    verify_build
    
    echo
    print_status "Build process completed successfully!"
    print_status "Binary: ./$BINARY_NAME"
    echo
    echo -e "${BLUE}To run the application:${NC}"
    echo -e "  ./$BINARY_NAME"
    echo
    echo -e "${BLUE}For help:${NC}"
    echo -e "  ./$BINARY_NAME --help"
    echo
}

# Run main function with all arguments
main "$@"
