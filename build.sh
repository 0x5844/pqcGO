#!/bin/bash

# Enhanced Post-Quantum Encryption Engine Build Script
# Optimized for performance, security, and cross-platform deployment

set -euo pipefail

# Build Configuration
readonly BINARY_NAME="quantum-engine"
readonly VERSION="${VERSION:-$(git describe --tags --always --dirty 2>/dev/null || echo 'dev')}"
readonly BUILD_TIME="$(date -u '+%Y-%m-%d_%H:%M:%S_UTC')"
readonly GO_VERSION="$(go version | awk '{print $3}')"

# Directories
readonly PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly BUILD_DIR="${PROJECT_ROOT}/build"
readonly DIST_DIR="${PROJECT_ROOT}/dist"
readonly VENDOR_DIR="${PROJECT_ROOT}/vendor"

# Build flags for optimal performance and security
readonly LDFLAGS=(
    "-s"                                    # Strip symbol table
    "-w"                                    # Strip DWARF debug info
    "-X main.Version=${VERSION}"
    "-X main.BuildTime=${BUILD_TIME}"
    "-X main.GoVersion=${GO_VERSION}"
    "-extldflags '-static'"                 # Static linking for security
)

readonly GCFLAGS=(
    "-l=4"                                  # Maximum inlining
    "-B"                                    # Disable bounds checking (careful!)
)

readonly BUILD_FLAGS=(
    "-trimpath"                             # Remove file system paths
    "-buildmode=exe"                        # Executable mode
    "-buildvcs=false"                       # Disable VCS info for reproducible builds
)

# Supported platforms for cross-compilation
readonly PLATFORMS=(
    "linux/amd64"
    "linux/arm64"
    "darwin/amd64"
    "darwin/arm64"
    "windows/amd64"
    "windows/arm64"
    "freebsd/amd64"
)

# Colors for output
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly NC='\033[0m' # No Color

# Logging functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $*"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $*"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $*"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $*" >&2
}

# Cleanup function
cleanup() {
    log_info "Cleaning up temporary files..."
    # Add cleanup logic if needed
}
trap cleanup EXIT

# Check prerequisites
check_prerequisites() {
    log_info "Checking prerequisites..."
    
    # Check Go version (require 1.24+ for ML-KEM support)
    local go_version
    go_version=$(go version | grep -oE 'go[0-9]+\.[0-9]+' | sed 's/go//')
    local major minor
    IFS='.' read -r major minor <<< "$go_version"
    
    if [[ $major -lt 1 || ($major -eq 1 && $minor -lt 24) ]]; then
        log_error "Go 1.24+ required for ML-KEM support. Current: go$go_version"
        exit 1
    fi
    
    # Check required tools
    local tools=("git" "upx")
    for tool in "${tools[@]}"; do
        if ! command -v "$tool" &> /dev/null; then
            log_warning "$tool not found. Some optimizations may be skipped."
        fi
    done
    
    log_success "Prerequisites check completed"
}

# Setup environment
setup_environment() {
    log_info "Setting up build environment..."
    
    # Create directories
    mkdir -p "$BUILD_DIR" "$DIST_DIR"
    
    # Set optimal Go environment
    export CGO_ENABLED=0                    # Disable CGO for static builds
    export GOPROXY=https://proxy.golang.org,direct
    export GOSUMDB=sum.golang.org
    export GOFLAGS="-mod=readonly"          # Ensure reproducible builds
    
    # Performance environment
    export GOMAXPROCS="$(nproc)"            # Use all CPU cores
    export GOGC=100                         # Optimize GC
    
    log_success "Environment setup completed"
}

# Download and verify dependencies
setup_dependencies() {
    log_info "Setting up dependencies..."
    
    # Initialize go.mod if it doesn't exist
    if [[ ! -f go.mod ]]; then
        log_info "Initializing go.mod..."
        go mod init quantum-engine
    fi
    
    # Add required dependencies
    log_info "Adding dependencies..."
    go get github.com/kudelskisecurity/crystals-go@latest
    go get golang.org/x/crypto/blake2s@latest
    go get golang.org/x/crypto/chacha20poly1305@latest
    go get golang.org/x/crypto/curve25519@latest
    go get golang.org/x/crypto/hkdf@latest
    
    # Download and verify
    go mod download
    go mod verify
    go mod tidy
    
    # Vendor dependencies for offline builds
    if [[ "${VENDOR:-false}" == "true" ]]; then
        log_info "Vendoring dependencies..."
        go mod vendor
    fi
    
    log_success "Dependencies setup completed"
}

# Run security checks
run_security_checks() {
    log_info "Running security checks..."
    
    # Check for known vulnerabilities
    if command -v govulncheck &> /dev/null; then
        log_info "Scanning for vulnerabilities..."
        govulncheck ./...
    else
        log_warning "govulncheck not found. Install with: go install golang.org/x/vuln/cmd/govulncheck@latest"
    fi
    
    # Static analysis
    if command -v gosec &> /dev/null; then
        log_info "Running security analysis..."
        gosec -fmt json -out "${BUILD_DIR}/security-report.json" ./...
    else
        log_warning "gosec not found. Install with: go install github.com/securecodewarrior/gosec/v2/cmd/gosec@latest"
    fi
    
    log_success "Security checks completed"
}

# Run tests
run_tests() {
    log_info "Running tests..."
    
    # Unit tests with race detection
    go test -race -coverprofile="${BUILD_DIR}/coverage.out" -covermode=atomic ./...
    
    # Generate coverage report
    if [[ -f "${BUILD_DIR}/coverage.out" ]]; then
        go tool cover -html="${BUILD_DIR}/coverage.out" -o "${BUILD_DIR}/coverage.html"
        local coverage
        coverage=$(go tool cover -func="${BUILD_DIR}/coverage.out" | tail -n 1 | awk '{print $3}')
        log_info "Test coverage: $coverage"
    fi
    
    # Benchmark tests
    log_info "Running benchmarks..."
    go test -bench=. -benchmem -cpuprofile="${BUILD_DIR}/cpu.prof" -memprofile="${BUILD_DIR}/mem.prof" ./... > "${BUILD_DIR}/benchmark.txt"
    
    log_success "Tests completed"
}

# Build for single platform
build_single() {
    local goos="$1"
    local goarch="$2"
    local output_name="${BINARY_NAME}"
    
    if [[ "$goos" == "windows" ]]; then
        output_name="${output_name}.exe"
    fi
    
    local output_path="${BUILD_DIR}/${goos}-${goarch}/${output_name}"
    mkdir -p "$(dirname "$output_path")"
    
    log_info "Building for ${goos}/${goarch}..."
    
    # Build with optimal flags
    GOOS="$goos" GOARCH="$goarch" go build \
        "${BUILD_FLAGS[@]}" \
        -ldflags "${LDFLAGS[*]}" \
        -gcflags "${GCFLAGS[*]}" \
        -o "$output_path" \
        .
    
    # Post-processing optimizations
    if [[ "$goos" == "$(go env GOOS)" && "$goarch" == "$(go env GOARCH)" ]]; then
        # UPX compression for same architecture (careful with cryptographic code)
        if command -v upx &> /dev/null && [[ "${UPX_COMPRESS:-false}" == "true" ]]; then
            log_info "Compressing binary with UPX..."
            upx --best --lzma "$output_path" || log_warning "UPX compression failed"
        fi
        
        # Strip additional symbols if possible
        if command -v strip &> /dev/null; then
            strip "$output_path" 2>/dev/null || true
        fi
    fi
    
    # Generate checksums
    if command -v sha256sum &> /dev/null; then
        (cd "$(dirname "$output_path")" && sha256sum "$(basename "$output_path")" > "${output_path}.sha256")
    fi
    
    local size
    size=$(du -h "$output_path" | cut -f1)
    log_success "Built ${goos}/${goarch} binary (${size}): $output_path"
}

# Build for all platforms
build_all() {
    log_info "Building for all platforms..."
    
    local build_start
    build_start=$(date +%s)
    
    # Build in parallel for faster compilation
    local pids=()
    for platform in "${PLATFORMS[@]}"; do
        IFS='/' read -r goos goarch <<< "$platform"
        (build_single "$goos" "$goarch") &
        pids+=($!)
        
        # Limit concurrent builds to prevent resource exhaustion
        if [[ ${#pids[@]} -ge 4 ]]; then
            wait "${pids[0]}"
            pids=("${pids[@]:1}")
        fi
    done
    
    # Wait for remaining builds
    for pid in "${pids[@]}"; do
        wait "$pid"
    done
    
    local build_time=$(($(date +%s) - build_start))
    log_success "All platforms built in ${build_time}s"
}

# Create distribution packages
create_packages() {
    log_info "Creating distribution packages..."
    
    for platform in "${PLATFORMS[@]}"; do
        IFS='/' read -r goos goarch <<< "$platform"
        local binary_name="${BINARY_NAME}"
        [[ "$goos" == "windows" ]] && binary_name="${binary_name}.exe"
        
        local build_path="${BUILD_DIR}/${goos}-${goarch}"
        local package_name="${BINARY_NAME}-${VERSION}-${goos}-${goarch}"
        
        if [[ -f "${build_path}/${binary_name}" ]]; then
            # Create package directory
            local package_dir="${DIST_DIR}/${package_name}"
            mkdir -p "$package_dir"
            
            # Copy binary and checksums
            cp "${build_path}/${binary_name}" "$package_dir/"
            [[ -f "${build_path}/${binary_name}.sha256" ]] && cp "${build_path}/${binary_name}.sha256" "$package_dir/"
            
            # Add documentation
            cp README.md "$package_dir/" 2>/dev/null || echo "# Quantum Encryption Engine v${VERSION}" > "$package_dir/README.md"
            
            # Create LICENSE if not exists
            [[ -f LICENSE ]] && cp LICENSE "$package_dir/" || cat > "$package_dir/LICENSE" << 'EOF'
MIT License - Post-Quantum Encryption Engine
EOF
            
            # Create archive
            (cd "$DIST_DIR" && tar -czf "${package_name}.tar.gz" "$package_name")
            rm -rf "$package_dir"
            
            log_success "Created package: ${package_name}.tar.gz"
        fi
    done
}

# Generate build report
generate_report() {
    log_info "Generating build report..."
    
    local report_file="${BUILD_DIR}/build-report.md"
    cat > "$report_file" << EOF
# Build Report - Quantum Encryption Engine

## Build Information
- **Version:** ${VERSION}
- **Build Time:** ${BUILD_TIME}
- **Go Version:** ${GO_VERSION}
- **Builder:** $(whoami)@$(hostname)

## Security Features
- **Hybrid KEM:** ML-KEM/Kyber + X25519
- **Symmetric Encryption:** XChaCha20-Poly1305
- **Hash Function:** BLAKE2s
- **File Integrity:** HMAC-BLAKE2s

## Build Optimizations
- Static linking enabled
- Symbol table stripped
- Debug info removed
- Maximum inlining (level 4)
- Path trimming for reproducible builds

## Built Platforms
EOF
    
    for platform in "${PLATFORMS[@]}"; do
        IFS='/' read -r goos goarch <<< "$platform"
        local binary_name="${BINARY_NAME}"
        [[ "$goos" == "windows" ]] && binary_name="${binary_name}.exe"
        local binary_path="${BUILD_DIR}/${goos}-${goarch}/${binary_name}"
        
        if [[ -f "$binary_path" ]]; then
            local size
            size=$(du -h "$binary_path" | cut -f1)
            echo "- **${goos}/${goarch}:** ${size}" >> "$report_file"
        fi
    done
    
    log_success "Build report generated: $report_file"
}

# Main build function
main() {
    local start_time
    start_time=$(date +%s)
    
    log_info "Starting Post-Quantum Encryption Engine build..."
    log_info "Version: $VERSION"
    log_info "Build configuration: optimized for performance and security"
    
    # Parse command line arguments
    local mode="${1:-all}"
    
    case "$mode" in
        "deps"|"dependencies")
            setup_environment
            setup_dependencies
            ;;
        "test")
            check_prerequisites
            setup_environment
            run_tests
            ;;
        "security"|"sec")
            check_prerequisites
            setup_environment
            run_security_checks
            ;;
        "single")
            local target_platform="${2:-$(go env GOOS)/$(go env GOARCH)}"
            IFS='/' read -r goos goarch <<< "$target_platform"
            check_prerequisites
            setup_environment
            setup_dependencies
            build_single "$goos" "$goarch"
            ;;
        "all"|"")
            check_prerequisites
            setup_environment
            setup_dependencies
            run_security_checks
            run_tests
            build_all
            create_packages
            generate_report
            ;;
        "clean")
            log_info "Cleaning build artifacts..."
            rm -rf "$BUILD_DIR" "$DIST_DIR" "$VENDOR_DIR"
            go clean -cache -modcache -testcache
            log_success "Clean completed"
            exit 0
            ;;
        "help"|"-h"|"--help")
            cat << 'EOF'
Post-Quantum Encryption Engine Build Script

Usage: ./build.sh [MODE] [OPTIONS]

Modes:
  all          Full build pipeline (default)
  deps         Setup dependencies only
  test         Run tests and benchmarks
  security     Run security checks
  single       Build for single platform
  clean        Clean all build artifacts
  help         Show this help

Examples:
  ./build.sh                    # Full build
  ./build.sh single linux/amd64 # Build for specific platform
  ./build.sh test              # Run tests only
  
Environment Variables:
  VERSION      Set build version
  VENDOR       Enable vendoring (true/false)
  UPX_COMPRESS Enable UPX compression (true/false)

Security Features:
- Static linking for minimal attack surface
- Symbol stripping for reverse engineering protection
- Vulnerability scanning with govulncheck
- Security analysis with gosec
- Reproducible builds with path trimming

Performance Optimizations:
- Maximum inlining optimization
- Parallel cross-compilation
- Binary compression (optional)
- Memory and CPU profiling
EOF
            exit 0
            ;;
        *)
            log_error "Unknown mode: $mode"
            log_info "Use './build.sh help' for usage information"
            exit 1
            ;;
    esac
    
    local total_time=$(($(date +%s) - start_time))
    log_success "Build completed in ${total_time}s"
    
    if [[ "$mode" == "all" || "$mode" == "" ]]; then
        log_info "Distribution packages available in: $DIST_DIR"
        log_info "Build artifacts available in: $BUILD_DIR"
    fi
}

# Execute main function with all arguments
main "$@"
