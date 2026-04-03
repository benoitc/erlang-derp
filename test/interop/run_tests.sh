#!/bin/bash
# Run DERP interoperability tests with Go and Python clients
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
PORT="${DERP_TEST_PORT:-8080}"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

cleanup() {
    log_info "Cleaning up..."
    if [ -n "$SERVER_PID" ] && kill -0 "$SERVER_PID" 2>/dev/null; then
        kill "$SERVER_PID" 2>/dev/null || true
        wait "$SERVER_PID" 2>/dev/null || true
    fi
}

trap cleanup EXIT

# Check dependencies
check_deps() {
    log_info "Checking dependencies..."

    # Check Erlang
    if ! command -v erl &>/dev/null; then
        log_error "Erlang not found. Please install Erlang/OTP."
        exit 1
    fi

    # Check rebar3
    if ! command -v rebar3 &>/dev/null; then
        log_error "rebar3 not found. Please install rebar3."
        exit 1
    fi

    # Check Python
    if command -v python3 &>/dev/null; then
        PYTHON=python3
    elif command -v python &>/dev/null; then
        PYTHON=python
    else
        log_warn "Python not found. Skipping Python tests."
        PYTHON=""
    fi

    # Check pynacl
    if [ -n "$PYTHON" ]; then
        if ! $PYTHON -c "import nacl" 2>/dev/null; then
            log_warn "pynacl not installed. Install with: pip install pynacl"
            log_warn "Skipping Python tests."
            PYTHON=""
        fi
    fi

    # Check Go
    if command -v go &>/dev/null; then
        GO=go
    else
        log_warn "Go not found. Skipping Go tests."
        GO=""
    fi
}

# Build the project
build_project() {
    log_info "Building Erlang project..."
    cd "$PROJECT_DIR"
    rebar3 compile
}

# Start DERP server in background
start_server() {
    log_info "Starting DERP server on port $PORT..."

    cd "$PROJECT_DIR"

    # Start server with HTTP listener only (no TLS for simpler testing)
    erl -pa _build/default/lib/*/ebin \
        -noshell \
        -eval "
            application:ensure_all_started(crypto),
            application:ensure_all_started(ssl),
            application:ensure_all_started(cowboy),

            %% Start derp components
            {ok, _} = derp_registry:start_link(),
            {ok, _} = derp_rate_limiter:start_link(#{}),
            {ok, _} = derp_server_sup:start_link(),

            %% Generate keypair and store in app env
            Keypair = derp_crypto:generate_keypair(),
            application:set_env(derp, keypair, Keypair),

            %% Start HTTP listener
            {ok, _} = derp_http:start_link(#{port => $PORT, keypair => Keypair}),
            io:format(\"DERP server started on port $PORT~n\"),

            %% Keep running
            receive stop -> ok end.
        " &

    SERVER_PID=$!

    # Wait for server to start
    sleep 2

    if ! kill -0 "$SERVER_PID" 2>/dev/null; then
        log_error "Server failed to start"
        exit 1
    fi

    # Check if server is responding
    if command -v curl &>/dev/null; then
        if curl -s "http://localhost:$PORT/derp" | grep -q "DERP server ready"; then
            log_info "Server is ready"
        else
            log_warn "Server may not be responding correctly"
        fi
    fi
}

# Run Python tests
run_python_tests() {
    if [ -z "$PYTHON" ]; then
        log_warn "Skipping Python tests (Python not available)"
        return 0
    fi

    log_info "Running Python interop tests..."
    cd "$SCRIPT_DIR"

    if $PYTHON python_client_test.py --host localhost --port "$PORT" -v; then
        log_info "Python tests passed"
        return 0
    else
        log_error "Python tests failed"
        return 1
    fi
}

# Run Go tests
run_go_tests() {
    if [ -z "$GO" ]; then
        log_warn "Skipping Go tests (Go not available)"
        return 0
    fi

    log_info "Running Go interop tests..."
    cd "$SCRIPT_DIR"

    # Initialize Go modules if needed
    if [ ! -f "go.sum" ]; then
        log_info "Downloading Go dependencies..."
        go mod tidy
    fi

    if go run go_client.go -server "localhost:$PORT" -v; then
        log_info "Go tests passed"
        return 0
    else
        log_error "Go tests failed"
        return 1
    fi
}

# Main
main() {
    log_info "DERP Interoperability Tests"
    echo "=============================="
    echo

    check_deps
    build_project
    start_server

    FAILED=0

    echo
    echo "Running client tests..."
    echo "----------------------"

    if ! run_python_tests; then
        FAILED=$((FAILED + 1))
    fi

    echo

    if ! run_go_tests; then
        FAILED=$((FAILED + 1))
    fi

    echo
    echo "=============================="

    if [ $FAILED -eq 0 ]; then
        log_info "All interop tests passed!"
        exit 0
    else
        log_error "$FAILED test suite(s) failed"
        exit 1
    fi
}

main "$@"
