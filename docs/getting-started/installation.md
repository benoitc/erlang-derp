# Installation

## Prerequisites

Before building DERP, ensure you have the following installed:

- **Erlang/OTP 26+** (27 recommended)
- **rebar3** - Erlang build tool
- **libsodium** - Development headers and library
- **CMake 3.14+** - For NIF compilation
- **C compiler** - GCC or Clang

### Installing Dependencies

=== "Ubuntu/Debian"

    ```bash
    sudo apt-get update
    sudo apt-get install erlang rebar3 libsodium-dev cmake build-essential
    ```

=== "Fedora/RHEL"

    ```bash
    sudo dnf install erlang rebar3 libsodium-devel cmake gcc gcc-c++
    ```

=== "macOS"

    ```bash
    brew install erlang rebar3 libsodium cmake
    ```

=== "Alpine"

    ```bash
    apk add erlang rebar3 libsodium-dev cmake gcc g++ musl-dev
    ```

## Building from Source

### Clone the Repository

```bash
git clone https://github.com/benoitc/erlang-derp.git
cd erlang-derp
```

### Compile

```bash
rebar3 compile
```

This will:

1. Fetch dependencies (Cowboy, JSX)
2. Compile the libsodium NIF
3. Compile Erlang source files

### Run Tests

```bash
# Unit tests
rebar3 eunit

# Integration tests
rebar3 ct

# Type checking
rebar3 dialyzer

# Cross-reference analysis
rebar3 xref
```

### Build a Release

```bash
rebar3 release
```

The release will be created in `_build/default/rel/derp/`.

### Build Production Release

```bash
rebar3 as prod release
```

This creates an optimized release with embedded Erlang runtime in `_build/prod/rel/derp/`.

## Docker Installation

For Docker-based deployment, see the [Docker Deployment Guide](../guide/docker.md).

```bash
# Build the image
docker build -t derp -f docker/Dockerfile .

# Or use docker-compose
cd docker
./certs/generate.sh  # Generate test certificates
docker-compose up
```

## Verification

After installation, verify everything works:

```bash
# Start the Erlang shell with the application
rebar3 shell

# In the shell, start the application
1> application:ensure_all_started(derp).
{ok,[jsx,cowlib,ranch,cowboy,derp]}

# Check the server is running
2> derp_server:get_public_key().
<<...32 bytes...>>
```

## Project Structure

```
erlang-derp/
├── src/                    # Erlang source files
│   ├── derp.app.src        # Application resource file
│   ├── derp_app.erl        # Application behavior
│   ├── derp_sup.erl        # Top-level supervisor
│   ├── derp_server.erl     # Server implementation
│   ├── derp_client.erl     # Client implementation
│   ├── derp_frame.erl      # Protocol framing
│   ├── derp_crypto.erl     # Cryptographic operations
│   └── ...
├── c_src/                  # C source for NIF
│   ├── derp_sodium_nif.c   # libsodium NIF
│   └── Makefile
├── config/                 # Release configuration
│   ├── sys.config          # Application config
│   └── vm.args             # VM arguments
├── docker/                 # Docker files
└── test/                   # Test files
```
