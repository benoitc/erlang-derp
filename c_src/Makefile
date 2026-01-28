# Makefile for derp_sodium NIF
# Supports: macOS (arm64/x86_64), Linux (arm64/amd64), FreeBSD

.PHONY: all clean rebuild

BUILD_DIR := build
PRIV_DIR := ../priv

# Detect OS and architecture
UNAME_S := $(shell uname -s)
UNAME_M := $(shell uname -m)

# CMake build type (Release by default)
CMAKE_BUILD_TYPE ?= Release

# CMake generator (default to Unix Makefiles)
CMAKE_GENERATOR ?= "Unix Makefiles"

# Additional CMake options
CMAKE_OPTS ?=

# Platform-specific settings
ifeq ($(UNAME_S),Darwin)
    # macOS
    CMAKE_OPTS += -DCMAKE_OSX_DEPLOYMENT_TARGET=10.15
    # Check for Homebrew libsodium
    HOMEBREW_PREFIX := $(shell brew --prefix 2>/dev/null || echo "/opt/homebrew")
    ifneq ($(wildcard $(HOMEBREW_PREFIX)/opt/libsodium),)
        CMAKE_OPTS += -DSODIUM_ROOT=$(HOMEBREW_PREFIX)/opt/libsodium
    endif
else ifeq ($(UNAME_S),FreeBSD)
    # FreeBSD - libsodium typically in /usr/local
    CMAKE_OPTS += -DSODIUM_ROOT=/usr/local
else ifeq ($(UNAME_S),Linux)
    # Linux - check common locations
    ifneq ($(wildcard /usr/include/sodium.h),)
        # System-wide installation
    else ifneq ($(wildcard /usr/local/include/sodium.h),)
        CMAKE_OPTS += -DSODIUM_ROOT=/usr/local
    endif
endif

all: $(PRIV_DIR)/derp_sodium_nif.so

$(BUILD_DIR)/Makefile: CMakeLists.txt CMake/FindErlang.cmake CMake/FindSodium.cmake
	@mkdir -p $(BUILD_DIR)
	@mkdir -p $(PRIV_DIR)
	cd $(BUILD_DIR) && cmake .. \
		-G $(CMAKE_GENERATOR) \
		-DCMAKE_BUILD_TYPE=$(CMAKE_BUILD_TYPE) \
		$(CMAKE_OPTS)

$(PRIV_DIR)/derp_sodium_nif.so: $(BUILD_DIR)/Makefile derp_sodium_nif.c
	cd $(BUILD_DIR) && cmake --build . --config $(CMAKE_BUILD_TYPE)

clean:
	rm -rf $(BUILD_DIR)
	rm -f $(PRIV_DIR)/derp_sodium_nif.so
	rm -f $(PRIV_DIR)/derp_sodium_nif.dylib
	rm -f $(PRIV_DIR)/derp_sodium_nif.dll

rebuild: clean all

# Development helpers
.PHONY: debug
debug:
	$(MAKE) CMAKE_BUILD_TYPE=Debug

.PHONY: verbose
verbose:
	$(MAKE) CMAKE_OPTS="$(CMAKE_OPTS) -DCMAKE_VERBOSE_MAKEFILE=ON"

# Print configuration
.PHONY: info
info:
	@echo "OS: $(UNAME_S)"
	@echo "Arch: $(UNAME_M)"
	@echo "Build type: $(CMAKE_BUILD_TYPE)"
	@echo "CMake opts: $(CMAKE_OPTS)"
