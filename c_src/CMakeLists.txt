cmake_minimum_required(VERSION 3.14)
project(derp_sodium_nif C)

# Set module path for custom find modules
set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_SOURCE_DIR}/CMake")

# Find Erlang
find_package(Erlang REQUIRED)

# Find libsodium
find_package(Sodium REQUIRED)

# Platform-specific settings
if(APPLE)
    set(CMAKE_SHARED_LIBRARY_SUFFIX ".so")
    set(CMAKE_SHARED_MODULE_SUFFIX ".so")
    # Universal binary support for macOS (arm64 + x86_64)
    if(NOT DEFINED CMAKE_OSX_ARCHITECTURES)
        execute_process(
            COMMAND uname -m
            OUTPUT_VARIABLE HOST_ARCH
            OUTPUT_STRIP_TRAILING_WHITESPACE
        )
        set(CMAKE_OSX_ARCHITECTURES ${HOST_ARCH})
    endif()
    # Minimum macOS version
    set(CMAKE_OSX_DEPLOYMENT_TARGET "10.15" CACHE STRING "Minimum macOS version")
endif()

if(UNIX AND NOT APPLE)
    # Linux and FreeBSD
    set(CMAKE_POSITION_INDEPENDENT_CODE ON)
endif()

# Compiler flags
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wextra -Wno-unused-parameter")
    set(CMAKE_C_FLAGS_RELEASE "-O3 -DNDEBUG")
    set(CMAKE_C_FLAGS_DEBUG "-g -O0")
endif()

# NIF shared library
add_library(derp_sodium_nif MODULE
    derp_sodium_nif.c
)

# Include directories
target_include_directories(derp_sodium_nif PRIVATE
    ${ERLANG_EI_INCLUDE_DIR}
    ${SODIUM_INCLUDE_DIR}
)

# Link libraries
target_link_libraries(derp_sodium_nif
    ${SODIUM_LIBRARY}
)

# Platform-specific linker flags
if(APPLE)
    set_target_properties(derp_sodium_nif PROPERTIES
        LINK_FLAGS "-bundle -flat_namespace -undefined suppress"
    )
elseif(UNIX)
    set_target_properties(derp_sodium_nif PROPERTIES
        LINK_FLAGS "-shared"
    )
endif()

# Output to priv directory
set_target_properties(derp_sodium_nif PROPERTIES
    PREFIX ""
    OUTPUT_NAME "derp_sodium_nif"
    LIBRARY_OUTPUT_DIRECTORY "${CMAKE_SOURCE_DIR}/../priv"
)

# Install target
install(TARGETS derp_sodium_nif
    LIBRARY DESTINATION priv
)
