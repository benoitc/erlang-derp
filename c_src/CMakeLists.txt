cmake_minimum_required(VERSION 3.14)
project(derp_nifs C CXX)

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

if(WIN32)
    # Windows - use .dll extension and link against WinSock
    set(CMAKE_SHARED_LIBRARY_SUFFIX ".dll")
    set(CMAKE_SHARED_MODULE_SUFFIX ".dll")
endif()

# Compiler flags
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wextra -Wno-unused-parameter")
    set(CMAKE_C_FLAGS_RELEASE "-O3 -DNDEBUG")
    set(CMAKE_C_FLAGS_DEBUG "-g -O0")
elseif(MSVC)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} /W3")
    set(CMAKE_C_FLAGS_RELEASE "/O2 /DNDEBUG")
    set(CMAKE_C_FLAGS_DEBUG "/Od /Zi")
endif()

# BoringSSL
set(BORINGSSL_DIR "${CMAKE_SOURCE_DIR}/boringssl")
if(EXISTS "${BORINGSSL_DIR}/CMakeLists.txt")
    # Disable BoringSSL tests and shared libs
    set(BUILD_SHARED_LIBS OFF CACHE BOOL "" FORCE)
    set(BUILD_TESTING OFF CACHE BOOL "" FORCE)

    # BoringSSL needs C++ for some components
    if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
        set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wno-unused-parameter")
    elseif(MSVC)
        set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} /W3 /wd4100")
    endif()

    add_subdirectory(${BORINGSSL_DIR} ${CMAKE_BINARY_DIR}/boringssl EXCLUDE_FROM_ALL)
    set(BORINGSSL_FOUND TRUE)
else()
    message(WARNING "BoringSSL not found at ${BORINGSSL_DIR}, skipping derp_tls_nif")
    set(BORINGSSL_FOUND FALSE)
endif()

# ==================================================================
# derp_sodium_nif
# ==================================================================

add_library(derp_sodium_nif MODULE
    derp_sodium_nif.c
)

target_include_directories(derp_sodium_nif PRIVATE
    ${ERLANG_EI_INCLUDE_DIR}
    ${SODIUM_INCLUDE_DIR}
)

target_link_libraries(derp_sodium_nif
    ${SODIUM_LIBRARY}
)

# Platform-specific linker flags for sodium NIF
if(APPLE)
    set_target_properties(derp_sodium_nif PROPERTIES
        LINK_FLAGS "-bundle -flat_namespace -undefined suppress"
    )
elseif(WIN32)
    # Windows - no special flags needed for MSVC
    set_target_properties(derp_sodium_nif PROPERTIES
        WINDOWS_EXPORT_ALL_SYMBOLS ON
    )
elseif(UNIX)
    set_target_properties(derp_sodium_nif PROPERTIES
        LINK_FLAGS "-shared"
    )
endif()

set_target_properties(derp_sodium_nif PROPERTIES
    PREFIX ""
    OUTPUT_NAME "derp_sodium_nif"
    LIBRARY_OUTPUT_DIRECTORY "${CMAKE_SOURCE_DIR}/../priv"
)

# ==================================================================
# derp_tls_nif (BoringSSL-based TLS with enif_select)
# ==================================================================

if(BORINGSSL_FOUND)
    add_library(derp_tls_nif MODULE
        derp_tls_nif.c
    )

    target_include_directories(derp_tls_nif PRIVATE
        ${ERLANG_EI_INCLUDE_DIR}
        ${BORINGSSL_DIR}/include
    )

    target_link_libraries(derp_tls_nif
        ssl
        crypto
    )

    if(WIN32)
        target_link_libraries(derp_tls_nif ws2_32)
    endif()

    # Platform-specific linker flags for TLS NIF
    if(APPLE)
        set_target_properties(derp_tls_nif PROPERTIES
            LINK_FLAGS "-bundle -flat_namespace -undefined suppress"
        )
    elseif(WIN32)
        # Windows - no special flags needed for MSVC
        set_target_properties(derp_tls_nif PROPERTIES
            WINDOWS_EXPORT_ALL_SYMBOLS ON
        )
    elseif(UNIX)
        set_target_properties(derp_tls_nif PROPERTIES
            LINK_FLAGS "-shared"
        )
    endif()

    set_target_properties(derp_tls_nif PROPERTIES
        PREFIX ""
        OUTPUT_NAME "derp_tls_nif"
        LIBRARY_OUTPUT_DIRECTORY "${CMAKE_SOURCE_DIR}/../priv"
    )
endif()

# Install targets
install(TARGETS derp_sodium_nif
    LIBRARY DESTINATION priv
)

if(BORINGSSL_FOUND)
    install(TARGETS derp_tls_nif
        LIBRARY DESTINATION priv
    )
endif()
