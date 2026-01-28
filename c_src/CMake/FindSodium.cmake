# FindSodium.cmake
# Find libsodium library and headers
#
# This module sets the following variables:
#   SODIUM_FOUND - True if libsodium was found
#   SODIUM_INCLUDE_DIR - Path to sodium.h
#   SODIUM_LIBRARY - Path to libsodium library
#   SODIUM_VERSION - Version string if available

# Platform-specific search paths
if(APPLE)
    # Homebrew paths for both Intel and Apple Silicon
    set(SODIUM_SEARCH_PATHS
        /opt/homebrew  # Apple Silicon
        /usr/local     # Intel
        /opt/local     # MacPorts
    )
elseif(CMAKE_SYSTEM_NAME STREQUAL "FreeBSD")
    set(SODIUM_SEARCH_PATHS
        /usr/local
        /usr
    )
else()
    # Linux
    set(SODIUM_SEARCH_PATHS
        /usr/local
        /usr
        /opt
    )
endif()

# Find sodium.h
find_path(SODIUM_INCLUDE_DIR sodium.h
    HINTS
        $ENV{SODIUM_ROOT}/include
        $ENV{SODIUM_INCLUDE_DIR}
    PATHS ${SODIUM_SEARCH_PATHS}
    PATH_SUFFIXES include
)

# Find libsodium library
find_library(SODIUM_LIBRARY
    NAMES sodium libsodium
    HINTS
        $ENV{SODIUM_ROOT}/lib
        $ENV{SODIUM_LIBRARY_DIR}
    PATHS ${SODIUM_SEARCH_PATHS}
    PATH_SUFFIXES lib lib64
)

# Try to get version from sodium/version.h
if(SODIUM_INCLUDE_DIR)
    file(STRINGS "${SODIUM_INCLUDE_DIR}/sodium/version.h" SODIUM_VERSION_LINE
        REGEX "^#define SODIUM_VERSION_STRING \"[^\"]*\"")
    if(SODIUM_VERSION_LINE)
        string(REGEX REPLACE "^#define SODIUM_VERSION_STRING \"([^\"]*)\"" "\\1"
            SODIUM_VERSION "${SODIUM_VERSION_LINE}")
    endif()
endif()

# Handle standard find_package arguments
include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(Sodium
    REQUIRED_VARS SODIUM_LIBRARY SODIUM_INCLUDE_DIR
    VERSION_VAR SODIUM_VERSION
)

# Mark variables as advanced
mark_as_advanced(
    SODIUM_INCLUDE_DIR
    SODIUM_LIBRARY
)

# Report what we found
if(SODIUM_FOUND)
    message(STATUS "Found libsodium ${SODIUM_VERSION}")
    message(STATUS "  Include dir: ${SODIUM_INCLUDE_DIR}")
    message(STATUS "  Library: ${SODIUM_LIBRARY}")
endif()
