# FindErlang.cmake
# Find Erlang/OTP installation and set up include paths
#
# This module sets the following variables:
#   ERLANG_FOUND - True if Erlang was found
#   ERLANG_EI_INCLUDE_DIR - Path to erl_nif.h
#   ERLANG_EI_LIBRARY_DIR - Path to Erlang libraries
#   ERLANG_ERTS_VERSION - ERTS version string

# Find erl executable
find_program(ERLANG_ERL erl
    HINTS
        $ENV{ERL_TOP}/bin
        /usr/local/bin
        /opt/homebrew/bin
        /usr/bin
)

if(NOT ERLANG_ERL)
    message(FATAL_ERROR "Could not find 'erl' executable")
endif()

# Get ERTS root directory
execute_process(
    COMMAND ${ERLANG_ERL} -noshell -eval "io:format(\"~s\", [code:root_dir()])" -s init stop
    OUTPUT_VARIABLE ERLANG_ROOT_DIR
    OUTPUT_STRIP_TRAILING_WHITESPACE
    ERROR_QUIET
)

if(NOT ERLANG_ROOT_DIR)
    message(FATAL_ERROR "Could not determine Erlang root directory")
endif()

# Get ERTS version
execute_process(
    COMMAND ${ERLANG_ERL} -noshell -eval "io:format(\"~s\", [erlang:system_info(version)])" -s init stop
    OUTPUT_VARIABLE ERLANG_ERTS_VERSION
    OUTPUT_STRIP_TRAILING_WHITESPACE
    ERROR_QUIET
)

# Find erl_nif.h include directory
# First try the standard ERTS include path
set(ERTS_INCLUDE_SEARCH_PATHS
    ${ERLANG_ROOT_DIR}/erts-${ERLANG_ERTS_VERSION}/include
    ${ERLANG_ROOT_DIR}/usr/include
)

# Also search versioned erts directories
file(GLOB ERTS_DIRS "${ERLANG_ROOT_DIR}/erts-*")
foreach(ERTS_DIR ${ERTS_DIRS})
    list(APPEND ERTS_INCLUDE_SEARCH_PATHS "${ERTS_DIR}/include")
endforeach()

find_path(ERLANG_EI_INCLUDE_DIR erl_nif.h
    PATHS ${ERTS_INCLUDE_SEARCH_PATHS}
    NO_DEFAULT_PATH
)

# Fallback: try to get it from erts include path
if(NOT ERLANG_EI_INCLUDE_DIR)
    execute_process(
        COMMAND ${ERLANG_ERL} -noshell -eval "io:format(\"~s\", [code:lib_dir(erts, include)])" -s init stop
        OUTPUT_VARIABLE ERLANG_EI_INCLUDE_DIR
        OUTPUT_STRIP_TRAILING_WHITESPACE
        ERROR_QUIET
    )
endif()

# Find library directory (for ei library if needed)
find_path(ERLANG_EI_LIBRARY_DIR liberl_interface.a libei.a
    PATHS
        ${ERLANG_ROOT_DIR}/usr/lib
        ${ERLANG_ROOT_DIR}/lib
    NO_DEFAULT_PATH
)

# Handle standard find_package arguments
include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(Erlang
    REQUIRED_VARS ERLANG_EI_INCLUDE_DIR
    VERSION_VAR ERLANG_ERTS_VERSION
)

# Mark variables as advanced
mark_as_advanced(
    ERLANG_ERL
    ERLANG_ROOT_DIR
    ERLANG_EI_INCLUDE_DIR
    ERLANG_EI_LIBRARY_DIR
    ERLANG_ERTS_VERSION
)

# Report what we found
if(ERLANG_FOUND)
    message(STATUS "Found Erlang ERTS ${ERLANG_ERTS_VERSION}")
    message(STATUS "  Include dir: ${ERLANG_EI_INCLUDE_DIR}")
endif()
