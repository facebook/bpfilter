# SPDX-License-Identifier: GPL-2.0
# Copyright (c) 2023 Meta Platforms, Inc. and affiliates.

cmake_minimum_required(VERSION 3.26)

project(bpfilter
    VERSION 0.0.1
    DESCRIPTION "BPF-based packet filtering framework"
    LANGUAGES C CXX
)

find_package(GTest REQUIRED)
find_package(Doxygen REQUIRED)

find_program(SPHINX_BIN sphinx-build REQUIRED)
find_program(LCOV_BIN lcov REQUIRED)
find_program(GENHTML_BIN genhtml REQUIRED)

include(GoogleTest)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

set(CMAKE_C_FLAGS_RELEASE "")       # No NDEBUG in release mode
set(CMAKE_CXX_FLAGS_RELEASE "")     # No NDEBUG in release mode

if (NOT CMAKE_BUILD_TYPE)
  message(STATUS "Setting build type to 'Release' as none was specified.")
  set(CMAKE_BUILD_TYPE "Release" CACHE STRING "Choose the type of build." FORCE)
else ()
    set(BF_VALID_BUILD_TYPE "debug;release")
    string(TOLOWER ${CMAKE_BUILD_TYPE} BF_LOWER_BUILD_TYPE)
    list(FIND BF_VALID_BUILD_TYPE ${BF_LOWER_BUILD_TYPE} BF_BUILD_TYPE_INDEX)
    if (${BF_BUILD_TYPE_INDEX} EQUAL -1)
        message(FATAL_ERROR "CMAKE_BUILD_TYPE must be either 'Debug' or 'Release' (default), not '${CMAKE_BUILD_TYPE}'")
    endif ()
endif ()

set(bpfilter_shared_srcs
    ${CMAKE_SOURCE_DIR}/shared/include/bpfilter/shared/mem.h
    ${CMAKE_SOURCE_DIR}/shared/include/bpfilter/shared/request.h
    ${CMAKE_SOURCE_DIR}/shared/src/request.c
    ${CMAKE_SOURCE_DIR}/shared/include/bpfilter/shared/response.h
    ${CMAKE_SOURCE_DIR}/shared/src/response.c
)

# Include headers to the list of sources, so dependencies are re-built
# on change.
set(bpfilter_daemon_srcs
    ${CMAKE_SOURCE_DIR}/src/core/chain.c ${CMAKE_SOURCE_DIR}/src/core/chain.h
    ${CMAKE_SOURCE_DIR}/src/core/dump.c ${CMAKE_SOURCE_DIR}/src/core/dump.h
    ${CMAKE_SOURCE_DIR}/src/core/list.c ${CMAKE_SOURCE_DIR}/src/core/list.h
    ${CMAKE_SOURCE_DIR}/src/core/match.c ${CMAKE_SOURCE_DIR}/src/core/match.h
    ${CMAKE_SOURCE_DIR}/src/core/rule.c ${CMAKE_SOURCE_DIR}/src/core/rule.h
    ${CMAKE_SOURCE_DIR}/src/core/string.h
    ${CMAKE_SOURCE_DIR}/src/core/table.c ${CMAKE_SOURCE_DIR}/src/core/table.h
    ${CMAKE_SOURCE_DIR}/src/core/target.c ${CMAKE_SOURCE_DIR}/src/core/target.h
)

set(bpfilter_library_srcs
    ${CMAKE_SOURCE_DIR}/lib/include/bpfilter/bpfilter.h
    ${CMAKE_SOURCE_DIR}/lib/src/ipt.c
)

set(bpfilter_cflags
    -Wall -Wextra
)

set(bpfilter_cflags_release
    -O2
)

set(bpfilter_cflags_debug
    -O0 -g3 -ggdb -fno-omit-frame-pointer
)

add_subdirectory(src)
add_subdirectory(lib)
add_subdirectory(tests)
add_subdirectory(doc)
