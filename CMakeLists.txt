# SPDX-License-Identifier: GPL-2.0-only
# Copyright (c) 2023 Meta Platforms, Inc. and affiliates.

cmake_minimum_required(VERSION 3.20)

if (NOT DEFINED DEFAULT_PROJECT_VERSION)
    set(DEFAULT_PROJECT_VERSION 0.0.0)
endif ()

project(bpfilter
    VERSION ${DEFAULT_PROJECT_VERSION}
    DESCRIPTION "BPF-based packet filtering framework"
    LANGUAGES C CXX
)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/tools/cmake")

include(GitVersion)
get_version_from_git()
message(NOTICE "bpfilter version ${PROJECT_VERSION}${PROJECT_VERSION_SUFFIX}")

# Store the number of CPUs in a variable, can be used to parallelize commands
include(ProcessorCount)
ProcessorCount(CPU_COUNT)
if(CPU_COUNT EQUAL 0)
    set(CPU_COUNT 1)
endif()

include(GNUInstallDirs)

option(NO_DOCS "Disable documentation generation" 0)
option(NO_TESTS "Disable unit, end-to-end, and integration tests" 0)
option(NO_CHECKS "Disable the check target (clang-tidy and clang-format" 0)
option(NO_BENCHMARKS "Disable the benchmark" 0)
option(WITH_COVERAGE "Build with code coverage support. Disabled by default" 0)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

set(BF_CONTACT "Quentin Deslandes <qde@naccy.de>")

if (NOT CMAKE_BUILD_TYPE)
  message(STATUS "Setting build type to 'release' as none was specified.")
  set(CMAKE_BUILD_TYPE "release" CACHE STRING "Choose the type of build." FORCE)
else ()
    set(BF_VALID_BUILD_TYPE "debug;release")
    string(TOLOWER ${CMAKE_BUILD_TYPE} BF_LOWER_BUILD_TYPE)
    list(FIND BF_VALID_BUILD_TYPE ${BF_LOWER_BUILD_TYPE} BF_BUILD_TYPE_INDEX)
    if (${BF_BUILD_TYPE_INDEX} EQUAL -1)
        message(FATAL_ERROR "CMAKE_BUILD_TYPE must be either 'debug' or 'release' (default), not '${CMAKE_BUILD_TYPE}'")
    endif ()
endif ()

# Ensure artefacts are moved to a common directory
file(MAKE_DIRECTORY ${CMAKE_BINARY_DIR}/output/include/bpfilter)
file(MAKE_DIRECTORY ${CMAKE_BINARY_DIR}/output/lib/pkgconfig)
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/output/lib)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/output/lib)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/output/sbin)

add_library(bf_global_flags INTERFACE)
target_compile_options(bf_global_flags
    INTERFACE
        -std=gnu17 -Wall -Wextra -fPIC
        $<$<BOOL:${WITH_COVERAGE}>:-fprofile-arcs -ftest-coverage>
        $<$<CONFIG:debug>:-O0 -g3 -ggdb -fno-omit-frame-pointer -fsanitize=address -fsanitize=undefined>
        $<$<CONFIG:release>:-O2>
)
target_include_directories(bf_global_flags
    INTERFACE
        ${CMAKE_SOURCE_DIR}/src/external
)
target_link_options(bf_global_flags
    INTERFACE
        $<$<BOOL:${WITH_COVERAGE}>:-fprofile-arcs -ftest-coverage>
        $<$<CONFIG:debug>:-fsanitize=address -fsanitize=undefined>
)

add_library(bf_global_flags_cxx INTERFACE)
target_compile_options(bf_global_flags_cxx
    INTERFACE
        -std=c++20 -Wall -Wextra -fPIC
        $<$<CONFIG:debug>:-O0 -g3 -ggdb -fno-omit-frame-pointer -fsanitize=address -fsanitize=undefined>
        $<$<CONFIG:release>:-O2>
)
target_link_options(bf_global_flags_cxx
    INTERFACE
        $<$<CONFIG:debug>:-fsanitize=address -fsanitize=undefined>
)

add_subdirectory(src/libbpfilter)
add_subdirectory(src/bfcli)
add_subdirectory(src/bpfilter)

if (NOT ${NO_DOCS})
    add_subdirectory(doc)
endif ()

if (NOT ${NO_TESTS})
    set(CMAKE_CTEST_ARGUMENTS "--output-on-failure")
    enable_testing()
    add_subdirectory(tests)
endif ()

if (NOT ${NO_BENCHMARKS})
    add_subdirectory(tools/benchmarks)
endif ()
