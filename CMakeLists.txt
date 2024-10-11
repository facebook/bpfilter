# SPDX-License-Identifier: GPL-2.0-only
# Copyright (c) 2023 Meta Platforms, Inc. and affiliates.

cmake_minimum_required(VERSION 3.20)

project(bpfilter
    VERSION 0.0.1
    DESCRIPTION "BPF-based packet filtering framework"
    LANGUAGES C CXX
)

include(GNUInstallDirs)

find_package(Doxygen REQUIRED)
find_package(PkgConfig REQUIRED)
find_package(FLEX REQUIRED)
find_package(BISON REQUIRED)

pkg_check_modules(bpf REQUIRED IMPORTED_TARGET libbpf)
pkg_check_modules(elf REQUIRED IMPORTED_TARGET libelf)
pkg_check_modules(cmocka REQUIRED IMPORTED_TARGET cmocka)
pkg_check_modules(nl REQUIRED IMPORTED_TARGET libnl-3.0)

# Required to get CMake to pass PIE flags to the compiler/linker
include(CheckPIESupported)
check_pie_supported()
if(NOT CMAKE_C_LINK_PIE_SUPPORTED)
  message(WARNING "PIE is not supported at link time: ${output}.\n"
                  "PIE link options will not be passed to linker.\n"
                  "If PIE is enabled by default, test auto discovery might fail.")
endif()

find_program(SPHINX_BIN sphinx-build REQUIRED)
find_program(LCOV_BIN lcov REQUIRED)
find_program(GENHTML_BIN genhtml REQUIRED)
find_program(CLANG_TIDY_BIN clang-tidy REQUIRED)
find_program(CLANG_FORMAT_BIN clang-format REQUIRED)
find_program(CLANG_BIN clang REQUIRED)
find_program(BPFTOOL_BIN bpftool REQUIRED)
find_program(JQ_BIN jq REQUIRED)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

set(CMAKE_C_FLAGS_RELEASE "")       # No NDEBUG in release mode
set(CMAKE_CXX_FLAGS_RELEASE "")     # No NDEBUG in release mode

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
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/output/bin)
configure_file(
    ${CMAKE_SOURCE_DIR}/src/libbpfilter/bpfilter.h
    ${CMAKE_BINARY_DIR}/output/include/bpfilter/bpfilter.h
)
configure_file(
    ${CMAKE_SOURCE_DIR}/src/libbpfilter/bpfilter.pc.in
    ${CMAKE_BINARY_DIR}/output/lib/pkgconfig/bpfilter.pc
)

add_library(bf_global_flags INTERFACE)
target_compile_options(bf_global_flags
    INTERFACE
        -std=gnu17 -Wall -Wextra
        $<$<CONFIG:debug>:-O0 -g3 -ggdb -fno-omit-frame-pointer -fsanitize=address -fsanitize=undefined>
        $<$<CONFIG:release>:-O2>
)
target_link_options(bf_global_flags
    INTERFACE
        $<$<CONFIG:debug>:-fsanitize=address -fsanitize=undefined>
)

add_subdirectory(src)
add_subdirectory(tests)
add_subdirectory(doc)

install(TARGETS bpfilter libbpfilter_a libbpfilter_so bfcli)

install(
    FILES ${CMAKE_SOURCE_DIR}/src/libbpfilter/bpfilter.h
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/bpfilter
)

install(
    FILES ${CMAKE_BINARY_DIR}/output/lib/pkgconfig/bpfilter.pc
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/pkgconfig
)
