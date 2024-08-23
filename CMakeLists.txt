# SPDX-License-Identifier: GPL-2.0-only
# Copyright (c) 2023 Meta Platforms, Inc. and affiliates.

cmake_minimum_required(VERSION 3.20)

project(bpfilter
    VERSION 0.0.1
    DESCRIPTION "BPF-based packet filtering framework"
    LANGUAGES C
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
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/output/lib)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/output/lib)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/output/bin)
configure_file(
    ${CMAKE_SOURCE_DIR}/src/lib/bpfilter.h
    ${CMAKE_BINARY_DIR}/output/include/bpfilter/bpfilter.h
)

set(bf_cflags
    -std=gnu17 -Wall -Wextra
    $<$<CONFIG:debug>:-O0 -g3 -ggdb -fno-omit-frame-pointer -fsanitize=address -fsanitize=undefined>
    $<$<CONFIG:release>:-O2>
)

set(bf_ldflags
    $<$<CONFIG:debug>:-fsanitize=address -fsanitize=undefined>
)

configure_file(resources/bpfilter.pc.in ${CMAKE_BINARY_DIR}/bpfilter.pc.in @ONLY)
file(
  GENERATE
  OUTPUT ${CMAKE_BINARY_DIR}/bpfilter.pc
  INPUT ${CMAKE_BINARY_DIR}/bpfilter.pc.in
)

install(
    FILES ${CMAKE_BINARY_DIR}/bpfilter.pc
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/pkgconfig
)

add_subdirectory(src)
add_subdirectory(tests)
add_subdirectory(doc)
