# SPDX-License-Identifier: GPL-2.0
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

pkg_check_modules(bpf REQUIRED IMPORTED_TARGET libbpf)
pkg_check_modules(elf REQUIRED IMPORTED_TARGET libelf)
pkg_check_modules(cmocka REQUIRED IMPORTED_TARGET cmocka)

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

set(bpfilter_shared_srcs
    ${CMAKE_SOURCE_DIR}/shared/include/bpfilter/shared/generic.h ${CMAKE_SOURCE_DIR}/shared/src/generic.c
    ${CMAKE_SOURCE_DIR}/shared/include/bpfilter/shared/front.h ${CMAKE_SOURCE_DIR}/shared/src/front.c
    ${CMAKE_SOURCE_DIR}/shared/include/bpfilter/shared/helper.h
    ${CMAKE_SOURCE_DIR}/shared/include/bpfilter/shared/ipt.h
    ${CMAKE_SOURCE_DIR}/shared/include/bpfilter/shared/request.h ${CMAKE_SOURCE_DIR}/shared/src/request.c
    ${CMAKE_SOURCE_DIR}/shared/include/bpfilter/shared/response.h ${CMAKE_SOURCE_DIR}/shared/src/response.c
)

# Include headers to the list of sources, so dependencies are re-built
# on change.
set(bpfilter_daemon_srcs
    ${CMAKE_SOURCE_DIR}/src/opts.h ${CMAKE_SOURCE_DIR}/src/opts.c

    ${CMAKE_SOURCE_DIR}/src/core/bpf.h ${CMAKE_SOURCE_DIR}/src/core/bpf.c
    ${CMAKE_SOURCE_DIR}/src/core/btf.h ${CMAKE_SOURCE_DIR}/src/core/btf.c
    ${CMAKE_SOURCE_DIR}/src/core/counter.h
    ${CMAKE_SOURCE_DIR}/src/core/context.h ${CMAKE_SOURCE_DIR}/src/core/context.c
    ${CMAKE_SOURCE_DIR}/src/core/dump.h ${CMAKE_SOURCE_DIR}/src/core/dump.c
    ${CMAKE_SOURCE_DIR}/src/core/flavor.h ${CMAKE_SOURCE_DIR}/src/core/flavor.c
    ${CMAKE_SOURCE_DIR}/src/core/helper.h ${CMAKE_SOURCE_DIR}/src/core/helper.c
    ${CMAKE_SOURCE_DIR}/src/core/hook.h ${CMAKE_SOURCE_DIR}/src/core/hook.c
    ${CMAKE_SOURCE_DIR}/src/core/list.h ${CMAKE_SOURCE_DIR}/src/core/list.c
    ${CMAKE_SOURCE_DIR}/src/core/logger.h ${CMAKE_SOURCE_DIR}/src/core/logger.c
    ${CMAKE_SOURCE_DIR}/src/core/match.h ${CMAKE_SOURCE_DIR}/src/core/match.c
    ${CMAKE_SOURCE_DIR}/src/core/rule.h ${CMAKE_SOURCE_DIR}/src/core/rule.c
    ${CMAKE_SOURCE_DIR}/src/core/marsh.h ${CMAKE_SOURCE_DIR}/src/core/marsh.c
    ${CMAKE_SOURCE_DIR}/src/core/verdict.h ${CMAKE_SOURCE_DIR}/src/core/verdict.c

    ${CMAKE_SOURCE_DIR}/src/generator/codegen.h ${CMAKE_SOURCE_DIR}/src/generator/codegen.c
    ${CMAKE_SOURCE_DIR}/src/generator/dump.h ${CMAKE_SOURCE_DIR}/src/generator/dump.c
    ${CMAKE_SOURCE_DIR}/src/generator/nf.h ${CMAKE_SOURCE_DIR}/src/generator/nf.c
    ${CMAKE_SOURCE_DIR}/src/generator/program.h ${CMAKE_SOURCE_DIR}/src/generator/program.c
    ${CMAKE_SOURCE_DIR}/src/generator/reg.h
    ${CMAKE_SOURCE_DIR}/src/generator/stub.h ${CMAKE_SOURCE_DIR}/src/generator/stub.c
    ${CMAKE_SOURCE_DIR}/src/generator/fixup.h ${CMAKE_SOURCE_DIR}/src/generator/fixup.c
    ${CMAKE_SOURCE_DIR}/src/generator/tc.h ${CMAKE_SOURCE_DIR}/src/generator/tc.c

    ${CMAKE_SOURCE_DIR}/src/xlate/front.h ${CMAKE_SOURCE_DIR}/src/xlate/front.c
    ${CMAKE_SOURCE_DIR}/src/xlate/ipt/helpers.h
    ${CMAKE_SOURCE_DIR}/src/xlate/ipt/dump.h ${CMAKE_SOURCE_DIR}/src/xlate/ipt/dump.c
    ${CMAKE_SOURCE_DIR}/src/xlate/ipt/ipt.c
)

set(bpfilter_library_srcs
    ${CMAKE_SOURCE_DIR}/lib/include/bpfilter/bpfilter.h
    ${CMAKE_SOURCE_DIR}/lib/src/generic.c
    ${CMAKE_SOURCE_DIR}/lib/src/ipt.c
)

set(bpfilter_cflags
    -std=gnu17 -Wall -Wextra
)

set(bpfilter_ldflags
)

set(bpfilter_cflags_release
    -O2
)

set(bpfilter_ldflags_release
)

set(bpfilter_cflags_debug
    -O0 -g3 -ggdb -fno-omit-frame-pointer
    -fsanitize=address -fsanitize=undefined
)

set(bpfilter_ldflags_debug
    -fsanitize=address -fsanitize=undefined
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
add_subdirectory(lib)
add_subdirectory(tests)
add_subdirectory(doc)
