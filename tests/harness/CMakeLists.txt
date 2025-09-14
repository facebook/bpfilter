# SPDX-License-Identifier: GPL-2.0-only
# Copyright (c) 2023 Meta Platforms, Inc. and affiliates.

find_package(PkgConfig REQUIRED)
pkg_check_modules(bpf REQUIRED IMPORTED_TARGET libbpf)
pkg_check_modules(cmocka REQUIRED IMPORTED_TARGET cmocka)
pkg_check_modules(nl REQUIRED IMPORTED_TARGET libnl-3.0)

add_library(harness EXCLUDE_FROM_ALL
    STATIC
        ${CMAKE_CURRENT_SOURCE_DIR}/daemon.h    ${CMAKE_CURRENT_SOURCE_DIR}/daemon.c
        ${CMAKE_CURRENT_SOURCE_DIR}/filters.h   ${CMAKE_CURRENT_SOURCE_DIR}/filters.c
        ${CMAKE_CURRENT_SOURCE_DIR}/mock.h      ${CMAKE_CURRENT_SOURCE_DIR}/mock.c
        ${CMAKE_CURRENT_SOURCE_DIR}/process.h   ${CMAKE_CURRENT_SOURCE_DIR}/process.c
        ${CMAKE_CURRENT_SOURCE_DIR}/prog.h      ${CMAKE_CURRENT_SOURCE_DIR}/prog.c
        ${CMAKE_CURRENT_SOURCE_DIR}/test.h      ${CMAKE_CURRENT_SOURCE_DIR}/test.c
)

target_include_directories(harness
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}
    PUBLIC
        ${CMAKE_SOURCE_DIR}/tests
        ${CMAKE_SOURCE_DIR}/external/include
)

target_link_libraries(harness
    PUBLIC
        bf_global_flags
        libbpfilter
        PkgConfig::bpf
        PkgConfig::cmocka
        PkgConfig::nl
)
