# SPDX-License-Identifier: GPL-2.0-only
# Copyright (c) 2023 Meta Platforms, Inc. and affiliates.

find_package(PkgConfig REQUIRED)
pkg_check_modules(bpf REQUIRED IMPORTED_TARGET libbpf)

set(core_srcs
    ${CMAKE_BINARY_DIR}/include/version.h
    ${CMAKE_CURRENT_SOURCE_DIR}/bpf.h              ${CMAKE_CURRENT_SOURCE_DIR}/bpf.c
    ${CMAKE_CURRENT_SOURCE_DIR}/btf.h              ${CMAKE_CURRENT_SOURCE_DIR}/btf.c
    ${CMAKE_CURRENT_SOURCE_DIR}/chain.h            ${CMAKE_CURRENT_SOURCE_DIR}/chain.c
    ${CMAKE_CURRENT_SOURCE_DIR}/counter.h          ${CMAKE_CURRENT_SOURCE_DIR}/counter.c
    ${CMAKE_CURRENT_SOURCE_DIR}/dump.h             ${CMAKE_CURRENT_SOURCE_DIR}/dump.c
    ${CMAKE_CURRENT_SOURCE_DIR}/flavor.h           ${CMAKE_CURRENT_SOURCE_DIR}/flavor.c
    ${CMAKE_CURRENT_SOURCE_DIR}/front.h            ${CMAKE_CURRENT_SOURCE_DIR}/front.c
    ${CMAKE_CURRENT_SOURCE_DIR}/helper.h           ${CMAKE_CURRENT_SOURCE_DIR}/helper.c
    ${CMAKE_CURRENT_SOURCE_DIR}/hook.h             ${CMAKE_CURRENT_SOURCE_DIR}/hook.c
    ${CMAKE_CURRENT_SOURCE_DIR}/if.h               ${CMAKE_CURRENT_SOURCE_DIR}/if.c
    ${CMAKE_CURRENT_SOURCE_DIR}/io.h               ${CMAKE_CURRENT_SOURCE_DIR}/io.c
    ${CMAKE_CURRENT_SOURCE_DIR}/list.h             ${CMAKE_CURRENT_SOURCE_DIR}/list.c
    ${CMAKE_CURRENT_SOURCE_DIR}/logger.h           ${CMAKE_CURRENT_SOURCE_DIR}/logger.c
    ${CMAKE_CURRENT_SOURCE_DIR}/marsh.h            ${CMAKE_CURRENT_SOURCE_DIR}/marsh.c
    ${CMAKE_CURRENT_SOURCE_DIR}/matcher.h          ${CMAKE_CURRENT_SOURCE_DIR}/matcher.c
    ${CMAKE_CURRENT_SOURCE_DIR}/ns.h               ${CMAKE_CURRENT_SOURCE_DIR}/ns.c
    ${CMAKE_CURRENT_SOURCE_DIR}/opts.h             ${CMAKE_CURRENT_SOURCE_DIR}/opts.c
    ${CMAKE_CURRENT_SOURCE_DIR}/request.h          ${CMAKE_CURRENT_SOURCE_DIR}/request.c
    ${CMAKE_CURRENT_SOURCE_DIR}/response.h         ${CMAKE_CURRENT_SOURCE_DIR}/response.c
    ${CMAKE_CURRENT_SOURCE_DIR}/rule.h             ${CMAKE_CURRENT_SOURCE_DIR}/rule.c
    ${CMAKE_CURRENT_SOURCE_DIR}/set.h              ${CMAKE_CURRENT_SOURCE_DIR}/set.c
    ${CMAKE_CURRENT_SOURCE_DIR}/verdict.h          ${CMAKE_CURRENT_SOURCE_DIR}/verdict.c
)

add_library(core
    OBJECT
        ${core_srcs}
)

target_include_directories(core
    PUBLIC
        ${CMAKE_SOURCE_DIR}/src
        ${CMAKE_BINARY_DIR}/include
)

target_link_libraries(core
    PUBLIC
        bf_global_flags
        PkgConfig::bpf
)
