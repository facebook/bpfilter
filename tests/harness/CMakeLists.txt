# SPDX-License-Identifier: GPL-2.0-only
# Copyright (c) 2023 Meta Platforms, Inc. and affiliates.

add_library(harness
    OBJECT
        ${CMAKE_CURRENT_SOURCE_DIR}/daemon.h    ${CMAKE_CURRENT_SOURCE_DIR}/daemon.c
        ${CMAKE_CURRENT_SOURCE_DIR}/filters.h   ${CMAKE_CURRENT_SOURCE_DIR}/filters.c
        ${CMAKE_CURRENT_SOURCE_DIR}/process.h   ${CMAKE_CURRENT_SOURCE_DIR}/process.c
        ${CMAKE_CURRENT_SOURCE_DIR}/sym.h       ${CMAKE_CURRENT_SOURCE_DIR}/sym.c
        ${CMAKE_CURRENT_SOURCE_DIR}/test.h      ${CMAKE_CURRENT_SOURCE_DIR}/test.c
)

target_include_directories(harness
    PUBLIC
        ${CMAKE_SOURCE_DIR}/tests
)

target_link_libraries(harness
    PUBLIC
        bf_global_flags
        core
)
