# SPDX-License-Identifier: GPL-2.0-only
# Copyright (c) 2023 Meta Platforms, Inc. and affiliates.

add_executable(e2e_bin
    ${CMAKE_CURRENT_SOURCE_DIR}/main.c
)

target_link_libraries(e2e_bin
    PRIVATE
        harness
        libbpfilter_a
)

add_custom_target(e2e
    COMMAND
        sudo
            $<TARGET_FILE:e2e_bin>
            --bpfilter $<TARGET_FILE:bpfilter>
    DEPENDS
        e2e_bin
        bpfilter
    COMMENT "Running end-to-end tests"
)
