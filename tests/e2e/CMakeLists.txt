# SPDX-License-Identifier: GPL-2.0-only
# Copyright (c) 2023 Meta Platforms, Inc. and affiliates.

find_package(Python3 COMPONENTS Interpreter)

add_custom_command(
    COMMAND
        ${CMAKE_COMMAND}
            -E make_directory
            ${CMAKE_CURRENT_BINARY_DIR}/include
    COMMAND
        Python3::Interpreter
            ${CMAKE_CURRENT_SOURCE_DIR}/genpkts.py
            --output ${CMAKE_CURRENT_BINARY_DIR}/include/packets.h
    DEPENDS
        ${CMAKE_CURRENT_SOURCE_DIR}/genpkts.py
	OUTPUT
        ${CMAKE_CURRENT_BINARY_DIR}/include/packets.h
	COMMENT "Generating the end-to-end test packets"
)

add_executable(e2e_bin EXCLUDE_FROM_ALL
    ${CMAKE_CURRENT_SOURCE_DIR}/main.c
    ${CMAKE_CURRENT_BINARY_DIR}/include/packets.h
)

target_include_directories(e2e_bin
    PRIVATE
        ${CMAKE_CURRENT_BINARY_DIR}/include
)

target_link_libraries(e2e_bin
    PRIVATE
        harness
        libbpfilter
)

add_custom_target(e2e
    COMMAND
        ${CMAKE_SOURCE_DIR}/tools/asroot
            $<TARGET_FILE:e2e_bin>
                --bpfilter $<TARGET_FILE:bpfilter>
    DEPENDS
        e2e_bin
        bpfilter
    COMMENT "Running end-to-end tests"
)
