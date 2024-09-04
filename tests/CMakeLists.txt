# SPDX-License-Identifier: GPL-2.0-only
# Copyright (c) 2023 Meta Platforms, Inc. and affiliates.

add_subdirectory(unit)
add_subdirectory(integration)
add_subdirectory(bpf)

get_target_property(core_srcs core SOURCES)
get_target_property(lib_srcs lib SOURCES)
get_target_property(daemon_srcs daemon SOURCES)

add_custom_target(lint
    COMMAND
        ${CLANG_TIDY_BIN}
            --config-file=${CMAKE_SOURCE_DIR}/.clang-tidy
            -p ${CMAKE_BINARY_DIR}
            ${core_srcs}
            ${lib_srcs}
            ${daemon_srcs}
            ${CMAKE_SOURCE_DIR}/src/cli/cli.c
    COMMENT "Run linter on source files"
)

add_custom_target(checkstyle
    COMMAND
        ${CLANG_FORMAT_BIN}
            --style=file:${CMAKE_SOURCE_DIR}/.clang-format
            --dry-run
            ${core_srcs}
            ${lib_srcs}
            ${daemon_srcs}
            ${CMAKE_SOURCE_DIR}/src/cli/cli.c
    COMMENT "Check source code formatting"
)

add_custom_target(test
    COMMAND $<TARGET_FILE:unit_tests>
    DEPENDS unit_tests
    COMMENT "Running tests"
)
