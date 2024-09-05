# SPDX-License-Identifier: GPL-2.0-only
# Copyright (c) 2023 Meta Platforms, Inc. and affiliates.

add_subdirectory(unit)
add_subdirectory(integration)
add_subdirectory(bpf)

# It's OK to use GLOB_RECURSE here, as it's not the main target for the source
# files but a secondary one.
file(GLOB_RECURSE bf_srcs
	${CMAKE_SOURCE_DIR}/src/*.c
	${CMAKE_SOURCE_DIR}/src/*.h
)

add_custom_target(lint
    COMMAND
        ${CLANG_TIDY_BIN}
            --config-file=${CMAKE_SOURCE_DIR}/.clang-tidy
            -p ${CMAKE_BINARY_DIR}
            ${bf_srcs}
    COMMENT "Run linter on source files"
)

add_custom_target(checkstyle
    COMMAND
        ${CLANG_FORMAT_BIN}
            --style=file:${CMAKE_SOURCE_DIR}/.clang-format
            --dry-run
            ${bf_srcs}
    COMMENT "Check source code formatting"
)

add_custom_target(test
    COMMAND $<TARGET_FILE:unit_tests>
    DEPENDS unit_tests
    COMMENT "Running tests"
)
