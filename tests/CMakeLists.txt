# SPDX-License-Identifier: GPL-2.0-only
# Copyright (c) 2023 Meta Platforms, Inc. and affiliates.

add_subdirectory(unit)
add_subdirectory(end_to_end)

add_custom_target(lint
    COMMAND ${CLANG_TIDY_BIN} --config-file=${CMAKE_SOURCE_DIR}/.clang-tidy -p ${CMAKE_BINARY_DIR} ${bpfilter_shared_srcs} ${bpfilter_daemon_srcs} ${bpfilter_library_srcs}
    COMMENT "Run linter on source files"
)

add_custom_target(checkstyle
    COMMAND ${CLANG_FORMAT_BIN} --style=file:${CMAKE_SOURCE_DIR}/.clang-format --dry-run ${bpfilter_shared_srcs} ${bpfilter_daemon_srcs} ${bpfilter_library_srcs}
    COMMENT "Check source code formatting"
)
