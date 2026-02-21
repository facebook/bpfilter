# SPDX-License-Identifier: GPL-2.0-only
# Copyright (c) 2023 Meta Platforms, Inc. and affiliates.

find_program(RUN_CLANG_TIDY_BIN NAMES run-clang-tidy-18 run-clang-tidy REQUIRED)
find_program(CLANG_FORMAT_BIN NAMES clang-format-18 clang-format REQUIRED)

file(GLOB_RECURSE bf_srcs
    ${CMAKE_SOURCE_DIR}/src/core/*.h            ${CMAKE_SOURCE_DIR}/src/core/*.c
    ${CMAKE_SOURCE_DIR}/src/bpfilter/*.h        ${CMAKE_SOURCE_DIR}/src/bpfilter/*.c
    ${CMAKE_SOURCE_DIR}/src/libbpfilter/*.h     ${CMAKE_SOURCE_DIR}/src/libbpfilter/*.c
    ${CMAKE_SOURCE_DIR}/src/bfcli/*.h           ${CMAKE_SOURCE_DIR}/src/bfcli/*.c
)
list(FILTER bf_srcs EXCLUDE REGEX "src/bpfilter/xlate/nft/nfmsg.*")
list(FILTER bf_srcs EXCLUDE REGEX "src/bpfilter/xlate/nft/nfgroup.*")

file(GLOB_RECURSE bf_test_srcs
    ${CMAKE_SOURCE_DIR}/tests/*.h               ${CMAKE_SOURCE_DIR}/tests/*.c
)
set(bf_all_srcs ${bf_srcs} ${bf_test_srcs})

add_test(NAME "check.lint"
    COMMAND
        ${RUN_CLANG_TIDY_BIN}
            -config-file=${CMAKE_SOURCE_DIR}/.clang-tidy
            -p ${CMAKE_BINARY_DIR}
            -extra-arg=-fno-caret-diagnostics
            -j ${CPU_COUNT}
            ${bf_srcs}
)

add_test(NAME "check.iwyu"
    COMMAND
        /usr/bin/iwyu_tool.py
            -p ${CMAKE_BINARY_DIR}
            ${CMAKE_SOURCE_DIR}/src/bpfilter/cgen/program.c
)

set_tests_properties("check.lint" PROPERTIES
    LABELS "check"
)

add_test(NAME "check.checkstyle"
    COMMAND
        ${CLANG_FORMAT_BIN}
            --style=file:${CMAKE_SOURCE_DIR}/.clang-format
            --dry-run
            --Werror
            ${bf_all_srcs}
)

set_tests_properties("check.checkstyle" PROPERTIES
    LABELS "check"
)

add_custom_target(fixstyle
    COMMAND
        ${CLANG_FORMAT_BIN}
            --style=file:${CMAKE_SOURCE_DIR}/.clang-format
            -i
            ${bf_all_srcs}
    COMMENT "Fixing style for all the source files"
)

add_custom_target(check
    COMMAND ${CMAKE_CTEST_COMMAND} --output-on-failure -L check
    COMMENT "Running check tests"
)