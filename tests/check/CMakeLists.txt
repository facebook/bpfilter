# SPDX-License-Identifier: GPL-2.0-only
# Copyright (c) 2023 Meta Platforms, Inc. and affiliates.

find_program(CLANG_TIDY_BIN NAMES clang-tidy-18 clang-tidy REQUIRED)
find_program(CLANG_FORMAT_BIN NAMES clang-format-18 clang-format REQUIRED)
find_program(SHELLCHECK_BIN NAMES shellcheck REQUIRED)
find_program(IWYU_TOOL_BIN NAMES iwyu_tool.py REQUIRED)

file(GLOB_RECURSE bf_srcs
    ${CMAKE_SOURCE_DIR}/src/core/*.h            ${CMAKE_SOURCE_DIR}/src/core/*.c
    ${CMAKE_SOURCE_DIR}/src/bpfilter/*.h        ${CMAKE_SOURCE_DIR}/src/bpfilter/*.c
    ${CMAKE_SOURCE_DIR}/src/libbpfilter/*.h     ${CMAKE_SOURCE_DIR}/src/libbpfilter/*.c
    ${CMAKE_SOURCE_DIR}/src/bfcli/*.h           ${CMAKE_SOURCE_DIR}/src/bfcli/*.c
    # ${CMAKE_SOURCE_DIR}/tests/*.h               ${CMAKE_SOURCE_DIR}/tests/*.c
)
list(FILTER bf_srcs EXCLUDE REGEX "src/bpfilter/xlate/nft/nfmsg.*")
list(FILTER bf_srcs EXCLUDE REGEX "src/bpfilter/xlate/nft/nfgroup.*")

file(GLOB_RECURSE bf_scripts
    ${CMAKE_SOURCE_DIR}/tests/*.sh
)

add_test(NAME "check.lint"
    COMMAND
        ${CLANG_TIDY_BIN}
            --quiet
            --config-file=${CMAKE_SOURCE_DIR}/.clang-tidy
            -p ${CMAKE_BINARY_DIR}
            --extra-arg=-fno-caret-diagnostics
            ${bf_srcs}
)

set_tests_properties("check.lint" PROPERTIES
    LABELS "check"
)

add_test(NAME "check.checkstyle"
    COMMAND
        ${CLANG_FORMAT_BIN}
            --style=file:${CMAKE_SOURCE_DIR}/.clang-format
            --dry-run
            ${bf_srcs}
)

set_tests_properties("check.checkstyle" PROPERTIES
    LABELS "check"
)

add_test(NAME "check.shellcheck"
    COMMAND
        ${SHELLCHECK_BIN}
            --shell=bash
            -x
            --source-path=SCRIPTDIR
            ${bf_scripts}
)

set_tests_properties("check.shellcheck" PROPERTIES
    LABELS "check"
)

add_test(NAME "check.iwyu"
    COMMAND
        ${IWYU_TOOL_BIN}
            -p ${CMAKE_BINARY_DIR}
            -e ${CMAKE_SOURCE_DIR}/src/external
            -e ${CMAKE_BINARY_DIR}/src/bfcli/generated
            --
            -Xiwyu --error
            -Xiwyu --no_comments
            -Xiwyu --mapping_file=${CMAKE_SOURCE_DIR}/tests/check/iwyu.mapping
)

set_tests_properties("check.iwyu" PROPERTIES
    LABELS "check"
)

add_custom_target(fixstyle
    COMMAND
        ${CLANG_FORMAT_BIN}
            --style=file:${CMAKE_SOURCE_DIR}/.clang-format
            -i
            ${bf_srcs}
    COMMENT "Fixing style for all the source files"
)

add_custom_target(check
    COMMAND ${CMAKE_CTEST_COMMAND} --output-on-failure -L check
    COMMENT "Running check tests"
)