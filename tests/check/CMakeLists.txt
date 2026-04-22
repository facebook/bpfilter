# SPDX-License-Identifier: GPL-2.0-only
# Copyright (c) 2023 Meta Platforms, Inc. and affiliates.

find_program(RUN_CLANG_TIDY_BIN NAMES run-clang-tidy-18 run-clang-tidy REQUIRED)
find_program(CLANG_FORMAT_BIN NAMES clang-format-18 clang-format REQUIRED)

file(GLOB_RECURSE bf_srcs
    ${CMAKE_SOURCE_DIR}/src/core/*.h            ${CMAKE_SOURCE_DIR}/src/core/*.c
    ${CMAKE_SOURCE_DIR}/src/libbpfilter/*.h     ${CMAKE_SOURCE_DIR}/src/libbpfilter/*.c
    ${CMAKE_SOURCE_DIR}/src/bfcli/*.h           ${CMAKE_SOURCE_DIR}/src/bfcli/*.c
)

file(GLOB_RECURSE bf_test_srcs
    ${CMAKE_SOURCE_DIR}/tests/*.h               ${CMAKE_SOURCE_DIR}/tests/*.c
    ${CMAKE_SOURCE_DIR}/tests/*.hpp             ${CMAKE_SOURCE_DIR}/tests/*.cpp
    ${CMAKE_SOURCE_DIR}/tools/benchmarks/*.hpp  ${CMAKE_SOURCE_DIR}/tools/benchmarks/*.cpp
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
            ${CMAKE_SOURCE_DIR}/src/libbpfilter/cgen/program.c
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

find_program(SG_BIN NAMES ast-grep)

if(SG_BIN)
    execute_process(
        COMMAND python3 -c "import yaml"
        RESULT_VARIABLE SG_PYYAML_RC
        OUTPUT_QUIET ERROR_QUIET
    )
    if(NOT SG_PYYAML_RC EQUAL 0)
        message(WARNING
            "ast-grep: python3 cannot import yaml; "
            "skipping check.astgrep. Install python3-pyyaml (dnf) or "
            "python3-yaml (apt) to enable it.")
    endif()
endif()

if(SG_BIN AND SG_PYYAML_RC EQUAL 0)
    set(SG_CONFIG ${CMAKE_SOURCE_DIR}/tools/ast-grep/sgconfig.yml)
    set(SG_KNOWN_ISSUES ${CMAKE_SOURCE_DIR}/tools/ast-grep/known_issues)
    set(SG_FILTER ${CMAKE_SOURCE_DIR}/tools/ast-grep/ignore_known_issues.py)

    add_test(NAME "check.astgrep"
        COMMAND bash -c "set -o pipefail; \
${SG_BIN} test --config ${SG_CONFIG} && \
${SG_BIN} scan --config ${SG_CONFIG} --json=stream \
    ${CMAKE_SOURCE_DIR}/src/libbpfilter \
    ${CMAKE_SOURCE_DIR}/src/bfcli \
  | python3 ${SG_FILTER} --check \
    --known-issues-dir ${SG_KNOWN_ISSUES} \
    --repo-root ${CMAKE_SOURCE_DIR}"
    )

    set_tests_properties("check.astgrep" PROPERTIES
        LABELS "check"
    )

    add_custom_target(astgrep-known-issues
        COMMAND bash -c "set -o pipefail; \
${SG_BIN} scan --config ${SG_CONFIG} --json=stream \
    ${CMAKE_SOURCE_DIR}/src/libbpfilter \
    ${CMAKE_SOURCE_DIR}/src/bfcli \
  | python3 ${SG_FILTER} --regen \
    --known-issues-dir ${SG_KNOWN_ISSUES} \
    --repo-root ${CMAKE_SOURCE_DIR}"
        COMMENT "Regenerating ast-grep known_issues/ from current scan"
        VERBATIM
    )
endif()

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