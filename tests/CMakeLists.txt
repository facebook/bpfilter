# SPDX-License-Identifier: GPL-2.0-only
# Copyright (c) 2023 Meta Platforms, Inc. and affiliates.

add_subdirectory(harness)
add_subdirectory(unit)
add_subdirectory(e2e)
add_subdirectory(integration)
add_subdirectory(check)

if (${WITH_COVERAGE})
    include(ProcessorCount)

    find_program(LCOV_BIN lcov REQUIRED)
    find_program(GENHTML_BIN genhtml REQUIRED)

    ProcessorCount(N)
    if(N EQUAL 0)
        set(N 1)
    endif()

    add_custom_target(coverage
        COMMAND
            ${LCOV_BIN}
                --capture
                --directory ${CMAKE_BINARY_DIR}
                --output-file ${CMAKE_CURRENT_BINARY_DIR}/raw_coverage.lcov
                --parallel ${N}
                --branch-coverage
                --quiet
        # Only keep the coverage for bpfilter's source files, not the tests.
        COMMAND
            ${LCOV_BIN}
                --output-file ${CMAKE_BINARY_DIR}/coverage.lcov
                --extract ${CMAKE_CURRENT_BINARY_DIR}/raw_coverage.lcov
                --ignore-errors unused
                --branch-coverage
                --parallel ${N}
                --quiet
                "${CMAKE_SOURCE_DIR}/src/libbpfilter\\*"
                "${CMAKE_SOURCE_DIR}/src/bpfilter\\*"
        COMMAND
            ${LCOV_BIN}
                --summary ${CMAKE_BINARY_DIR}/coverage.lcov
                --branch-coverage
        COMMAND
			${GENHTML_BIN}
				--output-directory ${CMAKE_BINARY_DIR}/coverage
                --branch-coverage
				${CMAKE_BINARY_DIR}/coverage.lcov > /dev/null;
        COMMAND
            cp ${CMAKE_BINARY_DIR}/.coverage_report.d.full ${CMAKE_BINARY_DIR}/.coverage_report.d
        BYPRODUCTS
            ${CMAKE_BINARY_DIR}/coverage.lcov
            ${CMAKE_BINARY_DIR}/coverage/index.html
        COMMENT "Generate the coverage.lcov summary file"
    )
endif()