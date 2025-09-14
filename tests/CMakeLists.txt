# SPDX-License-Identifier: GPL-2.0-only
# Copyright (c) 2023 Meta Platforms, Inc. and affiliates.

add_subdirectory(harness)

add_subdirectory(unit)
add_subdirectory(e2e)
add_subdirectory(pedantic)

add_subdirectory(integration)

add_custom_target(test
    COMMAND
        ${CMAKE_COMMAND} --build ${CMAKE_CURRENT_BINARY_DIR}/unit -- unit
    COMMAND
        ${CMAKE_COMMAND} --build ${CMAKE_CURRENT_BINARY_DIR}/e2e -- e2e
    COMMAND
        ${CMAKE_COMMAND} --build ${CMAKE_CURRENT_BINARY_DIR}/pedantic -- pedantic
    COMMENT "Running the test suite"
)
