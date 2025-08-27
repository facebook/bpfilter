# SPDX-License-Identifier: GPL-2.0-only
# Copyright (c) 2023 Meta Platforms, Inc. and affiliates.

add_subdirectory(harness)

add_subdirectory(unit)
add_subdirectory(e2e)
add_subdirectory(pedantic)

add_subdirectory(integration)

add_custom_target(test
    DEPENDS unit e2e pedantic
    COMMENT "Running tests"
)
