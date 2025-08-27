# SPDX-License-Identifier: GPL-2.0-only
# Copyright (c) 2023 Meta Platforms, Inc. and affiliates.

add_executable(pedantic_c EXCLUDE_FROM_ALL pedantic.c)

target_include_directories(pedantic_c
    PUBLIC
        ${CMAKE_SOURCE_DIR}/src
        ${CMAKE_BINARY_DIR}/include
)

target_compile_options(pedantic_c PRIVATE -pedantic-errors -std=c17)

target_link_libraries(pedantic_c
    PUBLIC
        bf_global_flags
)

add_executable(pedantic_cpp EXCLUDE_FROM_ALL pedantic.cpp)

target_include_directories(pedantic_cpp
    PUBLIC
        ${CMAKE_SOURCE_DIR}/src
        ${CMAKE_BINARY_DIR}/include
)

target_compile_options(pedantic_cpp PRIVATE -pedantic-errors -std=c++17)

target_link_libraries(pedantic_cpp
    PUBLIC
        bf_global_flags
)

add_custom_target(pedantic
    COMMAND $<TARGET_FILE:pedantic_c>
    COMMAND $<TARGET_FILE:pedantic_cpp>
    COMMENT "Running pedantic tests"
)
