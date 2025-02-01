# SPDX-License-Identifier: GPL-2.0-only
# Copyright (c) 2023 Meta Platforms, Inc. and affiliates.

find_package(FLEX REQUIRED)
find_package(BISON REQUIRED)

file(MAKE_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/generated/bfcli)
file(MAKE_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/generated/include/bfcli)

BISON_TARGET(bfcli_parser
    ${CMAKE_CURRENT_SOURCE_DIR}/parser.y
    ${CMAKE_CURRENT_BINARY_DIR}/generated/bfcli/parser.c
    COMPILE_FLAGS --debug
    DEFINES_FILE ${CMAKE_CURRENT_BINARY_DIR}/generated/include/bfcli/parser.h
)

FLEX_TARGET(bfcli_lexer
    ${CMAKE_CURRENT_SOURCE_DIR}/lexer.l
    ${CMAKE_CURRENT_BINARY_DIR}/generated/bfcli/lexer.c
    DEFINES_FILE ${CMAKE_CURRENT_BINARY_DIR}/generated/include/bfcli/lexer.h
)

ADD_FLEX_BISON_DEPENDENCY(bfcli_lexer bfcli_parser)

add_executable(bfcli
    ${CMAKE_CURRENT_SOURCE_DIR}/main.c
    ${BISON_bfcli_parser_OUTPUTS}
    ${FLEX_bfcli_lexer_OUTPUTS}
)

target_include_directories(bfcli
    PRIVATE
        ${CMAKE_SOURCE_DIR}/src
        ${CMAKE_CURRENT_BINARY_DIR}/generated/include
        ${CMAKE_CURRENT_BINARY_DIR}/generated/include/bfcli
)

target_link_libraries(bfcli
    PRIVATE
        bf_global_flags
        core
        libbpfilter_a
)
