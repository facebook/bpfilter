# SPDX-License-Identifier: GPL-2.0-only
# Copyright (c) 2023 Meta Platforms, Inc. and affiliates.

find_program(BISON_BIN bison REQUIRED)
find_program(FLEX_BIN flex REQUIRED)

file(MAKE_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/generated/bfcli)
file(MAKE_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/generated/include/bfcli)

add_custom_command(
    COMMAND
        ${BISON_BIN}
            --debug
            --defines=${CMAKE_CURRENT_BINARY_DIR}/generated/include/bfcli/parser.h
            -o ${CMAKE_CURRENT_BINARY_DIR}/generated/bfcli/parser.c
            ${CMAKE_CURRENT_SOURCE_DIR}/parser.y
    DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/parser.y
    OUTPUT
        ${CMAKE_CURRENT_BINARY_DIR}/generated/include/bfcli/parser.h
        ${CMAKE_CURRENT_BINARY_DIR}/generated/bfcli/parser.c
    COMMENT "Generate the Bison parser"
)

add_custom_target(bfcli_parser
    DEPENDS
        ${CMAKE_CURRENT_BINARY_DIR}/generated/include/bfcli/parser.h
        ${CMAKE_CURRENT_BINARY_DIR}/generated/bfcli/parser.c
)

add_custom_command(
    COMMAND
        ${FLEX_BIN}
            --header-file=${CMAKE_CURRENT_BINARY_DIR}/generated/include/bfcli/lexer.h
            -o ${CMAKE_CURRENT_BINARY_DIR}/generated/bfcli/lexer.c
            ${CMAKE_CURRENT_SOURCE_DIR}/lexer.l
    DEPENDS
        ${CMAKE_CURRENT_SOURCE_DIR}/parser.y
        ${CMAKE_CURRENT_BINARY_DIR}/generated/include/bfcli/parser.h
    OUTPUT
        ${CMAKE_CURRENT_BINARY_DIR}/generated/include/bfcli/lexer.h
        ${CMAKE_CURRENT_BINARY_DIR}/generated/bfcli/lexer.c
    COMMENT "Generate the Flex lexer"
)

add_custom_target(bfcli_lexer
    DEPENDS
        ${CMAKE_CURRENT_BINARY_DIR}/generated/include/bfcli/lexer.h
        ${CMAKE_CURRENT_BINARY_DIR}/generated/bfcli/lexer.c
)

add_executable(bfcli
    ${CMAKE_CURRENT_SOURCE_DIR}/main.c
    ${CMAKE_CURRENT_SOURCE_DIR}/print.c
    ${CMAKE_CURRENT_SOURCE_DIR}/print.h
    ${CMAKE_BINARY_DIR}/include/version.h
    ${CMAKE_CURRENT_BINARY_DIR}/generated/include/bfcli/parser.h
    ${CMAKE_CURRENT_BINARY_DIR}/generated/bfcli/parser.c
    ${CMAKE_CURRENT_BINARY_DIR}/generated/include/bfcli/lexer.h
    ${CMAKE_CURRENT_BINARY_DIR}/generated/bfcli/lexer.c
)

target_include_directories(bfcli
    PRIVATE
        ${CMAKE_SOURCE_DIR}/src
        ${CMAKE_BINARY_DIR}/include
        ${CMAKE_CURRENT_BINARY_DIR}/generated/include
        ${CMAKE_CURRENT_BINARY_DIR}/generated/include/bfcli
)

target_link_libraries(bfcli
    PRIVATE
        bf_global_flags
        core
        libbpfilter
)

install(TARGETS bfcli
    DESTINATION ${CMAKE_INSTALL_SBINDIR}
)
