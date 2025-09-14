# SPDX-License-Identifier: GPL-2.0-only
# Copyright (c) 2023 Meta Platforms, Inc. and affiliates.

find_program(BISON_BIN bison REQUIRED)
find_program(FLEX_BIN flex REQUIRED)

file(MAKE_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/generated)
file(MAKE_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/include)

add_custom_command(
    COMMAND
        ${BISON_BIN}
            --debug
            --defines=${CMAKE_CURRENT_BINARY_DIR}/include/parser.h
            -o ${CMAKE_CURRENT_BINARY_DIR}/generated/parser.c
            ${CMAKE_CURRENT_SOURCE_DIR}/parser.y
    DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/parser.y
    OUTPUT
        ${CMAKE_CURRENT_BINARY_DIR}/include/parser.h
        ${CMAKE_CURRENT_BINARY_DIR}/generated/parser.c
    COMMENT "Generate the Bison parser"
)

add_custom_target(bfcli_parser
    DEPENDS
        ${CMAKE_CURRENT_BINARY_DIR}/include/parser.h
        ${CMAKE_CURRENT_BINARY_DIR}/generated/parser.c
)

add_custom_command(
    COMMAND
        ${FLEX_BIN}
            --header-file=${CMAKE_CURRENT_BINARY_DIR}/include/lexer.h
            -o ${CMAKE_CURRENT_BINARY_DIR}/generated/lexer.c
            ${CMAKE_CURRENT_SOURCE_DIR}/lexer.l
    DEPENDS
        ${CMAKE_CURRENT_SOURCE_DIR}/lexer.l
        ${CMAKE_CURRENT_BINARY_DIR}/include/parser.h
    OUTPUT
        ${CMAKE_CURRENT_BINARY_DIR}/include/lexer.h
        ${CMAKE_CURRENT_BINARY_DIR}/generated/lexer.c
    COMMENT "Generate the Flex lexer"
)

add_custom_target(bfcli_lexer
    DEPENDS
        ${CMAKE_CURRENT_BINARY_DIR}/include/lexer.h
        ${CMAKE_CURRENT_BINARY_DIR}/generated/lexer.c
)

add_executable(bfcli
    ${CMAKE_CURRENT_SOURCE_DIR}/main.c
    ${CMAKE_CURRENT_SOURCE_DIR}/chain.h             ${CMAKE_CURRENT_SOURCE_DIR}/chain.c
    ${CMAKE_CURRENT_SOURCE_DIR}/helper.h            ${CMAKE_CURRENT_SOURCE_DIR}/helper.c
    ${CMAKE_CURRENT_SOURCE_DIR}/opts.h              ${CMAKE_CURRENT_SOURCE_DIR}/opts.c
    ${CMAKE_CURRENT_SOURCE_DIR}/print.h             ${CMAKE_CURRENT_SOURCE_DIR}/print.c
    ${CMAKE_CURRENT_SOURCE_DIR}/ruleset.h           ${CMAKE_CURRENT_SOURCE_DIR}/ruleset.c
    ${CMAKE_CURRENT_BINARY_DIR}/generated/parser.c  ${CMAKE_CURRENT_BINARY_DIR}/include/parser.h
    ${CMAKE_CURRENT_BINARY_DIR}/generated/lexer.c   ${CMAKE_CURRENT_BINARY_DIR}/include/lexer.h
)

target_compile_definitions(bfcli
    PRIVATE
        BF_CONTACT="${BF_CONTACT}"
        "YY_READ_BUF_SIZE=(yy_read_buf_size)"
)

target_include_directories(bfcli
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}
        ${CMAKE_CURRENT_BINARY_DIR}/include
)

target_link_libraries(bfcli
    PRIVATE
        bf_global_flags
        libbpfilter
)

install(TARGETS bfcli
    DESTINATION ${CMAKE_INSTALL_SBINDIR}
)
