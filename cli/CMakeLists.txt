# SPDX-License-Identifier: GPL-2.0-only
# Copyright (c) 2023 Meta Platforms, Inc. and affiliates.

file(MAKE_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/parser)

BISON_TARGET(bfcli_parser
    ${CMAKE_CURRENT_SOURCE_DIR}/parser/parser.y
    ${CMAKE_CURRENT_BINARY_DIR}/parser/parser.c
    COMPILE_FLAGS --debug
    DEFINES_FILE ${CMAKE_CURRENT_BINARY_DIR}/parser/parser.h
)

FLEX_TARGET(bfcli_lexer
    ${CMAKE_CURRENT_SOURCE_DIR}/parser/lexer.l
    ${CMAKE_CURRENT_BINARY_DIR}/parser/lexer.c
    DEFINES_FILE ${CMAKE_CURRENT_BINARY_DIR}/parser/lexer.h
)

ADD_FLEX_BISON_DEPENDENCY(bfcli_lexer bfcli_parser)

# Some definitions coming from src/core are required for bfcli. Ideally,
# src/core would be moved to its own library (or target, at least). The
# solution for now is to include those files to the target.
add_executable(bfcli
    ${CMAKE_SOURCE_DIR}/cli/main.c

    ${CMAKE_SOURCE_DIR}/src/opts.h ${CMAKE_SOURCE_DIR}/src/opts.c
    ${CMAKE_SOURCE_DIR}/src/core/chain.c ${CMAKE_SOURCE_DIR}/src/core/chain.h
    ${CMAKE_SOURCE_DIR}/src/core/dump.h ${CMAKE_SOURCE_DIR}/src/core/dump.c
    ${CMAKE_SOURCE_DIR}/src/core/helper.h ${CMAKE_SOURCE_DIR}/src/core/helper.c
    ${CMAKE_SOURCE_DIR}/src/core/hook.h ${CMAKE_SOURCE_DIR}/src/core/hook.c
    ${CMAKE_SOURCE_DIR}/src/core/list.h ${CMAKE_SOURCE_DIR}/src/core/list.c
    ${CMAKE_SOURCE_DIR}/src/core/logger.h ${CMAKE_SOURCE_DIR}/src/core/logger.c
    ${CMAKE_SOURCE_DIR}/src/core/matcher.h ${CMAKE_SOURCE_DIR}/src/core/matcher.c
    ${CMAKE_SOURCE_DIR}/src/core/rule.h ${CMAKE_SOURCE_DIR}/src/core/rule.c
    ${CMAKE_SOURCE_DIR}/src/core/marsh.h ${CMAKE_SOURCE_DIR}/src/core/marsh.c
    ${CMAKE_SOURCE_DIR}/src/core/verdict.h ${CMAKE_SOURCE_DIR}/src/core/verdict.c

    ${bpfilter_shared_srcs}
    ${BISON_bfcli_parser_OUTPUTS}
    ${FLEX_bfcli_lexer_OUTPUTS}
)

target_include_directories(bfcli
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}
        ${CMAKE_SOURCE_DIR}/src
        ${CMAKE_SOURCE_DIR}/shared/include
        ${CMAKE_SOURCE_DIR}/shared/include/bpfilter
        ${CMAKE_CURRENT_BINARY_DIR}
)

target_compile_options(bfcli
    PRIVATE
        -fPIE ${bpfilter_cflags}
        $<$<CONFIG:Release>:${bpfilter_cflags_release}>
        $<$<CONFIG:Debug>:${bpfilter_cflags_debug}>
)

target_link_options(bfcli
    PUBLIC
        ${bpfilter_ldflags}
        $<$<CONFIG:Release>:${bpfilter_ldflags_release}>
        $<$<CONFIG:Debug>:${bpfilter_ldflags_debug}>
)

target_link_libraries(bfcli
    PUBLIC
        PkgConfig::bpf
        PkgConfig::nl
)

install(
    TARGETS bfcli
    DESTINATION ${CMAKE_INSTALL_BINDIR}
)
