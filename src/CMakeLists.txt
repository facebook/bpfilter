# SPDX-License-Identifier: GPL-2.0-only
# Copyright (c) 2023 Meta Platforms, Inc. and affiliates.

#[[
    shared
#]]
add_library(shared OBJECT
    ${CMAKE_CURRENT_SOURCE_DIR}/shared/front.h          ${CMAKE_CURRENT_SOURCE_DIR}/shared/front.c
    ${CMAKE_CURRENT_SOURCE_DIR}/shared/generic.h        ${CMAKE_CURRENT_SOURCE_DIR}/shared/generic.c
    ${CMAKE_CURRENT_SOURCE_DIR}/shared/helper.h
    ${CMAKE_CURRENT_SOURCE_DIR}/shared/ipt.h
    ${CMAKE_CURRENT_SOURCE_DIR}/shared/request.h        ${CMAKE_CURRENT_SOURCE_DIR}/shared/request.c
    ${CMAKE_CURRENT_SOURCE_DIR}/shared/response.h       ${CMAKE_CURRENT_SOURCE_DIR}/shared/response.c
)

target_include_directories(shared PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_compile_options(shared PUBLIC ${bf_cflags})
target_link_options(shared PUBLIC ${bf_ldflags})

#[[
    core
#]]
add_library(core OBJECT
    ${CMAKE_CURRENT_SOURCE_DIR}/core/bpf.h              ${CMAKE_CURRENT_SOURCE_DIR}/core/bpf.c
    ${CMAKE_CURRENT_SOURCE_DIR}/core/btf.h              ${CMAKE_CURRENT_SOURCE_DIR}/core/btf.c
    ${CMAKE_CURRENT_SOURCE_DIR}/core/chain.h            ${CMAKE_CURRENT_SOURCE_DIR}/core/chain.c
    ${CMAKE_CURRENT_SOURCE_DIR}/core/context.h          ${CMAKE_CURRENT_SOURCE_DIR}/core/context.c
    ${CMAKE_CURRENT_SOURCE_DIR}/core/counter.h
    ${CMAKE_CURRENT_SOURCE_DIR}/core/dump.h             ${CMAKE_CURRENT_SOURCE_DIR}/core/dump.c
    ${CMAKE_CURRENT_SOURCE_DIR}/core/flavor.h           ${CMAKE_CURRENT_SOURCE_DIR}/core/flavor.c
    ${CMAKE_CURRENT_SOURCE_DIR}/core/helper.h           ${CMAKE_CURRENT_SOURCE_DIR}/core/helper.c
    ${CMAKE_CURRENT_SOURCE_DIR}/core/hook.h             ${CMAKE_CURRENT_SOURCE_DIR}/core/hook.c
    ${CMAKE_CURRENT_SOURCE_DIR}/core/list.h             ${CMAKE_CURRENT_SOURCE_DIR}/core/list.c
    ${CMAKE_CURRENT_SOURCE_DIR}/core/logger.h           ${CMAKE_CURRENT_SOURCE_DIR}/core/logger.c
    ${CMAKE_CURRENT_SOURCE_DIR}/core/marsh.h            ${CMAKE_CURRENT_SOURCE_DIR}/core/marsh.c
    ${CMAKE_CURRENT_SOURCE_DIR}/core/matcher.h          ${CMAKE_CURRENT_SOURCE_DIR}/core/matcher.c
    ${CMAKE_CURRENT_SOURCE_DIR}/core/opts.h             ${CMAKE_CURRENT_SOURCE_DIR}/core/opts.c
    ${CMAKE_CURRENT_SOURCE_DIR}/core/rule.h             ${CMAKE_CURRENT_SOURCE_DIR}/core/rule.c
    ${CMAKE_CURRENT_SOURCE_DIR}/core/verdict.h          ${CMAKE_CURRENT_SOURCE_DIR}/core/verdict.c
)

target_include_directories(core PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_compile_options(core PUBLIC ${bf_cflags})
target_link_options(core PUBLIC ${bf_ldflags})
target_link_libraries(core
    PUBLIC
        PkgConfig::bpf
        shared
)

#[[
    generator
#]]
add_library(generator OBJECT
    ${CMAKE_CURRENT_SOURCE_DIR}/generator/codegen.h     ${CMAKE_CURRENT_SOURCE_DIR}/generator/codegen.c
    ${CMAKE_CURRENT_SOURCE_DIR}/generator/dump.h        ${CMAKE_CURRENT_SOURCE_DIR}/generator/dump.c
    ${CMAKE_CURRENT_SOURCE_DIR}/generator/fixup.h       ${CMAKE_CURRENT_SOURCE_DIR}/generator/fixup.c
    ${CMAKE_CURRENT_SOURCE_DIR}/generator/jmp.h         ${CMAKE_CURRENT_SOURCE_DIR}/generator/jmp.c
    ${CMAKE_CURRENT_SOURCE_DIR}/generator/matcher/ip.h  ${CMAKE_CURRENT_SOURCE_DIR}/generator/matcher/ip.c
    ${CMAKE_CURRENT_SOURCE_DIR}/generator/nf.h          ${CMAKE_CURRENT_SOURCE_DIR}/generator/nf.c
    ${CMAKE_CURRENT_SOURCE_DIR}/generator/printer.h     ${CMAKE_CURRENT_SOURCE_DIR}/generator/printer.c
    ${CMAKE_CURRENT_SOURCE_DIR}/generator/program.h     ${CMAKE_CURRENT_SOURCE_DIR}/generator/program.c
    ${CMAKE_CURRENT_SOURCE_DIR}/generator/reg.h
    ${CMAKE_CURRENT_SOURCE_DIR}/generator/stub.h        ${CMAKE_CURRENT_SOURCE_DIR}/generator/stub.c
    ${CMAKE_CURRENT_SOURCE_DIR}/generator/swich.h       ${CMAKE_CURRENT_SOURCE_DIR}/generator/swich.c
    ${CMAKE_CURRENT_SOURCE_DIR}/generator/tc.h          ${CMAKE_CURRENT_SOURCE_DIR}/generator/tc.c
    ${CMAKE_CURRENT_SOURCE_DIR}/generator/xdp.h         ${CMAKE_CURRENT_SOURCE_DIR}/generator/xdp.c
)

target_include_directories(generator PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_compile_options(generator PUBLIC ${bf_cflags})
target_link_options(generator PUBLIC ${bf_ldflags})
target_link_libraries(generator
    PUBLIC
        core
        shared
)

#[[
    xlate
#]]
add_library(xlate OBJECT
    ${CMAKE_SOURCE_DIR}/src/xlate/cli.c
    ${CMAKE_SOURCE_DIR}/src/xlate/front.h               ${CMAKE_SOURCE_DIR}/src/xlate/front.c
    ${CMAKE_SOURCE_DIR}/src/xlate/ipt/dump.h            ${CMAKE_SOURCE_DIR}/src/xlate/ipt/dump.c
    ${CMAKE_SOURCE_DIR}/src/xlate/ipt/helpers.h
    ${CMAKE_SOURCE_DIR}/src/xlate/ipt/ipt.c
    ${CMAKE_SOURCE_DIR}/src/xlate/nft/nfgroup.h         ${CMAKE_SOURCE_DIR}/src/xlate/nft/nfgroup.c
    ${CMAKE_SOURCE_DIR}/src/xlate/nft/nfmsg.h           ${CMAKE_SOURCE_DIR}/src/xlate/nft/nfmsg.c
    ${CMAKE_SOURCE_DIR}/src/xlate/nft/nft.c
)

target_include_directories(xlate PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_compile_options(xlate PUBLIC ${bf_cflags})
target_link_options(xlate PUBLIC ${bf_ldflags})
target_link_libraries(xlate
    PUBLIC
        core
        shared
        PkgConfig::nl
)

#[[
    lib
#]]
add_library(lib OBJECT
    ${CMAKE_CURRENT_SOURCE_DIR}/lib/bpfilter.h
    ${CMAKE_CURRENT_SOURCE_DIR}/lib/generic.h           ${CMAKE_CURRENT_SOURCE_DIR}/lib/generic.c
                                                        ${CMAKE_CURRENT_SOURCE_DIR}/lib/ipt.c
                                                        ${CMAKE_CURRENT_SOURCE_DIR}/lib/nft.c
)

target_include_directories(shared PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
target_compile_options(lib PRIVATE -fPIC ${bf_cflags})
target_link_options(lib PUBLIC ${bf_ldflags})
target_link_libraries(lib PRIVATE shared)

#[[
    daemon
#]]
add_executable(daemon ${CMAKE_CURRENT_SOURCE_DIR}/daemon.c)

set_target_properties(daemon PROPERTIES OUTPUT_NAME bpfilter)

target_compile_options(daemon PRIVATE ${bf_cflags})
target_link_options(daemon PRIVATE ${bf_ldflags})
target_link_libraries(daemon
    PRIVATE
        core
        shared
        generator
        xlate
)

install(
    TARGETS daemon
    DESTINATION ${CMAKE_INSTALL_BINDIR}
)

#[[
    cli
]]
file(MAKE_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/generated/cli)
file(MAKE_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/generated/include/cli)

BISON_TARGET(cli_parser
    ${CMAKE_CURRENT_SOURCE_DIR}/cli/parser.y
    ${CMAKE_CURRENT_BINARY_DIR}/generated/cli/parser.c
    COMPILE_FLAGS --debug
    DEFINES_FILE ${CMAKE_CURRENT_BINARY_DIR}/generated/include/cli/parser.h
)

FLEX_TARGET(cli_lexer
    ${CMAKE_CURRENT_SOURCE_DIR}/cli/lexer.l
    ${CMAKE_CURRENT_BINARY_DIR}/generated/cli/lexer.c
    DEFINES_FILE ${CMAKE_CURRENT_BINARY_DIR}/generated/include/cli/lexer.h
)

ADD_FLEX_BISON_DEPENDENCY(cli_lexer cli_parser)

add_executable(cli
    ${CMAKE_CURRENT_SOURCE_DIR}/cli/cli.c
    ${BISON_cli_parser_OUTPUTS}
    ${FLEX_cli_lexer_OUTPUTS}
)

set_target_properties(cli PROPERTIES OUTPUT_NAME bfcli)

target_include_directories(cli
    PRIVATE
        ${CMAKE_CURRENT_BINARY_DIR}/generated/include
        ${CMAKE_CURRENT_BINARY_DIR}/generated/include/cli
)
target_compile_options(cli PRIVATE ${bf_cflags})
target_link_options(cli PRIVATE ${bf_ldflags})
target_link_libraries(cli
PRIVATE
        lib
        shared
        core
        generator
)

install(
    TARGETS cli
    DESTINATION ${CMAKE_INSTALL_BINDIR}
)

#[[
    libraries
#]]
add_library(libbpfilter_static STATIC $<TARGET_OBJECTS:lib>)
set_target_properties(libbpfilter_static PROPERTIES OUTPUT_NAME bpfilter)

add_library(libbpfilter_shared SHARED $<TARGET_OBJECTS:lib>)
set_target_properties(libbpfilter_shared PROPERTIES OUTPUT_NAME bpfilter)
target_compile_options(libbpfilter_shared PRIVATE -fPIC)

add_custom_target(library
    ALL
    DEPENDS libbpfilter_static libbpfilter_shared
    COMMENT "Compound target to build libbpfilter.a and libbpfilter.so"
)

install(
    TARGETS libbpfilter_static libbpfilter_shared
    DESTINATION ${CMAKE_INSTALL_LIBDIR}
)

install(
    FILES ${CMAKE_CURRENT_SOURCE_DIR}/lib/bpfilter.h
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/bpfilter
)
