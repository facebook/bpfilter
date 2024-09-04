# SPDX-License-Identifier: GPL-2.0-only
# Copyright (c) 2023 Meta Platforms, Inc. and affiliates.

#[[
    core
#]]
set(core_srcs
    ${CMAKE_CURRENT_SOURCE_DIR}/core/bpf.h              ${CMAKE_CURRENT_SOURCE_DIR}/core/bpf.c
    ${CMAKE_CURRENT_SOURCE_DIR}/core/btf.h              ${CMAKE_CURRENT_SOURCE_DIR}/core/btf.c
    ${CMAKE_CURRENT_SOURCE_DIR}/core/chain.h            ${CMAKE_CURRENT_SOURCE_DIR}/core/chain.c
    ${CMAKE_CURRENT_SOURCE_DIR}/core/counter.h
    ${CMAKE_CURRENT_SOURCE_DIR}/core/dump.h             ${CMAKE_CURRENT_SOURCE_DIR}/core/dump.c
    ${CMAKE_CURRENT_SOURCE_DIR}/core/flavor.h           ${CMAKE_CURRENT_SOURCE_DIR}/core/flavor.c
    ${CMAKE_CURRENT_SOURCE_DIR}/core/front.h            ${CMAKE_CURRENT_SOURCE_DIR}/core/front.c
    ${CMAKE_CURRENT_SOURCE_DIR}/core/helper.h           ${CMAKE_CURRENT_SOURCE_DIR}/core/helper.c
    ${CMAKE_CURRENT_SOURCE_DIR}/core/hook.h             ${CMAKE_CURRENT_SOURCE_DIR}/core/hook.c
    ${CMAKE_CURRENT_SOURCE_DIR}/core/if.h               ${CMAKE_CURRENT_SOURCE_DIR}/core/if.c
    ${CMAKE_CURRENT_SOURCE_DIR}/core/io.h               ${CMAKE_CURRENT_SOURCE_DIR}/core/io.c
    ${CMAKE_CURRENT_SOURCE_DIR}/core/list.h             ${CMAKE_CURRENT_SOURCE_DIR}/core/list.c
    ${CMAKE_CURRENT_SOURCE_DIR}/core/logger.h           ${CMAKE_CURRENT_SOURCE_DIR}/core/logger.c
    ${CMAKE_CURRENT_SOURCE_DIR}/core/marsh.h            ${CMAKE_CURRENT_SOURCE_DIR}/core/marsh.c
    ${CMAKE_CURRENT_SOURCE_DIR}/core/matcher.h          ${CMAKE_CURRENT_SOURCE_DIR}/core/matcher.c
    ${CMAKE_CURRENT_SOURCE_DIR}/core/nf.h               ${CMAKE_CURRENT_SOURCE_DIR}/core/nf.c
    ${CMAKE_CURRENT_SOURCE_DIR}/core/opts.h             ${CMAKE_CURRENT_SOURCE_DIR}/core/opts.c
    ${CMAKE_CURRENT_SOURCE_DIR}/core/request.h          ${CMAKE_CURRENT_SOURCE_DIR}/core/request.c
    ${CMAKE_CURRENT_SOURCE_DIR}/core/response.h         ${CMAKE_CURRENT_SOURCE_DIR}/core/response.c
    ${CMAKE_CURRENT_SOURCE_DIR}/core/rule.h             ${CMAKE_CURRENT_SOURCE_DIR}/core/rule.c
    ${CMAKE_CURRENT_SOURCE_DIR}/core/set.h              ${CMAKE_CURRENT_SOURCE_DIR}/core/set.c
    ${CMAKE_CURRENT_SOURCE_DIR}/core/verdict.h          ${CMAKE_CURRENT_SOURCE_DIR}/core/verdict.c
)

add_library(core OBJECT ${core_srcs})
target_include_directories(core PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_compile_options(core PUBLIC ${bf_cflags})
target_link_options(core PUBLIC ${bf_ldflags})
target_link_libraries(core PUBLIC PkgConfig::bpf)

add_library(core_pic OBJECT ${core_srcs})
target_include_directories(core_pic PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_compile_options(core_pic PUBLIC -fPIC ${bf_cflags})
target_link_options(core_pic PUBLIC ${bf_ldflags})
target_link_libraries(core_pic PUBLIC PkgConfig::bpf)

#[[
    lib
#]]
set(lib_srcs
    ${CMAKE_CURRENT_SOURCE_DIR}/lib/bpfilter.h
    ${CMAKE_CURRENT_SOURCE_DIR}/lib/generic.h           ${CMAKE_CURRENT_SOURCE_DIR}/lib/generic.c
                                                        ${CMAKE_CURRENT_SOURCE_DIR}/lib/ipt.c
                                                        ${CMAKE_CURRENT_SOURCE_DIR}/lib/nft.c
)

add_library(lib OBJECT ${lib_srcs})
target_include_directories(lib PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
target_compile_options(lib PRIVATE ${bf_cflags})
target_link_options(lib PUBLIC ${bf_ldflags})
target_link_libraries(lib PUBLIC core)

add_library(lib_pic OBJECT ${lib_srcs})
target_include_directories(lib_pic PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
target_compile_options(lib_pic PRIVATE -fPIC ${bf_cflags})
target_link_options(lib_pic PUBLIC ${bf_ldflags})
target_link_libraries(lib_pic PUBLIC core_pic)

#[[
    daemon
#]]
add_executable(daemon
    ${CMAKE_CURRENT_SOURCE_DIR}/daemon/daemon.c
    ${CMAKE_CURRENT_SOURCE_DIR}/daemon/cgen/codegen.h           ${CMAKE_CURRENT_SOURCE_DIR}/daemon/cgen/codegen.c
    ${CMAKE_CURRENT_SOURCE_DIR}/daemon/cgen/dump.h              ${CMAKE_CURRENT_SOURCE_DIR}/daemon/cgen/dump.c
    ${CMAKE_CURRENT_SOURCE_DIR}/daemon/cgen/fixup.h             ${CMAKE_CURRENT_SOURCE_DIR}/daemon/cgen/fixup.c
    ${CMAKE_CURRENT_SOURCE_DIR}/daemon/cgen/jmp.h               ${CMAKE_CURRENT_SOURCE_DIR}/daemon/cgen/jmp.c
    ${CMAKE_CURRENT_SOURCE_DIR}/daemon/cgen/matcher/ip4.h       ${CMAKE_CURRENT_SOURCE_DIR}/daemon/cgen/matcher/ip4.c
    ${CMAKE_CURRENT_SOURCE_DIR}/daemon/cgen/matcher/ip6.h       ${CMAKE_CURRENT_SOURCE_DIR}/daemon/cgen/matcher/ip6.c
    ${CMAKE_CURRENT_SOURCE_DIR}/daemon/cgen/matcher/tcp.h       ${CMAKE_CURRENT_SOURCE_DIR}/daemon/cgen/matcher/tcp.c
    ${CMAKE_CURRENT_SOURCE_DIR}/daemon/cgen/matcher/udp.h       ${CMAKE_CURRENT_SOURCE_DIR}/daemon/cgen/matcher/udp.c
    ${CMAKE_CURRENT_SOURCE_DIR}/daemon/cgen/matcher/meta.h      ${CMAKE_CURRENT_SOURCE_DIR}/daemon/cgen/matcher/meta.c
    ${CMAKE_CURRENT_SOURCE_DIR}/daemon/cgen/nf.h                ${CMAKE_CURRENT_SOURCE_DIR}/daemon/cgen/nf.c
    ${CMAKE_CURRENT_SOURCE_DIR}/daemon/cgen/printer.h           ${CMAKE_CURRENT_SOURCE_DIR}/daemon/cgen/printer.c
    ${CMAKE_CURRENT_SOURCE_DIR}/daemon/cgen/program.h           ${CMAKE_CURRENT_SOURCE_DIR}/daemon/cgen/program.c
    ${CMAKE_CURRENT_SOURCE_DIR}/daemon/cgen/reg.h
    ${CMAKE_CURRENT_SOURCE_DIR}/daemon/cgen/stub.h              ${CMAKE_CURRENT_SOURCE_DIR}/daemon/cgen/stub.c
    ${CMAKE_CURRENT_SOURCE_DIR}/daemon/cgen/swich.h             ${CMAKE_CURRENT_SOURCE_DIR}/daemon/cgen/swich.c
    ${CMAKE_CURRENT_SOURCE_DIR}/daemon/cgen/tc.h                ${CMAKE_CURRENT_SOURCE_DIR}/daemon/cgen/tc.c
    ${CMAKE_CURRENT_SOURCE_DIR}/daemon/cgen/xdp.h               ${CMAKE_CURRENT_SOURCE_DIR}/daemon/cgen/xdp.c
    ${CMAKE_CURRENT_SOURCE_DIR}/daemon/context.h                ${CMAKE_CURRENT_SOURCE_DIR}/daemon/context.c
    ${CMAKE_CURRENT_SOURCE_DIR}/daemon/xlate/cli.c
    ${CMAKE_CURRENT_SOURCE_DIR}/daemon/xlate/front.h            ${CMAKE_CURRENT_SOURCE_DIR}/daemon/xlate/front.c
    ${CMAKE_CURRENT_SOURCE_DIR}/daemon/xlate/ipt/dump.h         ${CMAKE_CURRENT_SOURCE_DIR}/daemon/xlate/ipt/dump.c
    ${CMAKE_CURRENT_SOURCE_DIR}/daemon/xlate/ipt/helpers.h
    ${CMAKE_CURRENT_SOURCE_DIR}/daemon/xlate/ipt/ipt.c
    ${CMAKE_CURRENT_SOURCE_DIR}/daemon/xlate/nft/nfgroup.h      ${CMAKE_CURRENT_SOURCE_DIR}/daemon/xlate/nft/nfgroup.c
    ${CMAKE_CURRENT_SOURCE_DIR}/daemon/xlate/nft/nfmsg.h        ${CMAKE_CURRENT_SOURCE_DIR}/daemon/xlate/nft/nfmsg.c
    ${CMAKE_CURRENT_SOURCE_DIR}/daemon/xlate/nft/nft.c
)

set_target_properties(daemon PROPERTIES OUTPUT_NAME bpfilter)

target_compile_options(daemon PRIVATE ${bf_cflags})
target_link_options(daemon PRIVATE ${bf_ldflags})
target_link_libraries(daemon
    PRIVATE
        core
        PkgConfig::nl
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
        core
)

install(
    TARGETS cli
    DESTINATION ${CMAKE_INSTALL_BINDIR}
)

#[[
    libraries
#]]
add_library(libbpfilter_static STATIC)
set_target_properties(libbpfilter_static PROPERTIES OUTPUT_NAME bpfilter)
target_compile_options(libbpfilter_static PRIVATE -fPIC)
target_link_libraries(libbpfilter_static PRIVATE core_pic lib_pic)

add_library(libbpfilter_shared SHARED)
set_target_properties(libbpfilter_shared PROPERTIES OUTPUT_NAME bpfilter)
target_compile_options(libbpfilter_shared PRIVATE -fPIC)
target_link_libraries(libbpfilter_shared PRIVATE core_pic lib_pic)

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
