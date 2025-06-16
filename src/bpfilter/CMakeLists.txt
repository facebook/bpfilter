# SPDX-License-Identifier: GPL-2.0-only
# Copyright (c) 2023 Meta Platforms, Inc. and affiliates.

find_package(PkgConfig REQUIRED)
pkg_check_modules(nl REQUIRED IMPORTED_TARGET libnl-3.0)

include(ElfStubs)

configure_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/bpfilter.service.in
    ${CMAKE_BINARY_DIR}/output/usr/lib/systemd/system/bpfilter.service
    @ONLY
)

add_executable(bpfilter
    ${CMAKE_CURRENT_SOURCE_DIR}/main.c
    ${CMAKE_BINARY_DIR}/include/version.h
    ${CMAKE_CURRENT_SOURCE_DIR}/opts.h                   ${CMAKE_CURRENT_SOURCE_DIR}/opts.c
    ${CMAKE_CURRENT_SOURCE_DIR}/cgen/cgen.h              ${CMAKE_CURRENT_SOURCE_DIR}/cgen/cgen.c
    ${CMAKE_CURRENT_SOURCE_DIR}/cgen/cgroup.h            ${CMAKE_CURRENT_SOURCE_DIR}/cgen/cgroup.c
    ${CMAKE_CURRENT_SOURCE_DIR}/cgen/dump.h              ${CMAKE_CURRENT_SOURCE_DIR}/cgen/dump.c
    ${CMAKE_CURRENT_SOURCE_DIR}/cgen/elfstub.h           ${CMAKE_CURRENT_SOURCE_DIR}/cgen/elfstub.c
    ${CMAKE_CURRENT_SOURCE_DIR}/cgen/fixup.h             ${CMAKE_CURRENT_SOURCE_DIR}/cgen/fixup.c
    ${CMAKE_CURRENT_SOURCE_DIR}/cgen/jmp.h               ${CMAKE_CURRENT_SOURCE_DIR}/cgen/jmp.c
    ${CMAKE_CURRENT_SOURCE_DIR}/cgen/matcher/ip4.h       ${CMAKE_CURRENT_SOURCE_DIR}/cgen/matcher/ip4.c
    ${CMAKE_CURRENT_SOURCE_DIR}/cgen/matcher/ip6.h       ${CMAKE_CURRENT_SOURCE_DIR}/cgen/matcher/ip6.c
    ${CMAKE_CURRENT_SOURCE_DIR}/cgen/matcher/set.h       ${CMAKE_CURRENT_SOURCE_DIR}/cgen/matcher/set.c
    ${CMAKE_CURRENT_SOURCE_DIR}/cgen/matcher/tcp.h       ${CMAKE_CURRENT_SOURCE_DIR}/cgen/matcher/tcp.c
    ${CMAKE_CURRENT_SOURCE_DIR}/cgen/matcher/udp.h       ${CMAKE_CURRENT_SOURCE_DIR}/cgen/matcher/udp.c
    ${CMAKE_CURRENT_SOURCE_DIR}/cgen/matcher/meta.h      ${CMAKE_CURRENT_SOURCE_DIR}/cgen/matcher/meta.c
    ${CMAKE_CURRENT_SOURCE_DIR}/cgen/matcher/icmp.h      ${CMAKE_CURRENT_SOURCE_DIR}/cgen/matcher/icmp.c
    ${CMAKE_CURRENT_SOURCE_DIR}/cgen/nf.h                ${CMAKE_CURRENT_SOURCE_DIR}/cgen/nf.c
    ${CMAKE_CURRENT_SOURCE_DIR}/cgen/printer.h           ${CMAKE_CURRENT_SOURCE_DIR}/cgen/printer.c
    ${CMAKE_CURRENT_SOURCE_DIR}/cgen/program.h           ${CMAKE_CURRENT_SOURCE_DIR}/cgen/program.c
    ${CMAKE_CURRENT_SOURCE_DIR}/cgen/prog/link.h         ${CMAKE_CURRENT_SOURCE_DIR}/cgen/prog/link.c
    ${CMAKE_CURRENT_SOURCE_DIR}/cgen/prog/map.h          ${CMAKE_CURRENT_SOURCE_DIR}/cgen/prog/map.c
    ${CMAKE_CURRENT_SOURCE_DIR}/cgen/runtime.h
    ${CMAKE_CURRENT_SOURCE_DIR}/cgen/stub.h              ${CMAKE_CURRENT_SOURCE_DIR}/cgen/stub.c
    ${CMAKE_CURRENT_SOURCE_DIR}/cgen/swich.h             ${CMAKE_CURRENT_SOURCE_DIR}/cgen/swich.c
    ${CMAKE_CURRENT_SOURCE_DIR}/cgen/tc.h                ${CMAKE_CURRENT_SOURCE_DIR}/cgen/tc.c
    ${CMAKE_CURRENT_SOURCE_DIR}/cgen/xdp.h               ${CMAKE_CURRENT_SOURCE_DIR}/cgen/xdp.c
    ${CMAKE_CURRENT_SOURCE_DIR}/ctx.h                    ${CMAKE_CURRENT_SOURCE_DIR}/ctx.c
    ${CMAKE_CURRENT_SOURCE_DIR}/xlate/cli.c
    ${CMAKE_CURRENT_SOURCE_DIR}/xlate/front.h            ${CMAKE_CURRENT_SOURCE_DIR}/xlate/front.c
    ${CMAKE_CURRENT_SOURCE_DIR}/xlate/ipt/dump.h         ${CMAKE_CURRENT_SOURCE_DIR}/xlate/ipt/dump.c
    ${CMAKE_CURRENT_SOURCE_DIR}/xlate/ipt/helpers.h
    ${CMAKE_CURRENT_SOURCE_DIR}/xlate/ipt/ipt.c
    # Do not build those until the nft front-end is fixed.
    # ${CMAKE_CURRENT_SOURCE_DIR}/xlate/nft/nfgroup.h      ${CMAKE_CURRENT_SOURCE_DIR}/xlate/nft/nfgroup.c
    # ${CMAKE_CURRENT_SOURCE_DIR}/xlate/nft/nfmsg.h        ${CMAKE_CURRENT_SOURCE_DIR}/xlate/nft/nfmsg.c
    ${CMAKE_CURRENT_SOURCE_DIR}/xlate/nft/nft.c

    ${CMAKE_SOURCE_DIR}/src/external/disasm.h            ${CMAKE_SOURCE_DIR}/src/external/disasm.c
    ${CMAKE_SOURCE_DIR}/src/external/murmur3.h           ${CMAKE_SOURCE_DIR}/src/external/murmur3.c
)

file(MAKE_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/include/bpfilter/cgen)
bf_target_add_elfstubs(bpfilter
    DIR ${CMAKE_CURRENT_SOURCE_DIR}/bpf
    SYM_PREFIX "_bf_rawstubs_"
    DECL_HDR_PATH ${CMAKE_CURRENT_BINARY_DIR}/include/bpfilter/cgen/rawstubs.h
    STUBS
        "parse_ipv6_eh"
        "update_counters"
)

target_compile_definitions(bpfilter
    PRIVATE
        BF_CONTACT="${BF_CONTACT}"
)

target_include_directories(bpfilter
    PUBLIC
        ${CMAKE_SOURCE_DIR}/src
        ${CMAKE_BINARY_DIR}/include
        ${CMAKE_CURRENT_BINARY_DIR}/include
)

target_link_libraries(bpfilter
    PRIVATE
        bf_global_flags
        core
        PkgConfig::nl
)

install(TARGETS bpfilter
    DESTINATION ${CMAKE_INSTALL_SBINDIR}
)

install(
    FILES ${CMAKE_BINARY_DIR}/output/usr/lib/systemd/system/bpfilter.service
    DESTINATION ${CMAKE_INSTALL_PREFIX}/lib/systemd/system
)
