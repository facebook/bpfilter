# SPDX-License-Identifier: GPL-2.0-only
# Copyright (c) 2023 Meta Platforms, Inc. and affiliates.

include(ElfStubs)

configure_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/bpfilter.service.in
    ${CMAKE_BINARY_DIR}/output/usr/lib/systemd/system/bpfilter.service
    @ONLY
)

add_executable(bpfilter
    ${CMAKE_CURRENT_SOURCE_DIR}/main.c
    ${CMAKE_CURRENT_SOURCE_DIR}/cgen/cgen.h              ${CMAKE_CURRENT_SOURCE_DIR}/cgen/cgen.c
    ${CMAKE_CURRENT_SOURCE_DIR}/cgen/cgroup_skb.h        ${CMAKE_CURRENT_SOURCE_DIR}/cgen/cgroup_skb.c
    ${CMAKE_CURRENT_SOURCE_DIR}/cgen/cgroup_sock_addr.h  ${CMAKE_CURRENT_SOURCE_DIR}/cgen/cgroup_sock_addr.c
    ${CMAKE_CURRENT_SOURCE_DIR}/cgen/dump.h              ${CMAKE_CURRENT_SOURCE_DIR}/cgen/dump.c
    ${CMAKE_CURRENT_SOURCE_DIR}/cgen/elfstub.h           ${CMAKE_CURRENT_SOURCE_DIR}/cgen/elfstub.c
    ${CMAKE_CURRENT_SOURCE_DIR}/cgen/fixup.h             ${CMAKE_CURRENT_SOURCE_DIR}/cgen/fixup.c
    ${CMAKE_CURRENT_SOURCE_DIR}/cgen/handle.h            ${CMAKE_CURRENT_SOURCE_DIR}/cgen/handle.c
    ${CMAKE_CURRENT_SOURCE_DIR}/cgen/jmp.h               ${CMAKE_CURRENT_SOURCE_DIR}/cgen/jmp.c
    ${CMAKE_CURRENT_SOURCE_DIR}/cgen/matcher/cmp.h       ${CMAKE_CURRENT_SOURCE_DIR}/cgen/matcher/cmp.c
    ${CMAKE_CURRENT_SOURCE_DIR}/cgen/matcher/meta.h      ${CMAKE_CURRENT_SOURCE_DIR}/cgen/matcher/meta.c
    ${CMAKE_CURRENT_SOURCE_DIR}/cgen/matcher/packet.h    ${CMAKE_CURRENT_SOURCE_DIR}/cgen/matcher/packet.c
    ${CMAKE_CURRENT_SOURCE_DIR}/cgen/matcher/set.h       ${CMAKE_CURRENT_SOURCE_DIR}/cgen/matcher/set.c
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
    ${CMAKE_CURRENT_SOURCE_DIR}/xlate.c

    ${CMAKE_SOURCE_DIR}/src/external/include/disasm.h   ${CMAKE_SOURCE_DIR}/src/external/disasm.c
)

file(MAKE_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/include/cgen)
bf_target_add_elfstubs(bpfilter
    DIR ${CMAKE_CURRENT_SOURCE_DIR}/bpf
    SYM_PREFIX "_bf_rawstubs_"
    DECL_HDR_PATH ${CMAKE_CURRENT_BINARY_DIR}/include/cgen/rawstubs.h
    STUBS
        "parse_ipv6_eh"
        "parse_ipv6_nh"
        "update_counters"
        "pkt_log"
        "flow_hash"
)

target_compile_definitions(bpfilter
    PRIVATE
        BF_CONTACT="${BF_CONTACT}"
)

target_include_directories(bpfilter
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}
        ${CMAKE_CURRENT_BINARY_DIR}/include
        ${CMAKE_SOURCE_DIR}/src/external/include
)

target_link_libraries(bpfilter
    PRIVATE
        bf_global_flags
        libbpfilter
)

install(TARGETS bpfilter
    DESTINATION ${CMAKE_INSTALL_SBINDIR}
)

install(
    FILES ${CMAKE_BINARY_DIR}/output/usr/lib/systemd/system/bpfilter.service
    DESTINATION ${CMAKE_INSTALL_PREFIX}/lib/systemd/system
)
