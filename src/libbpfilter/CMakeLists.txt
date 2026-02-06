# SPDX-License-Identifier: GPL-2.0-only
# Copyright (c) 2023 Meta Platforms, Inc. and affiliates.

find_package(PkgConfig REQUIRED)
pkg_check_modules(bpf REQUIRED IMPORTED_TARGET libbpf)

set(libbpfilter_srcs
    # Public interface
    ${CMAKE_CURRENT_SOURCE_DIR}/include/bpfilter/bpfilter.h
    ${CMAKE_CURRENT_SOURCE_DIR}/include/bpfilter/bpf.h
    ${CMAKE_CURRENT_SOURCE_DIR}/include/bpfilter/bpf_types.h
    ${CMAKE_CURRENT_SOURCE_DIR}/include/bpfilter/btf.h
    ${CMAKE_CURRENT_SOURCE_DIR}/include/bpfilter/chain.h
    ${CMAKE_CURRENT_SOURCE_DIR}/include/bpfilter/counter.h
    ${CMAKE_CURRENT_SOURCE_DIR}/include/bpfilter/dump.h
    ${CMAKE_CURRENT_SOURCE_DIR}/include/bpfilter/dynbuf.h
    ${CMAKE_CURRENT_SOURCE_DIR}/include/bpfilter/flavor.h
    ${CMAKE_CURRENT_SOURCE_DIR}/include/bpfilter/front.h
    ${CMAKE_CURRENT_SOURCE_DIR}/include/bpfilter/helper.h
    ${CMAKE_CURRENT_SOURCE_DIR}/include/bpfilter/hook.h
    ${CMAKE_CURRENT_SOURCE_DIR}/include/bpfilter/if.h
    ${CMAKE_CURRENT_SOURCE_DIR}/include/bpfilter/io.h
    ${CMAKE_CURRENT_SOURCE_DIR}/include/bpfilter/list.h
    ${CMAKE_CURRENT_SOURCE_DIR}/include/bpfilter/logger.h
    ${CMAKE_CURRENT_SOURCE_DIR}/include/bpfilter/matcher.h
    ${CMAKE_CURRENT_SOURCE_DIR}/include/bpfilter/ns.h
    ${CMAKE_CURRENT_SOURCE_DIR}/include/bpfilter/pack.h
    ${CMAKE_CURRENT_SOURCE_DIR}/include/bpfilter/request.h
    ${CMAKE_CURRENT_SOURCE_DIR}/include/bpfilter/response.h
    ${CMAKE_CURRENT_SOURCE_DIR}/include/bpfilter/rule.h
    ${CMAKE_CURRENT_SOURCE_DIR}/include/bpfilter/runtime.h
    ${CMAKE_CURRENT_SOURCE_DIR}/include/bpfilter/set.h
    ${CMAKE_CURRENT_SOURCE_DIR}/include/bpfilter/verdict.h

    # Private sources and headers
    ${CMAKE_CURRENT_SOURCE_DIR}/bpf.c
    ${CMAKE_CURRENT_SOURCE_DIR}/btf.c
    ${CMAKE_CURRENT_SOURCE_DIR}/chain.c
    ${CMAKE_CURRENT_SOURCE_DIR}/cli.c
    ${CMAKE_CURRENT_SOURCE_DIR}/counter.c
    ${CMAKE_CURRENT_SOURCE_DIR}/dump.c
    ${CMAKE_CURRENT_SOURCE_DIR}/dynbuf.c
    ${CMAKE_CURRENT_SOURCE_DIR}/flavor.c
    ${CMAKE_CURRENT_SOURCE_DIR}/front.c
    ${CMAKE_CURRENT_SOURCE_DIR}/helper.c
    ${CMAKE_CURRENT_SOURCE_DIR}/hook.c
    ${CMAKE_CURRENT_SOURCE_DIR}/if.c
    ${CMAKE_CURRENT_SOURCE_DIR}/io.c
    ${CMAKE_CURRENT_SOURCE_DIR}/ipt.c
    ${CMAKE_CURRENT_SOURCE_DIR}/list.c
    ${CMAKE_CURRENT_SOURCE_DIR}/logger.c
    ${CMAKE_CURRENT_SOURCE_DIR}/matcher.c
    ${CMAKE_CURRENT_SOURCE_DIR}/nft.c
    ${CMAKE_CURRENT_SOURCE_DIR}/pack.c
    ${CMAKE_CURRENT_SOURCE_DIR}/ns.c
    ${CMAKE_CURRENT_SOURCE_DIR}/request.c
    ${CMAKE_CURRENT_SOURCE_DIR}/response.c
    ${CMAKE_CURRENT_SOURCE_DIR}/rule.c
    ${CMAKE_CURRENT_SOURCE_DIR}/set.c
    ${CMAKE_CURRENT_SOURCE_DIR}/verdict.c
    ${CMAKE_CURRENT_SOURCE_DIR}/version.c

    # External
    ${CMAKE_SOURCE_DIR}/src/external/include/mpack.h
    ${CMAKE_SOURCE_DIR}/src/external/mpack.c
)

configure_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/bpfilter.pc.in
    ${CMAKE_BINARY_DIR}/output/lib/pkgconfig/bpfilter.pc
    @ONLY
)

configure_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/include/bpfilter/version.h.in
    ${CMAKE_CURRENT_BINARY_DIR}/include/bpfilter/version.h
    @ONLY
)

add_library(libbpfilter
    SHARED
        ${libbpfilter_srcs}
)

target_compile_definitions(libbpfilter
    PRIVATE
        # MPack should use the C standard library API
        MPACK_STDLIB
)

target_include_directories(libbpfilter
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}
        ${CMAKE_SOURCE_DIR}/src/external/include
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/include
        ${CMAKE_CURRENT_BINARY_DIR}/include
)

target_link_libraries(libbpfilter
    PRIVATE
        bf_global_flags
        m
    PUBLIC
        PkgConfig::bpf
)

set_target_properties(libbpfilter PROPERTIES OUTPUT_NAME bpfilter)
set_target_properties(libbpfilter PROPERTIES VERSION ${PROJECT_VERSION} SOVERSION ${PROJECT_VERSION_MAJOR})

install(TARGETS libbpfilter)

install(
    DIRECTORY
        ${CMAKE_CURRENT_SOURCE_DIR}/include/bpfilter
        ${CMAKE_CURRENT_BINARY_DIR}/include/bpfilter
    TYPE INCLUDE
)

install(
    FILES ${CMAKE_BINARY_DIR}/output/lib/pkgconfig/bpfilter.pc
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/pkgconfig
)
