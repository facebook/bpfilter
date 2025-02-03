# SPDX-License-Identifier: GPL-2.0-only
# Copyright (c) 2023 Meta Platforms, Inc. and affiliates.

set(libbpfilter_srcs
    ${CMAKE_CURRENT_SOURCE_DIR}/bpfilter.h
                                                    ${CMAKE_CURRENT_SOURCE_DIR}/cli.c
    ${CMAKE_CURRENT_SOURCE_DIR}/generic.h           ${CMAKE_CURRENT_SOURCE_DIR}/generic.c
                                                    ${CMAKE_CURRENT_SOURCE_DIR}/ipt.c
                                                    ${CMAKE_CURRENT_SOURCE_DIR}/nft.c
)

configure_file(
    ${CMAKE_SOURCE_DIR}/src/libbpfilter/bpfilter.h
    ${CMAKE_BINARY_DIR}/output/include/bpfilter/bpfilter.h
)

configure_file(
    ${CMAKE_SOURCE_DIR}/src/libbpfilter/bpfilter.pc.in
    ${CMAKE_BINARY_DIR}/output/lib/pkgconfig/bpfilter.pc
    @ONLY
)

add_library(libbpfilter SHARED
    ${libbpfilter_srcs}
)

set_target_properties(libbpfilter PROPERTIES OUTPUT_NAME bpfilter)

target_include_directories(libbpfilter
    PRIVATE
        ${CMAKE_SOURCE_DIR}/src
)

target_link_libraries(libbpfilter
    PRIVATE
        bf_global_flags
        core
)

install(TARGETS libbpfilter)

install(
    FILES ${CMAKE_SOURCE_DIR}/src/libbpfilter/bpfilter.h
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/bpfilter
)

install(
    FILES ${CMAKE_BINARY_DIR}/output/lib/pkgconfig/bpfilter.pc
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/pkgconfig
)
