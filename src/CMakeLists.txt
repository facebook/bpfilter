# SPDX-License-Identifier: GPL-2.0
# Copyright (c) 2023 Meta Platforms, Inc. and affiliates.

add_executable(bpfilter
    ${CMAKE_SOURCE_DIR}/src/main.c
    ${bpfilter_daemon_srcs}
    ${bpfilter_shared_srcs}
)

target_include_directories(bpfilter
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}
        ${CMAKE_SOURCE_DIR}/shared/include # Required for shared include files to include each other.
        ${CMAKE_SOURCE_DIR}/shared/include/bpfilter
)

target_compile_options(bpfilter
    PRIVATE
        -fPIE ${bpfilter_cflags}
        $<$<CONFIG:Release>:${bpfilter_cflags_release}>
        $<$<CONFIG:Debug>:${bpfilter_cflags_debug}>
)

target_link_options(bpfilter
    PUBLIC
        ${bpfilter_ldflags}
        $<$<CONFIG:Release>:${bpfilter_ldflags_release}>
        $<$<CONFIG:Debug>:${bpfilter_ldflags_debug}>
)

target_link_libraries(bpfilter
    PUBLIC
        bpf
)

install(
    TARGETS bpfilter
    DESTINATION ${CMAKE_INSTALL_BINDIR}
)
