# SPDX-License-Identifier: GPL-2.0
# Copyright (c) 2023 Meta Platforms, Inc. and affiliates.

add_executable(raw raw.c)

target_compile_options(raw
    PRIVATE
        ${bpfilter_cflags}
        $<$<CONFIG:Release>:${bpfilter_cflags_release}>
        $<$<CONFIG:Debug>:${bpfilter_cflags_debug}>
)

target_include_directories(raw SYSTEM
    PRIVATE
        ${CMAKE_SOURCE_DIR}/shared/include
        ${CMAKE_SOURCE_DIR}/lib/include
)

target_link_options(raw
    PUBLIC
        ${bpfilter_ldflags}
        $<$<CONFIG:Release>:${bpfilter_ldflags_release}>
        $<$<CONFIG:Debug>:${bpfilter_ldflags_debug}>
)

target_link_libraries(raw
    PRIVATE
        libbpfilter_so
)
