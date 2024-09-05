# SPDX-License-Identifier: GPL-2.0-only
# Copyright (c) 2023 Meta Platforms, Inc. and affiliates.

set(libbpfilter_srcs
    ${CMAKE_CURRENT_SOURCE_DIR}/bpfilter.h
    ${CMAKE_CURRENT_SOURCE_DIR}/generic.h           ${CMAKE_CURRENT_SOURCE_DIR}/generic.c
                                                    ${CMAKE_CURRENT_SOURCE_DIR}/ipt.c
                                                    ${CMAKE_CURRENT_SOURCE_DIR}/nft.c
)

add_library(libbpfilter_a STATIC
    ${libbpfilter_srcs}
)

set_target_properties(libbpfilter_a PROPERTIES OUTPUT_NAME bpfilter)

target_include_directories(libbpfilter_a
    PRIVATE
        ${CMAKE_SOURCE_DIR}/src
)

target_link_libraries(libbpfilter_a
    PRIVATE
        bf_global_flags
        core
)

add_library(libbpfilter_so SHARED
    ${libbpfilter_srcs}
)

set_target_properties(libbpfilter_so PROPERTIES OUTPUT_NAME bpfilter)

target_include_directories(libbpfilter_so
    PRIVATE
        ${CMAKE_SOURCE_DIR}/src
)

target_compile_options(libbpfilter_so
    PRIVATE
        -fPIC
)

target_link_libraries(libbpfilter_so
    PRIVATE
        bf_global_flags
        core.pic
)

add_custom_target(libbpfilter
    ALL
    DEPENDS libbpfilter_a libbpfilter_so
    COMMENT "Compound target to build libbpfilter.a and libbpfilter.so"
)
