# SPDX-License-Identifier: GPL-2.0
# Copyright (c) 2023 Meta Platforms, Inc. and affiliates.

add_executable(bpfilter ${bpfilter_srcs})

target_include_directories(bpfilter
    PRIVATE
        ${CMAKE_SOURCE_DIR}/include
        ${CMAKE_SOURCE_DIR}/src
)

target_compile_options(bpfilter
    PRIVATE
        -fPIE ${bpfilter_cflags}
)
