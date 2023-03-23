# SPDX-License-Identifier: GPL-2.0
# Copyright (c) 2023 Meta Platforms, Inc. and affiliates.

cmake_minimum_required(VERSION 3.26)

project(bpfilter
    VERSION 0.0.1
    DESCRIPTION "BPF-based packet filtering framework"
    LANGUAGES C
)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# Include headers to the list of sources, so dependencies are re-built
# on change.
set(bpfilter_srcs
    ${CMAKE_SOURCE_DIR}/src/main.c
)

set(libbpfilter_srcs
    ${CMAKE_SOURCE_DIR}/lib/include/bpfilter.h
    ${CMAKE_SOURCE_DIR}/lib/src/ipt.c
)

set(bpfilter_cflags
    -Wall -Wextra
)

add_subdirectory(src)
add_subdirectory(lib)
