# SPDX-License-Identifier: GPL-2.0-only
# Copyright (c) 2023 Meta Platforms, Inc. and affiliates.

add_library(harness EXCLUDE_FROM_ALL
    SHARED
        fake.c fake.h
        mock.c mock.h
        test.c test.h
)

target_include_directories(harness
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}
)

target_link_libraries(harness
    PUBLIC
        libbpfilter
)

add_library(mock EXCLUDE_FROM_ALL
    SHARED
        mock/btf__load_vmlinux_btf.c
        mock/isatty.c
        mock/setns.c
        mock/syscall.c
)

target_compile_options(mock PUBLIC -fPIC)

target_link_libraries(mock
    PUBLIC
        dl
        harness
)