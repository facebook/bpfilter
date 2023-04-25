# SPDX-License-Identifier: GPL-2.0
# Copyright (c) 2023 Meta Platforms, Inc. and affiliates.

add_library(libbpfilter_o OBJECT
    ${bpfilter_library_srcs}
    ${bpfilter_shared_srcs}
)

#[[
libbpfilter_o is the main target compiling libbpfilter's source files.
The objects files are used to build an archive (libbpfilter_a) and a
shared library (libbpfilter_so).
]]

target_include_directories(libbpfilter_o
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/include
        ${CMAKE_CURRENT_SOURCE_DIR}/source
        ${CMAKE_SOURCE_DIR}/shared/include # For headers included in header files
        ${CMAKE_SOURCE_DIR}/shared/include/bpfilter # For headers included in C source files
)

target_compile_options(libbpfilter_o
    PRIVATE
        -fPIC ${bpfilter_cflags}
        $<$<CONFIG:Release>:${bpfilter_cflags_release}>
        $<$<CONFIG:Debug>:${bpfilter_cflags_debug}>
)

add_library(libbpfilter_a STATIC $<TARGET_OBJECTS:libbpfilter_o>)
set_target_properties(libbpfilter_a PROPERTIES OUTPUT_NAME bpfilter)

add_library(libbpfilter_so SHARED $<TARGET_OBJECTS:libbpfilter_o>)
set_target_properties(libbpfilter_so PROPERTIES OUTPUT_NAME bpfilter)

add_custom_target(libbpfilter
    ALL
    DEPENDS libbpfilter_a libbpfilter_so
    COMMENT "Compound target to build libbpfilter.a and libbpfilter.so"
)
