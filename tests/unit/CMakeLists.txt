# SPDX-License-Identifier: GPL-2.0
# Copyright (c) 2023 Meta Platforms, Inc. and affiliates.

enable_testing()

set(tests_unit_srcs
    list.cc
    map.cc
)

#[[
bpfilter_o can't be used here to build against the unit tests, as we need
--coverage build flag to be added. Hence, bpfilter_unit_o is defined.
]]
add_library(bpfilter_unit_o OBJECT
    ${bpfilter_daemon_srcs}
    ${bpfilter_shared_srcs}
)

target_compile_options(bpfilter_unit_o
	PRIVATE
        ${bpfilter_cflags}
        -fsanitize=address -fsanitize=undefined
        -fprofile-arcs -ftest-coverage
        $<$<CONFIG:Release>:${bpfilter_cflags_release}>
        $<$<CONFIG:Debug>:${bpfilter_cflags_debug}>
)

target_include_directories(bpfilter_unit_o
	PUBLIC
        ${CMAKE_SOURCE_DIR}/src
        ${CMAKE_SOURCE_DIR}/shared/include/bpfilter
)

target_link_options(bpfilter_unit_o
    PUBLIC
        ${bpfilter_ldflags}
        $<$<CONFIG:Release>:${bpfilter_ldflags_release}>
        $<$<CONFIG:Debug>:${bpfilter_ldflags_debug}>
)

target_link_libraries(bpfilter_unit_o
    PRIVATE
        gcov
)

add_executable(tests_unit ${tests_unit_srcs})

target_compile_options(tests_unit
    PRIVATE
        ${bpfilter_cflags}
        $<$<CONFIG:Release>:${bpfilter_cflags_release}>
        $<$<CONFIG:Debug>:${bpfilter_cflags_debug}>
)

target_link_libraries(tests_unit
    PRIVATE
        bpfilter_unit_o
        GTest::gtest_main
)

target_link_options(tests_unit
    PUBLIC
        ${bpfilter_ldflags}
        $<$<CONFIG:Release>:${bpfilter_ldflags_release}>
        $<$<CONFIG:Debug>:${bpfilter_ldflags_debug}>
)

gtest_discover_tests(tests_unit)
