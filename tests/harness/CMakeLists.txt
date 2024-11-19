# SPDX-License-Identifier: GPL-2.0-only
# Copyright (c) 2023 Meta Platforms, Inc. and affiliates.

# - Define a new mock
#
# bpfilter uses ld's --wrap option to mock functions. --wrap will rename the
# given symbol ${SYM} as __real_${SYM}, and every call to ${SYM} will actually
# call __wrap_${SYM}. This function will had the necessary option to the
# target in order for ld to wrap the requested symbol.
#
# See https://ftp.gnu.org/old-gnu/Manuals/ld-2.9.1/html_node/ld_3.html.
#
function(bf_test_mock TARGET)
cmake_parse_arguments(PARSE_ARGV 1 _LOCAL "" "" "FUNCTIONS")

message(STATUS "Mocking the following function(s):")
foreach(_function IN LISTS _LOCAL_FUNCTIONS)
    target_link_options(${TARGET}
        PUBLIC
            -Wl,--wrap=${_function}
    )
    message(STATUS "  ${_function}()")
endforeach()
endfunction()

add_library(harness
    STATIC
        ${CMAKE_CURRENT_SOURCE_DIR}/daemon.h    ${CMAKE_CURRENT_SOURCE_DIR}/daemon.c
        ${CMAKE_CURRENT_SOURCE_DIR}/filters.h   ${CMAKE_CURRENT_SOURCE_DIR}/filters.c
        ${CMAKE_CURRENT_SOURCE_DIR}/mock.h      ${CMAKE_CURRENT_SOURCE_DIR}/mock.c
        ${CMAKE_CURRENT_SOURCE_DIR}/process.h   ${CMAKE_CURRENT_SOURCE_DIR}/process.c
        ${CMAKE_CURRENT_SOURCE_DIR}/prog.h      ${CMAKE_CURRENT_SOURCE_DIR}/prog.c
        ${CMAKE_CURRENT_SOURCE_DIR}/sym.h       ${CMAKE_CURRENT_SOURCE_DIR}/sym.c
        ${CMAKE_CURRENT_SOURCE_DIR}/test.h      ${CMAKE_CURRENT_SOURCE_DIR}/test.c
)

target_include_directories(harness
    PUBLIC
        ${CMAKE_SOURCE_DIR}/tests
)

target_link_libraries(harness
    PUBLIC
        bf_global_flags
        core
        PkgConfig::bpf
        PkgConfig::cmocka
        PkgConfig::elf
        PkgConfig::nl
)

bf_test_mock(harness
    FUNCTIONS
        bf_bpf
        bf_bpf_obj_get
        btf__load_vmlinux_btf
        calloc
        malloc
        nlmsg_alloc
        nlmsg_append
        nlmsg_convert
        nlmsg_put
        open
        read
        snprintf
        vsnprintf
        write
)
