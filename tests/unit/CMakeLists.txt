# SPDX-License-Identifier: GPL-2.0-only
# Copyright (c) 2023 Meta Platforms, Inc. and affiliates.

# - Set property to files that should not be build.
#
# As bpfilter unit tests directly include the source file (.c) into the test
# file, it can leave to ODR violation. This issue could be fixed by excluding
# the tested files from the target sources list, which would break the
# dependencies chain (changing the source file wouldn't rebuild the tests, as
# the test target doesn't depend on it). Instead, tested source files can be
# marked as HEADER_ONLY, so they would still be part of the dependecies chain
# without being build.
#
# set_source_files_properties() will apply the HEADER_ONLY property to the
# source file but only for the targets defined in the CMakeLists.txt file it's
# called.
#
# Because the test files have the same name as the tested files, we only need
# to compare the relative file path to know whether a given source file is
# tested, hence should have the HEADER_ONLY property assigned.
#
# Usage:
#   bf_test_configure_non_build_srcs(${TARGET}
#       TESTS
#           # List of test files
#       SOURCES
#           # List of source files
#   )
#
function(bf_test_configure_non_build_srcs TARGET)
    cmake_parse_arguments(PARSE_ARGV 1 _LOCAL "" "" "TESTS;SOURCES")

    set(_test_srcs "")
    foreach(_test_src IN LISTS _LOCAL_TESTS)
        # Get absolute path to source file, and path relative to the project's
        # test directory.
        get_filename_component(_abs_test_src ${_test_src} ABSOLUTE)
        file(RELATIVE_PATH _rel_test_src ${CMAKE_CURRENT_SOURCE_DIR} ${_abs_test_src})
        list(APPEND _test_srcs "${_rel_test_src}")
    endforeach()

    foreach(_bf_src IN LISTS _LOCAL_SOURCES)
        get_source_file_property(
            IS_HEADER_ONLY ${_bf_src}
            TARGET_DIRECTORY bpfilter
            HEADER_FILE_ONLY
        )

        # Get absolute path to source file, and path relative to the project's
        # root directory.
        get_filename_component(_abs_bf_src ${_bf_src} ABSOLUTE)
        file(RELATIVE_PATH _rel_bf_src ${CMAKE_SOURCE_DIR}/src ${_abs_bf_src})

        if (${_rel_bf_src} IN_LIST _test_srcs OR IS_HEADER_ONLY)
            set_source_files_properties(${_abs_bf_src}
                PROPERTIES
                    HEADER_FILE_ONLY ON
            )
        endif()
    endforeach()
endfunction()

# - Define a new mock
#
# bpfilter uses ld's --wrap option to mock functions. --wrap will rename the
# given symbol ${SYM} as __real_${SYM}, and every call to ${SYM} will actually
# call __wrap_${SYM}. This function will add the necessary option to the
# target in order for ld to wrap the requested symbol.
#
# See https://ftp.gnu.org/old-gnu/Manuals/ld-2.9.1/html_node/ld_3.html.
#
function(bf_test_mock TARGET)
    cmake_parse_arguments(PARSE_ARGV 1 _LOCAL "" "" "FUNCTIONS")

    list(LENGTH _LOCAL_FUNCTIONS N_MOCKS)

    message(STATUS "Mocking ${N_MOCKS} functions for target '${TARGET}'")
    foreach(_function IN LISTS _LOCAL_FUNCTIONS)
        target_link_options(${TARGET}
            PUBLIC
                -Wl,--wrap=${_function}
        )
        message(VERBOSE "  - ${_function}()")
    endforeach()
endfunction()

include(ElfStubs)

enable_testing()

set(bf_test_srcs
    libbpfilter/btf.c
    libbpfilter/chain.c
    libbpfilter/flavor.c
    libbpfilter/front.c
    libbpfilter/helper.c
    libbpfilter/hook.c
    libbpfilter/list.c
    libbpfilter/matcher.c
    libbpfilter/rule.c
    libbpfilter/set.c
    libbpfilter/verdict.c
    bpfilter/opts.c
    bpfilter/cgen/cgen.c
    bpfilter/cgen/jmp.c
    bpfilter/cgen/printer.c
    bpfilter/cgen/program.c
    bpfilter/cgen/prog/map.c
    bpfilter/cgen/swich.c
    bpfilter/ctx.c
    bpfilter/xlate/nft/nft.c
)

get_target_property(libbpfilter_srcs libbpfilter SOURCES)
get_target_property(bpfilter_srcs bpfilter SOURCES)

list(REMOVE_ITEM bpfilter_srcs ${CMAKE_SOURCE_DIR}/src/bpfilter/main.c)

add_executable(unit_bin EXCLUDE_FROM_ALL
    ${CMAKE_CURRENT_SOURCE_DIR}/assert_override.h
    ${CMAKE_CURRENT_SOURCE_DIR}/main.c
    ${CMAKE_CURRENT_SOURCE_DIR}/fake.h  ${CMAKE_CURRENT_SOURCE_DIR}/fake.c
    ${CMAKE_CURRENT_SOURCE_DIR}/mock.h  ${CMAKE_CURRENT_SOURCE_DIR}/mock.c

    ${bf_test_srcs}

    ${libbpfilter_srcs}
    ${bpfilter_srcs}
)

file(MAKE_DIRECTORY ${CMAKE_BINARY_DIR}/include/bpfilter/cgen)
bf_target_add_elfstubs(unit_bin
    DIR ${CMAKE_SOURCE_DIR}/src/bpfilter/bpf
    SYM_PREFIX "_bf_rawstubs_"
    DECL_HDR_PATH ${CMAKE_CURRENT_BINARY_DIR}/include/bpfilter/cgen/rawstubs.h
    STUBS
        "parse_ipv6_eh"
        "parse_ipv6_nh"
        "update_counters"
        "log"
)

bf_test_configure_non_build_srcs(unit_bin
    TESTS
        ${bf_test_srcs}
    SOURCES
        ${libbpfilter_srcs}
        ${bpfilter_srcs}
)

set_source_files_properties(${bf_test_srcs} ${core_srcs} ${bpfilter_srcs} ${libbpfilter_srcs}
    PROPERTIES
        COMPILE_OPTIONS "-ftest-coverage;-fprofile-arcs;-fprofile-abs-path"
)

target_compile_options(unit_bin
    PRIVATE
        -include ${CMAKE_CURRENT_SOURCE_DIR}/assert_override.h
        -fno-inline-small-functions     # Prevent inlining that would be -Wl,wrap (e.g. bf_ctx_token())
)

target_include_directories(unit_bin
    PRIVATE
        ${CMAKE_SOURCE_DIR}/src/libbpfilter/include
        ${CMAKE_SOURCE_DIR}/src
        ${CMAKE_SOURCE_DIR}/src/bpfilter
        ${CMAKE_SOURCE_DIR}/src/external/include
        ${CMAKE_CURRENT_SOURCE_DIR}
        ${CMAKE_BINARY_DIR}/src/bpfilter/include
        ${CMAKE_CURRENT_BINARY_DIR}/include
)

target_link_libraries(unit_bin
    PRIVATE
        bf_global_flags
        harness
        gcov
)

bf_test_mock(unit_bin
    FUNCTIONS
        bf_bpf
        bf_bpf_map_create
        bf_bpf_obj_get
        bf_btf_get_id
        bf_ctx_token
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

add_custom_target(unit
    COMMAND $<TARGET_FILE:unit_bin>
    COMMENT "Running unit tests"
)

if (NOT ${NO_DOCS})
    include(ProcessorCount)
    find_program(LCOV_BIN lcov REQUIRED)

    ProcessorCount(N)
    if(N EQUAL 0)
        set(N 1)
    endif()

    file(MAKE_DIRECTORY ${CMAKE_BINARY_DIR}/output/tests)

    add_custom_command(TARGET unit
        POST_BUILD
        COMMAND
            ${CMAKE_COMMAND}
                -E make_directory
                ${CMAKE_BINARY_DIR}/output/tests
        COMMAND
            ${LCOV_BIN}
                --capture
                --directory ${CMAKE_BINARY_DIR}
                --output-file ${CMAKE_CURRENT_BINARY_DIR}/lcov.out
                --parallel ${N}
                --quiet
        # Only keep the coverage for bpfilter's source files, not the tests.
        COMMAND
            ${LCOV_BIN}
                --output-file ${CMAKE_BINARY_DIR}/output/tests/lcov.out
                --extract ${CMAKE_CURRENT_BINARY_DIR}/lcov.out
                --ignore-errors unused
                --parallel ${N}
                --quiet
                "${CMAKE_SOURCE_DIR}/src/libbpfilter\\*"
                "${CMAKE_SOURCE_DIR}/src/bpfilter\\*"
        COMMAND
            ${LCOV_BIN}
                --summary ${CMAKE_BINARY_DIR}/output/tests/lcov.out
        BYPRODUCTS ${CMAKE_BINARY_DIR}/output/tests/lcov.out
        COMMENT "Generate the lcov.out summary file"
    )
endif ()
