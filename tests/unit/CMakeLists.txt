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
        # Get absolute path to source file, and path relative to the project's
        # root directory.
        get_filename_component(_abs_bf_src ${_bf_src} ABSOLUTE)
        file(RELATIVE_PATH _rel_bf_src ${CMAKE_SOURCE_DIR}/src ${_abs_bf_src})

        if (${_rel_bf_src} IN_LIST _test_srcs)
            set_source_files_properties(${_abs_bf_src}
                PROPERTIES
                    HEADER_FILE_ONLY ON
            )
        endif()
    endforeach()
endfunction()

enable_testing()

set(bf_test_srcs
    core/opts.c
    core/btf.c
    core/flavor.c
    core/front.c
    core/helper.c
    core/hook.c
    core/list.c
    core/marsh.c
    core/matcher.c
    core/rule.c
    core/verdict.c
    bpfilter/cgen/cgen.c
    bpfilter/cgen/jmp.c
    bpfilter/cgen/printer.c
    bpfilter/cgen/program.c
    bpfilter/cgen/prog/map.c
    bpfilter/cgen/swich.c
    bpfilter/ctx.c
    bpfilter/xlate/nft/nft.c
    bpfilter/xlate/nft/nfmsg.c
    bpfilter/xlate/nft/nfgroup.c
)

get_target_property(core_srcs core SOURCES)
get_target_property(bpfilter_srcs bpfilter SOURCES)
get_target_property(lib_srcs libbpfilter SOURCES)

list(REMOVE_ITEM bpfilter_srcs ${CMAKE_SOURCE_DIR}/src/bpfilter/main.c)

add_executable(unit_bin
    ${CMAKE_CURRENT_SOURCE_DIR}/assert_override.h
    ${CMAKE_CURRENT_SOURCE_DIR}/main.c
    ${CMAKE_CURRENT_SOURCE_DIR}/fake.h  ${CMAKE_CURRENT_SOURCE_DIR}/fake.c

    ${bf_test_srcs}

    ${core_srcs}
    ${bpfilter_srcs}
    ${lib_srcs}
)

bf_test_configure_non_build_srcs(unit_bin
    TESTS
        ${bf_test_srcs}
    SOURCES
        ${core_srcs}
        ${bpfilter_srcs}
        ${lib_srcs}
)

set_source_files_properties(${bf_test_srcs} ${core_srcs} ${bpfilter_srcs} ${lib_srcs}
    PROPERTIES
        COMPILE_OPTIONS "-ftest-coverage;-fprofile-arcs"
)

target_compile_options(unit_bin
    PRIVATE
        -include ${CMAKE_CURRENT_SOURCE_DIR}/assert_override.h
)

target_include_directories(unit_bin
    PRIVATE
        ${CMAKE_SOURCE_DIR}/src         # First look for headers in src/
        ${CMAKE_CURRENT_SOURCE_DIR}     # Then use overrides in tests/units
        ${CMAKE_BINARY_DIR}/include
)

target_link_libraries(unit_bin
    PRIVATE
        bf_global_flags
        harness
        gcov
)

add_custom_target(test
    COMMAND
        $<TARGET_FILE:unit_bin>
    DEPENDS
        unit_bin
    COMMENT "Running tests"
)

if (NOT ${NO_DOCS})
    find_program(LCOV_BIN lcov REQUIRED)

    add_custom_command(TARGET test
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
        # Only keep the coverage for bpfilter's source files, not the tests.
        COMMAND
            ${LCOV_BIN}
                --output-file ${CMAKE_BINARY_DIR}/output/tests/lcov.out
                --extract ${CMAKE_CURRENT_BINARY_DIR}/lcov.out
                --ignore-errors unused
                "${CMAKE_SOURCE_DIR}/src/\\*"
        COMMENT "Generate the lcov.out summary file"
    )
endif ()
