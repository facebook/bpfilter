# SPDX-License-Identifier: GPL-2.0
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
        file(RELATIVE_PATH _rel_bf_src ${CMAKE_SOURCE_DIR} ${_abs_bf_src})

        if (${_rel_bf_src} IN_LIST _test_srcs)
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
            PRIVATE
                -Wl,--wrap=${_function}
        )
        message(STATUS "  ${_function}()")
    endforeach()
endfunction()

enable_testing()

set(bf_test_srcs
    src/core/context.c
    src/core/flavor.c
    src/core/helper.c
    src/core/hook.c
    src/core/list.c
    src/core/marsh.c
    src/core/target.c
    src/generator/codegen.c
    src/generator/nf.c
)

add_executable(tests_unit
    assert_override.h

    harness/main.c
    harness/cmocka.h
    harness/elf.c harness/elf.h
    harness/helper.c harness/helper.h
    harness/mock.c harness/mock.h
    harness/test.c harness/test.h

    ${bf_test_srcs}

    ${bpfilter_daemon_srcs}
    ${bpfilter_shared_srcs}
)

bf_test_configure_non_build_srcs(tests_unit
    TESTS
        ${bf_test_srcs}
    SOURCES
        ${bpfilter_daemon_srcs}
        ${bpfilter_shared_srcs}
)

# The unit tests executable needs PIC disabled for test auto-discovery to work.
set_property(TARGET tests_unit PROPERTY POSITION_INDEPENDENT_CODE FALSE)

target_compile_options(tests_unit
    PRIVATE
        -fprofile-arcs -ftest-coverage
        -include ${CMAKE_CURRENT_SOURCE_DIR}/assert_override.h
        ${bpfilter_cflags}
        $<$<CONFIG:Release>:${bpfilter_cflags_release}>
        $<$<CONFIG:Debug>:${bpfilter_cflags_debug}>
)

target_include_directories(tests_unit
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}
        ${CMAKE_SOURCE_DIR}/src
        ${CMAKE_SOURCE_DIR}/shared/include
        ${CMAKE_SOURCE_DIR}/shared/include/bpfilter
)

target_link_libraries(tests_unit
    PRIVATE
        PkgConfig::bpf
        gcov
        PkgConfig::cmocka
        PkgConfig::elf
)

target_link_options(tests_unit
    PUBLIC
        ${bpfilter_ldflags}
        $<$<CONFIG:Release>:${bpfilter_ldflags_release}>
        $<$<CONFIG:Debug>:${bpfilter_ldflags_debug}>
)

bf_test_mock(tests_unit
    FUNCTIONS
        calloc
        malloc
        open
        read
        write
)

add_custom_target(test
    COMMAND $<TARGET_FILE:tests_unit> --verbose --xml=test-report.xml
    DEPENDS tests_unit
    COMMENT "Running unit tests"
)
