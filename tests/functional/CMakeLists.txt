# SPDX-License-Identifier: GPL-2.0-only
# Copyright (c) 2023 Meta Platforms, Inc. and affiliates.

find_package(cmocka REQUIRED)

function(bf_add_functional_test SOURCE)
    set(source_wo_ext ${SOURCE})
    cmake_path(REMOVE_EXTENSION source_wo_ext)
    string(REPLACE "/" "." target_suffix "${source_wo_ext}")
    set(target_name "functional.${target_suffix}")

    add_executable(${target_name} EXCLUDE_FROM_ALL ${SOURCE})

    target_compile_options(${target_name}
        PRIVATE
            -std=c++20
    )

    target_link_libraries(${target_name}
        PRIVATE
            bf_global_flags_cxx
            libbpfilter
            harness
            harness_cxx
            cmocka
    )

    add_dependencies(functional_bin ${target_name})

    add_test(NAME ${target_name}
        COMMAND ${CMAKE_SOURCE_DIR}/tools/asroot $<TARGET_FILE:${target_name}>
    )

    set_tests_properties(${target_name}
        PROPERTIES
            LABELS "functional"
            ENVIRONMENT "PATH=${CMAKE_BINARY_DIR}/output/sbin:$ENV{PATH}"
    )
endfunction()

add_custom_target(functional_bin
    DEPENDS libbpfilter bpfilter harness_cxx harness
)

add_custom_target(functional
    COMMAND ${CMAKE_CTEST_COMMAND} --output-on-failure -L functional
    DEPENDS functional_bin
)

bf_add_functional_test(matchers/icmp_code.cpp)
