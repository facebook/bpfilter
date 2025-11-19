# SPDX-License-Identifier: GPL-2.0-only
# Copyright (c) 2023 Meta Platforms, Inc. and affiliates.

add_dependencies(test_bin libbpfilter)
get_target_property(lib_gen_inc_dir libbpfilter BINARY_DIR)

add_test(NAME "integration.pedantic.c"
    COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/pedantic_c.sh
)

set_tests_properties("integration.pedantic.c" PROPERTIES
    LABELS "integration"
    ENVIRONMENT "ROOT_DIR=${CMAKE_SOURCE_DIR};BUILD_DIR=${CMAKE_BINARY_DIR};GEN_INC_DIR=${lib_gen_inc_dir}/include"
)

add_test(NAME "integration.pedantic.cpp"
    COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/pedantic_cpp.sh
)

set_tests_properties("integration.pedantic.cpp" PROPERTIES
    LABELS "integration"
    ENVIRONMENT "ROOT_DIR=${CMAKE_SOURCE_DIR};BUILD_DIR=${CMAKE_BINARY_DIR};GEN_INC_DIR=${lib_gen_inc_dir}/include"
)
