# SPDX-License-Identifier: GPL-2.0-only
# Copyright (c) 2026 Meta Platforms, Inc. and affiliates.

set(CMAKE_C_COMPILER clang)
set(CMAKE_CXX_COMPILER clang++)

add_executable(fuzz_parser
    ${CMAKE_CURRENT_SOURCE_DIR}/fuzz_parser.c
    ${CMAKE_SOURCE_DIR}/src/bfcli/helper.c
    ${CMAKE_SOURCE_DIR}/src/bfcli/ruleset.c
    ${CMAKE_BINARY_DIR}/src/bfcli/generated/parser.c
    ${CMAKE_BINARY_DIR}/src/bfcli/generated/lexer.c
)

target_compile_options(fuzz_parser
    PRIVATE
        -g
        -fsanitize=fuzzer,address,undefined
        -fno-omit-frame-pointer
)

target_compile_definitions(fuzz_parser
    PRIVATE
        "YY_READ_BUF_SIZE=(yy_read_buf_size)"
)

target_include_directories(fuzz_parser
    PRIVATE
        ${CMAKE_SOURCE_DIR}/src/bfcli
        ${CMAKE_SOURCE_DIR}/src/external
        ${CMAKE_BINARY_DIR}/src/bfcli/include
)

target_link_options(fuzz_parser
    PRIVATE
        -fsanitize=fuzzer,address,undefined
)

target_link_libraries(fuzz_parser
    PRIVATE
        libbpfilter
)

add_dependencies(fuzz_parser bfcli_parser bfcli_lexer)

file(MAKE_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/corpus)
file(MAKE_DIRECTORY ${CMAKE_BINARY_DIR}/findings)

add_test(NAME "fuzzing.parser"
    COMMAND $<TARGET_FILE:fuzz_parser>
        -artifact_prefix=${CMAKE_CURRENT_BINARY_DIR}/findings/
        -max_total_time=60
        -print_final_stats=1
        -only_ascii=1
        -close_fd_mask=3
        -dict=${CMAKE_CURRENT_SOURCE_DIR}/keywords.dict
        -max_len=16384
        -artifact_prefix=${CMAKE_BINARY_DIR}/findings
        ${CMAKE_CURRENT_BINARY_DIR}/corpus
        ${CMAKE_CURRENT_SOURCE_DIR}/corpus
)

set_tests_properties("fuzzing.parser" PROPERTIES
    LABELS "fuzzing"
    ENVIRONMENT "ROOT_DIR=${CMAKE_SOURCE_DIR};BUILD_DIR=${CMAKE_BINARY_DIR};GEN_INC_DIR=${lib_gen_inc_dir}/include"
)

add_custom_target(fuzzing
    COMMAND ${CMAKE_CTEST_COMMAND} --output-on-failure -L fuzzing
    DEPENDS fuzz_parser
    COMMENT "Running fuzzing tests"
)