# SPDX-License-Identifier: GPL-2.0-only
# Copyright (c) 2023 Meta Platforms, Inc. and affiliates.

option(ENABLE_BENCHMARK "Enable benchmark" off)

if (NOT ENABLE_BENCHMARK)
    return()
endif ()

find_package(benchmark REQUIRED)

add_executable(benchmark_bin
    main.cpp
    benchmark.cpp benchmark.hpp
)

target_include_directories(benchmark_bin
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}
)

target_compile_options(benchmark_bin
    PRIVATE
        -std=c++20
)

target_link_libraries(benchmark_bin
    PRIVATE
        PkgConfig::bpf
        benchmark::benchmark
)

add_custom_command(
    OUTPUT
        ${CMAKE_BINARY_DIR}/_fake_dep.txt
        ${CMAKE_BINARY_DIR}/gitrev.txt
    COMMAND
        /bin/sh -c "echo -n $(git rev-parse --short HEAD) > ${CMAKE_BINARY_DIR}/gitrev.txt"
    COMMAND
        /bin/sh -c "if [[ $(git status --porcelain) ]]; then echo -n _dirty >> ${CMAKE_BINARY_DIR}/gitrev.txt; fi"
    WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
    VERBATIM
)

add_custom_target(benchmark
    COMMAND
        sudo
            $<TARGET_FILE:benchmark_bin>
                --cli $<TARGET_FILE:bfcli>
                --daemon $<TARGET_FILE:bpfilter>
                --output ${CMAKE_BINARY_DIR}/output/`cat gitrev.txt`.json
    DEPENDS
        benchmark_bin bfcli bpfilter
        ${CMAKE_BINARY_DIR}/gitrev.txt
    WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
    USES_TERMINAL
    COMMENT "Running benchmarks"
)
