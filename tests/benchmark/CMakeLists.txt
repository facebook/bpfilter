# SPDX-License-Identifier: GPL-2.0-only
# Copyright (c) 2023 Meta Platforms, Inc. and affiliates.

option(ENABLE_BENCHMARK "Enable benchmark" off)

if (NOT ENABLE_BENCHMARK)
    return()
endif ()

find_package(benchmark REQUIRED)

add_executable(benchmark_bin benchmark.cpp)

target_compile_options(benchmark_bin
    PRIVATE
        -std=c++20
)

target_link_libraries(benchmark_bin
    PRIVATE
        PkgConfig::bpf
        benchmark::benchmark
)

add_custom_target(benchmark
    COMMAND
        sudo
            $<TARGET_FILE:benchmark_bin>
                --cli $<TARGET_FILE:bfcli>
                --daemon $<TARGET_FILE:bpfilter>
    DEPENDS benchmark_bin bfcli bpfilter
    COMMENT "Running benchmarks"
)
