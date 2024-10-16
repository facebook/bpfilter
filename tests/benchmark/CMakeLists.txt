# SPDX-License-Identifier: GPL-2.0-only
# Copyright (c) 2023 Meta Platforms, Inc. and affiliates.

option(ENABLE_BENCHMARK "Enable benchmark" off)

if (NOT ENABLE_BENCHMARK)
    return()
endif ()

find_package(benchmark REQUIRED)
pkg_check_modules(git2 REQUIRED IMPORTED_TARGET libgit2)

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
        PkgConfig::git2
        benchmark::benchmark
)

add_custom_target(benchmark
    COMMAND
        sudo
            $<TARGET_FILE:benchmark_bin>
                --cli $<TARGET_FILE:bfcli>
                --daemon $<TARGET_FILE:bpfilter>
                --srcdir ${CMAKE_SOURCE_DIR}
                --outfile ${CMAKE_BINARY_DIR}/output/{gitrev}.json
    DEPENDS benchmark_bin bfcli bpfilter
    WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
    USES_TERMINAL
    COMMENT "Running benchmarks"
)
