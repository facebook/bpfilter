# SPDX-License-Identifier: GPL-2.0-only
# Copyright (c) 2023 Meta Platforms, Inc. and affiliates.

configure_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/bpfilter.service.in
    ${CMAKE_BINARY_DIR}/output/usr/lib/systemd/system/bpfilter.service
    @ONLY
)

add_executable(bpfilter
    ${CMAKE_CURRENT_SOURCE_DIR}/main.c
)

target_compile_definitions(bpfilter
    PRIVATE
        BF_CONTACT="${BF_CONTACT}"
)

target_include_directories(bpfilter
    PRIVATE
        ${CMAKE_SOURCE_DIR}/src/libbpfilter
)

target_link_libraries(bpfilter
    PRIVATE
        bf_global_flags
        libbpfilter
)

install(TARGETS bpfilter
    DESTINATION ${CMAKE_INSTALL_SBINDIR}
)

install(
    FILES ${CMAKE_BINARY_DIR}/output/usr/lib/systemd/system/bpfilter.service
    DESTINATION ${CMAKE_INSTALL_PREFIX}/lib/systemd/system
)
