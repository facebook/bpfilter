# SPDX-License-Identifier: GPL-2.0
# Copyright (c) 2023 Meta Platforms, Inc. and affiliates.

enable_testing()

add_executable(tests_unit
    src/core/context.c
    src/core/flavor.c
    src/core/hook.c
    src/core/marsh.c
    src/core/list.c
    src/core/target.c
    src/core/helper.c
    ${bpfilter_daemon_srcs} ${bpfilter_shared_srcs}
)

target_compile_options(tests_unit
    PRIVATE
        -fprofile-arcs -ftest-coverage
        ${bpfilter_cflags}
        $<$<CONFIG:Release>:${bpfilter_cflags_release}>
        $<$<CONFIG:Debug>:${bpfilter_cflags_debug}>
        ${CRITERION_CFLAGS_OTHER}
)

target_include_directories(tests_unit
    PRIVATE
        ${SDL2_INCLUDE_DIRS}
        ${CMAKE_CURRENT_SOURCE_DIR}
        ${CMAKE_SOURCE_DIR}/src
        ${CMAKE_SOURCE_DIR}/shared/include
        ${CMAKE_SOURCE_DIR}/shared/include/bpfilter
)

target_link_libraries(tests_unit
    PRIVATE
        bpf
        ${CRITERION_LIBRARIES}
        gcov
)

target_link_options(tests_unit
    PUBLIC
        -Wl,--allow-multiple-definition
        ${bpfilter_ldflags}
        $<$<CONFIG:Release>:${bpfilter_ldflags_release}>
        $<$<CONFIG:Debug>:${bpfilter_ldflags_debug}>
)

add_custom_target(test
    COMMAND $<TARGET_FILE:tests_unit> --verbose --xml=test-report.xml
    DEPENDS tests_unit
    COMMENT "Running unit tests"
)
