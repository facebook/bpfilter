# SPDX-License-Identifier: GPL-2.0
# Copyright (c) 2023 Meta Platforms, Inc. and affiliates.

function(createEndToEndTarget SOURCE)
    message("Creating end-to-end target '${SOURCE}'")
    add_executable(${SOURCE} ${SOURCE}.c)

    target_compile_options(${SOURCE}
        PRIVATE
            ${bpfilter_cflags}
            $<$<CONFIG:Release>:${bpfilter_cflags_release}>
            $<$<CONFIG:Debug>:${bpfilter_cflags_debug}>
    )

    target_include_directories(${SOURCE} SYSTEM
        PRIVATE
            ${CMAKE_SOURCE_DIR}/shared/include
            ${CMAKE_SOURCE_DIR}/lib/include
    )

    target_link_options(${SOURCE}
        PUBLIC
            ${bpfilter_ldflags}
            $<$<CONFIG:Release>:${bpfilter_ldflags_release}>
            $<$<CONFIG:Debug>:${bpfilter_ldflags_debug}>
    )

    target_link_libraries(${SOURCE}
        PRIVATE
            libbpfilter_so
    )
endfunction()

createEndToEndTarget(raw)
createEndToEndTarget(ipt)
