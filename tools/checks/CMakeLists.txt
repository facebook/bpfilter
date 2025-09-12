# SPDX-License-Identifier: GPL-2.0-only
# Copyright (c) 2023 Meta Platforms, Inc. and affiliates.

find_program(CLANG_TIDY_BIN NAMES clang-tidy-18 clang-tidy REQUIRED)
find_program(CLANG_FORMAT_BIN NAMES clang-format-18 clang-format REQUIRED)

# It's OK to use GLOB_RECURSE here, as it's not the main target for the source
# files but a secondary one.
file(GLOB_RECURSE bf_srcs
    ${CMAKE_SOURCE_DIR}/src/core/*.h            ${CMAKE_SOURCE_DIR}/src/core/*.c
    ${CMAKE_SOURCE_DIR}/src/bpfilter/*.h        ${CMAKE_SOURCE_DIR}/src/bpfilter/*.c
    ${CMAKE_SOURCE_DIR}/src/libbpfilter/*.h     ${CMAKE_SOURCE_DIR}/src/libbpfilter/*.c
    ${CMAKE_SOURCE_DIR}/src/bfcli/*.h           ${CMAKE_SOURCE_DIR}/src/bfcli/*.c
    ${CMAKE_SOURCE_DIR}/tests/harness/*.h       ${CMAKE_SOURCE_DIR}/tests/harness/*.c
)
list(FILTER bf_srcs EXCLUDE REGEX "src/bpfilter/xlate/nft/nfmsg.*")
list(FILTER bf_srcs EXCLUDE REGEX "src/bpfilter/xlate/nft/nfgroup.*")

# Create a custom rawstubs.h header to be included instead of bpfilter's
# rawstubs.h, without any included source file ($STUB.inc.c), as those are
# generated source file and we don't want to check them.
file(GLOB_RECURSE bf_elfstubs ${CMAKE_SOURCE_DIR}/src/bpfilter/bpf/*.c)
foreach (stub ${bf_elfstubs})
    get_filename_component(filename ${stub} NAME_WE)

    set(HDR_INC "${HDR_INC}static const unsigned char ${filename}[1] = {};\nstatic const unsigned int ${filename}_len = 1;\n")
    set(HDR_DECL "${HDR_DECL}{ .elf = ${filename}, .len = ${filename}_len, },")
endforeach ()

file(MAKE_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/include/bpfilter/cgen)
configure_file(
    ${CMAKE_SOURCE_DIR}/tools/cmake/rawstubs.h.in
    ${CMAKE_CURRENT_BINARY_DIR}/include/bpfilter/cgen/rawstubs.h
    @ONLY
)

add_custom_command(
    DEPENDS
        ${CMAKE_BINARY_DIR}/compile_commands.json
    COMMAND
        # Create a new compile_commands.json file without the unit test sources,
        # as they use specific build flags to include mock_assert(), which
        # creates false positives with clang-tidy.
        ${CMAKE_CURRENT_SOURCE_DIR}/filtersrcs
            --input ${CMAKE_BINARY_DIR}/compile_commands.json
            --output ${CMAKE_CURRENT_BINARY_DIR}/compile_commands.json
            --filter ".*\/tests\/unit$"
    OUTPUT
        ${CMAKE_CURRENT_BINARY_DIR}/compile_commands.json
    COMMENT
        "Generating filtered compile_commands.json"
    VERBATIM
)

set(check_stamps "")

foreach (filepath ${bf_srcs})
    get_filename_component(directory ${filepath} DIRECTORY)
    file(RELATIVE_PATH rel_directory ${CMAKE_SOURCE_DIR} ${directory})
    set(stamp_dir ${CMAKE_CURRENT_BINARY_DIR}/check_stamps/${rel_directory})

    get_filename_component(filename ${filepath} NAME)
    set(stamp_file ${stamp_dir}/${filename}.checked)

    file(MAKE_DIRECTORY ${stamp_dir})

    add_custom_command(
        DEPENDS
            ${filepath}
            ${CMAKE_SOURCE_DIR}/.clang-tidy
            ${CMAKE_CURRENT_BINARY_DIR}/compile_commands.json
        COMMAND
            ${CLANG_TIDY_BIN}
                --quiet
                --config-file=${CMAKE_SOURCE_DIR}/.clang-tidy
                -p ${CMAKE_CURRENT_BINARY_DIR}
                --extra-arg=-fno-caret-diagnostics
                --extra-arg-before="-I${CMAKE_CURRENT_BINARY_DIR}/include"
                ${filepath}
        COMMAND
            ${CLANG_FORMAT_BIN}
                --style=file:${CMAKE_SOURCE_DIR}/.clang-format
                --dry-run
                ${filepath}
        COMMAND
            ${CMAKE_COMMAND} -E touch ${stamp_file}
        OUTPUT ${stamp_file}
        COMMENT "Checking ${rel_directory}/${filename}"
    )

    list(APPEND check_stamps ${stamp_file})
endforeach ()

# Generated files (especially from Bison and Flex) are required.
add_custom_target(check
    DEPENDS
        bfcli_parser
        bfcli_lexer
        ${check_stamps}
)

add_custom_target(fixstyle
    COMMAND
        ${CLANG_FORMAT_BIN}
            --style=file:${CMAKE_SOURCE_DIR}/.clang-format
            -i
            ${bf_srcs}
    COMMENT "Fixing style for all the source files"
)
