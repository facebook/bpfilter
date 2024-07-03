# SPDX-License-Identifier: GPL-2.0-only
# Copyright (c) 2023 Meta Platforms, Inc. and affiliates.

# - Create a build target for a BPF example program.
#
# Example programs are not aimed to be used directly by bpfilter, but they
# might be helpful during development to understand how clang or libbpf use
# a specific BPF feature, and replicate their behaviour in bpfilter.
#
# Storing those example programs within bpfilter's repository will ensure
# they are always available.
#
# For a given example program ${PROGRAM}, the BPF-C code source file must
# be named as ${PROGRAM}.bpf.c, and the loader must be named ${PROGRAM}.c.
# Example programs must use the BPF skeleton feature.
#
function(bf_test_make_bpf_example NAME)
    add_custom_target(${NAME}.bpf.o
        COMMAND
            ${CLANG_BIN}
                -O2 -g -target bpf
                -c ${CMAKE_CURRENT_SOURCE_DIR}/${NAME}.bpf.c
                -o ${NAME}.bpf.o
        DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/${NAME}.bpf.c
        BYPRODUCTS ${NAME}.bpf.o
        COMMENT "Compile ${NAME}.bpf.c source file"
    )

    add_custom_target(${NAME}.skeleton.h
        COMMAND
            ${BPFTOOL_BIN} gen skeleton ${NAME}.bpf.o > ${NAME}.skeleton.h
        DEPENDS ${NAME}.bpf.o
        BYPRODUCTS ${NAME}.skeleton.h
        COMMENT "Generate skeleton file for ${NAME}.bpf.o"
    )

    add_custom_target(${NAME}
        COMMAND
            ${CLANG_BIN}
                -O2 -I ${CMAKE_CURRENT_BINARY_DIR} -g -lbpf
                ${CMAKE_CURRENT_SOURCE_DIR}/${NAME}.c
                -o ${NAME}
        DEPENDS ${NAME}.skeleton.h
        BYPRODUCTS ${NAME}
        COMMENT "Compile ${NAME} loader"
    )

    message(STATUS "Add ${NAME} example program")
endfunction()

bf_test_make_bpf_example(xdp_printk)
