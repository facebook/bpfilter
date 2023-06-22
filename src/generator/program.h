/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#pragma once

#include <linux/bpf.h>

#include <stddef.h>
#include <stdint.h>

#include "core/dump.h"
#include "core/hook.h"
#include "core/list.h"
#include "external/filter.h"
#include "generator/fixup.h"
#include "shared/front.h"

#define PIN_PATH_LEN 64

#define CODEGEN_REG_RETVAL BPF_REG_0
#define CODEGEN_REG_SCRATCH1 BPF_REG_1
#define CODEGEN_REG_SCRATCH2 BPF_REG_2
#define CODEGEN_REG_SCRATCH3 BPF_REG_3
#define CODEGEN_REG_SCRATCH4 BPF_REG_4
#define CODEGEN_REG_SCRATCH5 BPF_REG_5
#define CODEGEN_REG_DATA_END CODEGEN_REG_SCRATCH5
#define CODEGEN_REG_L3 BPF_REG_6
#define CODEGEN_REG_L4 BPF_REG_7
#define CODEGEN_REG_RUNTIME_CTX BPF_REG_8
#define CODEGEN_REG_CTX BPF_REG_9

#define EMIT(program, x)                                                       \
    ({                                                                         \
        int __r = bf_program_emit((program), (x));                             \
        if (__r < 0)                                                           \
            return __r;                                                        \
    })

#define EMIT_FIXUP(program, type, insn)                                        \
    ({                                                                         \
        int __r = bf_program_emit_fixup((program), (type), (insn));            \
        if (__r < 0)                                                           \
            return __r;                                                        \
    })

#define EMIT_FIXUP_CALL(program, function)                                     \
    ({                                                                         \
        int __r = bf_program_emit_fixup_call((program), (function));           \
        if (__r < 0)                                                           \
            return __r;                                                        \
    })

#define EMIT_LOAD_FD_FIXUP(program, reg)                                       \
    ({                                                                         \
        const struct bpf_insn ld_insn[2] = {BPF_LD_MAP_FD(reg, 0)};            \
        int __r = bf_program_emit_fixup((program), BF_CODEGEN_FIXUP_MAP_FD,    \
                                        ld_insn[0]);                           \
        if (__r < 0)                                                           \
            return __r;                                                        \
        __r = bf_program_emit((program), ld_insn[1]);                          \
        if (__r < 0)                                                           \
            return __r;                                                        \
    })

struct bf_marsh;
struct bf_rule;
struct bf_counter;

struct bf_program
{
    uint32_t ifindex;
    enum bf_hook hook;
    enum bf_front front;
    char prog_name[BPF_OBJ_NAME_LEN];
    char map_name[BPF_OBJ_NAME_LEN];
    char prog_pin_path[PIN_PATH_LEN];
    char map_pin_path[PIN_PATH_LEN];
    size_t num_rules;

    /* Bytecode */
    uint32_t functions_location[_BF_CODEGEN_FIXUP_FUNCTION_MAX];
    struct bpf_insn *img;
    size_t img_size;
    size_t img_cap;
    bf_list fixups;
};

#define _cleanup_bf_program_ __attribute__((__cleanup__(bf_program_free)))

int bf_program_new(struct bf_program **program, int ifindex, enum bf_hook hook,
                   enum bf_front front);
void bf_program_free(struct bf_program **program);
int bf_program_marsh(const struct bf_program *program, struct bf_marsh **marsh);
int bf_program_unmarsh(const struct bf_marsh *marsh,
                       struct bf_program **program);
void bf_program_dump(const struct bf_program *program, prefix_t *prefix);
int bf_program_grow_img(struct bf_program *program);

int bf_program_emit(struct bf_program *program, struct bpf_insn insn);
int bf_program_emit_fixup(struct bf_program *program, enum bf_fixup_type type,
                          struct bpf_insn insn);
int bf_program_emit_fixup_call(struct bf_program *program,
                               enum bf_fixup_function function);
int bf_program_generate(struct bf_program *program, bf_list *rules);
int bf_program_load(struct bf_program *program);
int bf_program_unload(struct bf_program *program);

int bf_program_get_counters(const struct bf_program *program,
                            const struct bf_rule *rule,
                            struct bf_counter *counters);
int bf_program_set_counters(struct bf_program *program,
                            const struct bf_counter *counters);
