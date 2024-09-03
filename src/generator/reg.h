/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#pragma once

#include <linux/bpf.h>

#include "external/filter.h"

/**
 * BPF registers aliases adapted to bpfilter usage.
 */
enum bf_reg
{
    BF_REG_0 = BPF_REG_0,
    BF_REG_1 = BPF_REG_1,
    BF_REG_2 = BPF_REG_2,
    BF_REG_3 = BPF_REG_3,
    BF_REG_4 = BPF_REG_4,
    BF_REG_5 = BPF_REG_5,
    BF_REG_6 = BPF_REG_6,
    BF_REG_7 = BPF_REG_7,
    BF_REG_8 = BPF_REG_8,
    BF_REG_9 = BPF_REG_9,
    BF_REG_10 = BPF_REG_10,

    // Function arguments
    BF_ARG_1 = BPF_REG_1,
    BF_ARG_2 = BPF_REG_2,
    BF_ARG_3 = BPF_REG_3,
    BF_ARG_4 = BPF_REG_4,
    BF_ARG_5 = BPF_REG_5,

    // Callee saved registers, used for runtime context and packet headers
    BF_REG_L2 = BPF_REG_6,
    BF_REG_L3 = BPF_REG_7,
    BF_REG_L4 = BPF_REG_8,
    BF_REG_CTX = BPF_REG_9,

    BF_REG_RET = BPF_REG_0,
    BF_REG_FP = BPF_REG_FP,
};
