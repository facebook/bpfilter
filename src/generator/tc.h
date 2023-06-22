/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#pragma once

#include "core/flavor.h"
#include "core/hook.h"

/**
 * @brief Generate a handle for a TC codegen.
 *
 * Handles are a way to identify a BPF program within the TC namespace.
 *
 * @param codegen Codegen to generate a handle for.
 * @return 32 bits handle for the codegen.
 */
#define bf_tc_program_handle(program)                                          \
    ({                                                                         \
        typeof(program) _program = (program);                                  \
        (_program->hook << 16) | _program->front;                              \
    })

extern const struct bf_flavor_ops bf_flavor_ops_tc;

/**
 * @brief Convert @ref bf_hook into a TC hook.
 *
 * @param hook Hook to convert. Must be valid TC hook.
 * @return TC hook, as a bpf_tc_attach_point enumeration value.
 */
enum bpf_tc_attach_point bf_hook_to_tc_hook(enum bf_hook hook);
