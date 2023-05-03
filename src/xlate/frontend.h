/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#pragma once

#include "core/context.h"
#include "shared/request.h"

struct bf_table;
struct bf_codegen;

typedef int (*bf_fe_translate_fn)(void *data, size_t data_size,
                                  bf_list (*codegens)[__BF_HOOK_MAX]);
typedef void (*bf_fe_dump_fn)(void *data);

struct bf_frontend
{
    bf_fe_translate_fn translate;
    bf_fe_dump_fn dump;
};

const struct bf_frontend *bf_frontend_get(enum bf_request_type type);
