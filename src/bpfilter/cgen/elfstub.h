/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#pragma once

#include <stddef.h>

struct bpf_insn;

enum bf_elfstub_id
{
    BF_ELFSTUB_PARSE_IPV6_EH,
    _BF_ELFSTUB_MAX,
};

struct bf_elfstub
{
    enum bf_elfstub_id id;
    struct bpf_insn *insns;
    size_t ninsns;
};

#define _free_bf_elfstub_ __attribute__((__cleanup__(bf_elfstub_free)))

int bf_elfstub_new(struct bf_elfstub **stub, enum bf_elfstub_id id);
void bf_elfstub_free(struct bf_elfstub **stub);
