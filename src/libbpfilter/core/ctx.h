/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#pragma once

#include <stdbool.h>
#include <stdint.h>

#include <bpfilter/elfstub.h>

struct btf;

/**
 * @file core/ctx.h
 *
 * Internal definition of `struct bf_ctx`.
 *
 * The public header `bpfilter/ctx.h` only forward-declares this type so
 * library users can hold and pass pointers without depending on any
 * particular layout. Modules inside `libbpfilter` that need to read fields
 * include this header.
 */

struct bf_ctx
{
    /// BPF token file descriptor.
    int token_fd;

    /// ELF stubs indexed by @ref bf_elfstub_id.
    struct bf_elfstub *stubs[_BF_ELFSTUB_MAX];

    /// Pass a token to BPF system calls, obtained from bpffs.
    bool with_bpf_token;

    /// Path to the bpffs mountpoint, owned by the context.
    char *bpffs_path;

    /// vmlinux BTF object, owned by the context.
    struct btf *btf;
};
