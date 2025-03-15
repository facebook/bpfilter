/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#pragma once

#include <stddef.h>
#include <stdint.h>

/**
 * @file prog.h
 *
 * This module defines `bf_test_prog` to manipulate a BPF program generated by
 * `bpfilter`.
 *
 * Once a `bf_test_prog` object has been created, use `bf_test_prog_open()` to
 * link it to a BPF program attach to the system using the program's name.
 */

struct bf_chain;

struct bf_test_packet
{
    size_t len;
    const void *data;
};

#define _free_bf_test_prog_ __attribute__((__cleanup__(bf_test_prog_free)))

struct bf_test_prog
{
    int fd;
};

struct bf_test_prog *bf_test_prog_get(const struct bf_chain *chain);

int bf_test_prog_new(struct bf_test_prog **prog);
void bf_test_prog_free(struct bf_test_prog **prog);
int bf_test_prog_open(struct bf_test_prog *prog, const char *name);
