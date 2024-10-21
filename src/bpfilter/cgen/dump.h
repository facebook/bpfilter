/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#pragma once

/**
 * @file dump.h
 *
 * @ref bf_program_dump_bytecode is defined to pretty-print the BPF bytecode
 * from a @ref bf_program structure. The logic used here is inspired by
 * bpftool's dumper (https://github.com/libbpf/bpftool) with all the heavy
 * lifting performed by Linux @c kernel/bpf/disasm.c .
 */

struct bf_program;

void bf_program_dump_bytecode(const struct bf_program *program);
