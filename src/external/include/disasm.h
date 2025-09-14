/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright (c) 2011-2014 PLUMgrid, http://plumgrid.com
 * Copyright (c) 2016 Facebook
 */

#ifndef __BPF_DISASM_H__
#define __BPF_DISASM_H__

#include <linux/bpf.h>
#include <linux/kernel.h>

#include <stdbool.h>
#include <stdint.h>

typedef void (*bpf_insn_print_t)(void *private_data,
						const char *, ...);
typedef const char *(*bpf_insn_revmap_call_t)(void *private_data,
					      const struct bpf_insn *insn);
typedef const char *(*bpf_insn_print_imm_t)(void *private_data,
					    const struct bpf_insn *insn,
					    uint64_t full_imm);

struct bpf_insn_cbs {
	bpf_insn_print_t	cb_print;
	bpf_insn_revmap_call_t	cb_call;
	bpf_insn_print_imm_t	cb_imm;
	void			*private_data;
};

void print_bpf_insn(const struct bpf_insn_cbs *cbs,
		    const struct bpf_insn *insn,
		    bool allow_ptr_leaks);
#endif
