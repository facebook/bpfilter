/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2021 Telegram FZ-LLC
 * Copyright (c) 2022 Meta Platforms, Inc. and affiliates.
 */

#ifndef NET_BPFILTER_CODEGEN_H
#define NET_BPFILTER_CODEGEN_H

#include <linux/bpf.h>
#include <linux/filter.h>
#include <linux/list.h>

#include <bpf/libbpf.h>

#include <errno.h>
#include <stddef.h>
#include <stdint.h>

struct context;
struct table;

#define CODEGEN_REG_RETVAL	BPF_REG_0
#define CODEGEN_REG_SCRATCH1	BPF_REG_1
#define CODEGEN_REG_SCRATCH2	BPF_REG_2
#define CODEGEN_REG_SCRATCH3	BPF_REG_3
#define CODEGEN_REG_SCRATCH4	BPF_REG_4
#define CODEGEN_REG_SCRATCH5	BPF_REG_5
#define CODEGEN_REG_DATA_END	CODEGEN_REG_SCRATCH5
#define CODEGEN_REG_L3		BPF_REG_6
#define CODEGEN_REG_L4		BPF_REG_7
#define CODEGEN_REG_RUNTIME_CTX BPF_REG_8
#define CODEGEN_REG_CTX		BPF_REG_9

#define EMIT(codegen, x)					     \
	do {							     \
		typeof(codegen) __codegen = codegen;		     \
		if ((__codegen)->len_cur + 1 > (__codegen)->len_max) \
			return -ENOMEM;				     \
		(__codegen)->img[codegen->len_cur++] = (x);	     \
	} while (0)

#define EMIT_FIXUP(codegen, fixup_type, insn)				       \
	do {								       \
		const int __err = emit_fixup((codegen), (fixup_type), (insn)); \
		if (__err)						       \
			return __err;					       \
	} while (0)

#define EMIT_ADD_COUNTER(codegen)			     \
	do {						     \
		const int __err = emit_add_counter(codegen); \
		if (__err)				     \
			return __err;			     \
	} while (0)

#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#define EMIT_LITTLE_ENDIAN(codegen, x) EMIT(codegen, x)
#else
#define EMIT_LITTLE_ENDIAN(codegen, x)
#endif

struct runtime_context {
	uint32_t data_size;
	void *l3;
	void *l4;
};

#define STACK_RUNTIME_CONTEXT_OFFSET(field)		    \
	(-(short)(offsetof(struct runtime_context, field) + \
		  sizeof(((struct runtime_context *)NULL)->field)))

#define STACK_SCRATCHPAD_OFFSET (-(short)sizeof(struct runtime_context))

enum codegen_map_type {
	CODEGEN_MAP_COUNTERS,
	__MAX_CODEGEN_MAP_TYPE
};

enum codegen_fixup_type {
	CODEGEN_FIXUP_NEXT_RULE,
	CODEGEN_FIXUP_END_OF_CHAIN,
	CODEGEN_FIXUP_JUMP_TO_CHAIN,
	CODEGEN_FIXUP_COUNTERS_INDEX,
	__MAX_CODEGEN_FIXUP_TYPE
};

struct codegen_fixup_desc {
	struct list_head list;
	enum codegen_fixup_type type;
	uint32_t insn;
	union {
		uint32_t offset;
	};
};

enum codegen_reloc_type {
	CODEGEN_RELOC_MAP,
	__MAX_CODEGEN_RELOC_TYPE
};

struct codegen_reloc_desc {
	struct list_head list;
	enum codegen_reloc_type type;
	uint32_t insn;
	union {
		struct {
			enum codegen_map_type map;
			// TODO: add BTF
		};
	};
};

enum codegen_subprog_type {
	CODEGEN_SUBPROG_USER_CHAIN,
};

struct codegen_subprog_desc {
	struct list_head list;
	enum codegen_subprog_type type;
	uint32_t insn;
	union {
		uint32_t offset;
	};
};

struct codegen_ops;
struct shared_codegen;

struct codegen {
	struct context *ctx;
	struct bpf_insn *img;
	char *log_buf;
	size_t log_buf_size;
	int iptables_hook;
	union {
		enum bpf_tc_attach_point bpf_tc_hook;
	};
	enum bpf_prog_type prog_type;
	uint32_t len_cur;
	uint32_t len_max;
	uint32_t rule_index;
	const struct codegen_ops *codegen_ops;
	struct shared_codegen *shared_codegen;
	struct list_head fixup;
	struct list_head relocs;
	struct list_head awaiting_subprogs;
	uint16_t subprogs_cur;
	uint16_t subprogs_max;
	struct codegen_subprog_desc **subprogs;
	void *img_ctx;
};

struct shared_codegen {
	int maps_refcnt;
	union bpf_attr maps[__MAX_CODEGEN_MAP_TYPE];
	int maps_fd[__MAX_CODEGEN_MAP_TYPE];
};

struct codegen_ops {
	int (*gen_inline_prologue)(struct codegen *codegen);
	int (*load_packet_data)(struct codegen *codegen, int dst_reg);
	int (*load_packet_data_end)(struct codegen *codegen, int dst_reg);
	int (*emit_ret_code)(struct codegen *codegen, int ret_code);
	int (*gen_inline_epilogue)(struct codegen *codegen);
	int (*load_img)(struct codegen *codegen);
	void (*unload_img)(struct codegen *codegen);
};

void create_shared_codegen(struct shared_codegen *shared_codegen);
int create_codegen(struct codegen *codegen, enum bpf_prog_type type);
int codegen_push_awaiting_subprog(struct codegen *codegen,
				  struct codegen_subprog_desc *subprog);
int codegen_fixup(struct codegen *codegen, enum codegen_fixup_type fixup_type);
int emit_fixup(struct codegen *codegen, enum codegen_fixup_type fixup_type,
	       struct bpf_insn insn);
int emit_add_counter(struct codegen *codegen);
int try_codegen(struct codegen *codegen, const struct table *table);
int load_img(struct codegen *codegen);
void unload_img(struct codegen *codegen);
void free_codegen(struct codegen *codegen);

#endif // NET_BPFILTER_CODEGEN_H
