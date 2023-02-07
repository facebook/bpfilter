// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2021 Telegram FZ-LLC
 * Copyright (c) 2022 Meta Platforms, Inc. and affiliates.
 */

#define _GNU_SOURCE

#include "codegen.h"

#include "../../include/uapi/linux/bpfilter.h"

#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/pkt_cls.h>

#include <bpf/bpf_endian.h>

#include <unistd.h>
#include <sys/syscall.h>

#include <search.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <bpf/libbpf.h>

#include "logger.h"
#include "rule.h"
#include "table.h"

enum fixup_insn_type {
	FIXUP_INSN_OFF,
	FIXUP_INSN_IMM,
	__MAX_FIXUP_INSN_TYPE
};

static int sys_bpf(int cmd, union bpf_attr *attr, unsigned int size)
{
	return syscall(SYS_bpf, cmd, attr, size);
}

static __u64 bpf_ptr_to_u64(const void *ptr)
{
	return (__u64)(unsigned long)ptr;
}

static int subprog_desc_comparator(const void *x, const void *y)
{
	const struct codegen_subprog_desc *subprog_x = *(const struct codegen_subprog_desc **)x;
	const struct codegen_subprog_desc *subprog_y = *(const struct codegen_subprog_desc **)y;

	if (subprog_x->type != subprog_y->type)
		return subprog_x->type - subprog_y->type;

	if (subprog_x->type == CODEGEN_SUBPROG_USER_CHAIN)
		return subprog_x->offset - subprog_y->offset;

	BUG_ON(1);

	return -1;
}

/**
 * codegen_inline_memset_zero_64() - Generate eBPF bytecode to initialise a
 *	contiguous memory area with 0.
 * @ctx: codegen context.
 * @addr_reg: register containing the address of the memory area to initialise.
 *	The caller need to initialise the register properly before calling this
 *	function.
 * @size: size of the memory area. As this function initialises 64 bits at a
 *	time, @size needs to be a multiple of 64 bits. If it doesn't, the
 *	function return without intialising the memory and an error message is
 *	printed out.
 *
 * Return: 0 on success, negative errno value on error.
 */
static int codegen_inline_memset_zero_64(struct codegen *ctx, int reg,
					 size_t size)
{
	if (size % 8) {
		BFLOG_ERR("codegen_memset_zero_64() called with size %ld, size must be a multiple of 8",
			  size);
		return -EINVAL;
	}

	for (size_t i = 0; i * 8 < size; ++i)
		EMIT(ctx, BPF_ST_MEM(BPF_DW, reg, i * 8, 0));

	return 0;
}

static int codegen_push_subprog(struct codegen *codegen,
				struct codegen_subprog_desc *subprog)
{
	// TODO: merge this with codegen_fixup_push.

	if (codegen->subprogs_cur == codegen->subprogs_max) {
		struct codegen_subprog_desc **subprogs;
		uint16_t subprogs_max;

		subprogs_max = codegen->subprogs_cur ?
			       2 * codegen->subprogs_cur : 1;
		subprogs = reallocarray(codegen->subprogs, subprogs_max,
					sizeof(codegen->subprogs[0]));
		if (!subprogs) {
			BFLOG_ERR("out of memory");
			return -ENOMEM;
		}

		codegen->subprogs_max = subprogs_max;
		codegen->subprogs = subprogs;
	}

	codegen->subprogs[codegen->subprogs_cur++] = subprog;

	qsort(codegen->subprogs, codegen->subprogs_cur,
	      sizeof(codegen->subprogs[0]), subprog_desc_comparator);

	return 0;
}

static const struct codegen_subprog_desc *codegen_find_subprog(struct codegen *codegen,
							       const struct codegen_subprog_desc **subprog)
{
	const struct codegen_subprog_desc **found;

	found = bsearch(subprog, codegen->subprogs, codegen->subprogs_cur,
			sizeof(codegen->subprogs[0]), subprog_desc_comparator);

	return found ? *found : NULL;
}

static const struct codegen_subprog_desc *codegen_find_user_chain_subprog(struct codegen *codegen,
									  uint32_t offset)
{
	const struct codegen_subprog_desc subprog = {
		.type = CODEGEN_SUBPROG_USER_CHAIN,
		.offset = offset
	};
	const struct codegen_subprog_desc *subprog_ptr = &subprog;

	return codegen_find_subprog(codegen, &subprog_ptr);
}

int codegen_push_awaiting_subprog(struct codegen *codegen,
				  struct codegen_subprog_desc *subprog)
{
	struct list_head *t, *n;

	if (codegen_find_subprog(codegen, (const struct codegen_subprog_desc **)&subprog)) {
		free(subprog);
		return 0;
	}

	list_for_each_safe(t, n, &codegen->awaiting_subprogs) {
		struct codegen_subprog_desc *awaiting_subprog;

		awaiting_subprog = list_entry(t, struct codegen_subprog_desc, list);
		if (!subprog_desc_comparator(&awaiting_subprog, &subprog)) {
			free(subprog);
			return 0;
		}
	}

	list_add_tail(&subprog->list, &codegen->awaiting_subprogs);

	return 0;
}

static int codegen_fixup_insn(struct bpf_insn *insn, enum fixup_insn_type type,
			      __s32 v)
{
	switch (type) {
	case FIXUP_INSN_OFF:
		if (insn->off) {
			BFLOG_ERR("missing instruction offset");
			return -EINVAL;
		}

		insn->off = v;

		return 0;
	case FIXUP_INSN_IMM:
		if (insn->imm) {
			BFLOG_ERR("missing instruction immediate value");
			return -EINVAL;
		}

		insn->imm = v;

		return 0;
	default:
		BFLOG_ERR("invalid fixup instruction type");
		return -EINVAL;
	}
}

int codegen_fixup(struct codegen *codegen, enum codegen_fixup_type fixup_type)
{
	struct list_head *t, *n;

	list_for_each_safe(t, n, &codegen->fixup) {
		enum fixup_insn_type type = __MAX_FIXUP_INSN_TYPE;
		struct codegen_fixup_desc *fixup;
		struct bpf_insn *insn;
		__s32 v;
		int r;

		fixup = list_entry(t, struct codegen_fixup_desc, list);
		if (fixup->type != fixup_type)
			continue;

		if (fixup->type >= __MAX_CODEGEN_FIXUP_TYPE) {
			BFLOG_ERR("invalid instruction fixup type: %d",
				  fixup->type);
			return -EINVAL;
		}

		if (fixup->insn > codegen->len_cur) {
			BFLOG_ERR("invalid instruction fixup offset");
			return -EINVAL;
		}

		insn = &codegen->img[fixup->insn];

		if (fixup_type == CODEGEN_FIXUP_NEXT_RULE ||
		    fixup_type == CODEGEN_FIXUP_END_OF_CHAIN) {
			type = FIXUP_INSN_OFF;
			v = codegen->len_cur - fixup->insn - 1;
		}

		if (fixup_type == CODEGEN_FIXUP_JUMP_TO_CHAIN) {
			const struct codegen_subprog_desc *subprog;

			subprog = codegen_find_user_chain_subprog(codegen,
								  fixup->offset);
			if (!subprog) {
				BFLOG_ERR("subprogram not found for offset %d",
					  fixup->offset);
				return -EINVAL;
			}

			type = FIXUP_INSN_OFF;
			v = subprog->insn - fixup->insn - 1;
		}

		if (fixup_type == CODEGEN_FIXUP_COUNTERS_INDEX) {
			type = FIXUP_INSN_IMM;
			BFLOG_DBG("fixup counter for rule %d", codegen->rule_index);
			v = codegen->rule_index;
		}

		r = codegen_fixup_insn(insn, type, v);
		if (r) {
			BFLOG_ERR("failed to fixup codegen instruction: %s",
				  STRERR(r));
			return r;
		}

		list_del(t);
		free(fixup);
	}

	return 0;
}

int emit_fixup(struct codegen *codegen, enum codegen_fixup_type fixup_type,
	       struct bpf_insn insn)
{
	struct codegen_fixup_desc *fixup;

	fixup = malloc(sizeof(*fixup));
	if (!fixup) {
		BFLOG_ERR("out of memory");
		return -ENOMEM;
	}

	INIT_LIST_HEAD(&fixup->list);
	fixup->type = fixup_type;
	fixup->insn = codegen->len_cur;
	list_add_tail(&fixup->list, &codegen->fixup);

	EMIT(codegen, insn);

	return 0;
}

int emit_add_counter(struct codegen *codegen)
{
	struct bpf_insn insns[2] = { BPF_LD_MAP_FD(BPF_REG_ARG1, 0) };
	struct codegen_reloc_desc *reloc;

	reloc = malloc(sizeof(*reloc));
	if (!reloc) {
		BFLOG_ERR("out of memory");
		return -ENOMEM;
	}

	INIT_LIST_HEAD(&reloc->list);
	reloc->type = CODEGEN_RELOC_MAP;
	reloc->map = CODEGEN_MAP_COUNTERS;
	reloc->insn = codegen->len_cur;
	list_add_tail(&reloc->list, &codegen->relocs);

	EMIT(codegen, insns[0]);
	EMIT(codegen, insns[1]);

	EMIT_FIXUP(codegen, CODEGEN_FIXUP_COUNTERS_INDEX,
		   BPF_ST_MEM(BPF_W, BPF_REG_10, STACK_SCRATCHPAD_OFFSET - 4, 0));
	EMIT(codegen, BPF_MOV64_REG(BPF_REG_ARG2, BPF_REG_10));
	EMIT(codegen,
	     BPF_ALU64_IMM(BPF_ADD, BPF_REG_ARG2, STACK_SCRATCHPAD_OFFSET - 4));
	EMIT(codegen, BPF_EMIT_CALL(BPF_FUNC_map_lookup_elem));
	EMIT(codegen, BPF_JMP_IMM(BPF_JEQ, BPF_REG_0, 0, 14));

	reloc = malloc(sizeof(*reloc));
	if (!reloc) {
		BFLOG_ERR("out of memory");
		return -ENOMEM;
	}

	INIT_LIST_HEAD(&reloc->list);
	reloc->type = CODEGEN_RELOC_MAP;
	reloc->map = CODEGEN_MAP_COUNTERS;
	reloc->insn = codegen->len_cur;
	list_add_tail(&reloc->list, &codegen->relocs);

	EMIT(codegen, insns[0]);
	EMIT(codegen, insns[1]);

	EMIT(codegen, BPF_LDX_MEM(BPF_DW, CODEGEN_REG_SCRATCH5, BPF_REG_0, 0));
	EMIT(codegen, BPF_LDX_MEM(BPF_DW, CODEGEN_REG_SCRATCH4, BPF_REG_0, 8));
	EMIT(codegen, BPF_LDX_MEM(BPF_W, CODEGEN_REG_SCRATCH3, CODEGEN_REG_RUNTIME_CTX,
				  STACK_RUNTIME_CONTEXT_OFFSET(data_size)));
	EMIT(codegen, BPF_ALU64_IMM(BPF_ADD, CODEGEN_REG_SCRATCH5, 1));
	EMIT(codegen,
	     BPF_ALU64_REG(BPF_ADD, CODEGEN_REG_SCRATCH4, CODEGEN_REG_SCRATCH3));
	EMIT(codegen, BPF_STX_MEM(BPF_DW, BPF_REG_0, CODEGEN_REG_SCRATCH5, 0));
	EMIT(codegen, BPF_STX_MEM(BPF_DW, BPF_REG_0, CODEGEN_REG_SCRATCH4, 8));
	EMIT(codegen, BPF_MOV64_REG(BPF_REG_ARG2, BPF_REG_10));
	EMIT(codegen,
	     BPF_ALU64_IMM(BPF_ADD, BPF_REG_ARG2, STACK_SCRATCHPAD_OFFSET - 4));
	EMIT(codegen, BPF_MOV64_REG(BPF_REG_ARG3, BPF_REG_0));
	EMIT(codegen, BPF_MOV32_IMM(BPF_REG_ARG4, BPF_EXIST));
	EMIT(codegen, BPF_EMIT_CALL(BPF_FUNC_map_update_elem));

	return 0;
}

static int codegen_reloc(struct codegen *codegen)
{
	struct shared_codegen *shared_codegen;
	struct list_head *t;

	shared_codegen = codegen->shared_codegen;

	list_for_each(t, &codegen->relocs) {
		struct codegen_reloc_desc *reloc;
		struct bpf_insn *insn;

		reloc = list_entry(t, struct codegen_reloc_desc, list);

		if (reloc->insn >= codegen->len_cur) {
			BFLOG_ERR("invalid instruction relocation offset");
			return -EINVAL;
		}

		insn = &codegen->img[reloc->insn];

		if (reloc->type == CODEGEN_RELOC_MAP) {
			enum codegen_map_type map_type;

			if (codegen->len_cur <= reloc->insn + 1) {
				BFLOG_ERR("invalid instruction relocation map offset");
				return -EINVAL;
			}

			if (insn->code != (BPF_LD | BPF_DW | BPF_IMM)) {
				BFLOG_ERR("invalid instruction relocation code %d",
					  insn->code);
				return -EINVAL;
			}

			map_type = insn->imm;
			if (map_type < 0 || map_type >= __MAX_CODEGEN_MAP_TYPE) {
				BFLOG_ERR("invalid instruction relocation map type: %d",
					  map_type);
				return -EINVAL;
			}

			BUG_ON(shared_codegen->maps_fd[map_type] < 0);
			insn->imm = shared_codegen->maps_fd[map_type];

			continue;
		}

		BFLOG_ERR("invalid instruction relocation type %d", reloc->type);
		return -EINVAL;
	}

	return 0;
}

static int load_maps(struct codegen *codegen)
{
	struct shared_codegen *shared_codegen;
	int i;

	shared_codegen = codegen->shared_codegen;

	if (shared_codegen->maps_refcnt++)
		return 0;

	for (i = 0; i < __MAX_CODEGEN_MAP_TYPE; ++i) {
		int j;
		int fd;
		int saved_errno;
		union bpf_attr *map;

		BUG_ON(shared_codegen->maps_fd[i] > -1);

		map = &shared_codegen->maps[i];
		fd = sys_bpf(BPF_MAP_CREATE, map, sizeof(*map));
		if (fd > -1) {
			BFLOG_DBG("opened BPF map with FD %d", fd);
			shared_codegen->maps_fd[i] = fd;
			continue;
		}

		BFLOG_ERR("bpf syscall failed during map creation: %s",
			  STRERR(fd));
		saved_errno = errno;

		for (j = 0; j < i; ++j) {
			close(shared_codegen->maps_fd[j]);
			shared_codegen->maps_fd[j] = -1;
		}

		return saved_errno;
	}

	return 0;
}

static void unload_maps(struct codegen *codegen)
{
	struct shared_codegen *shared_codegen;
	int i;

	shared_codegen = codegen->shared_codegen;

	if (--shared_codegen->maps_refcnt)
		return;

	for (i = 0; i < __MAX_CODEGEN_MAP_TYPE; ++i) {
		if (shared_codegen->maps_fd[i] > -1) {
			close(shared_codegen->maps_fd[i]);
			shared_codegen->maps_fd[i] = -1;
		}
	}
}

static int tc_gen_inline_prologue(struct codegen *codegen)
{
	EMIT(codegen, BPF_MOV64_REG(CODEGEN_REG_CTX, BPF_REG_ARG1));
	EMIT(codegen, BPF_MOV64_REG(CODEGEN_REG_RUNTIME_CTX, BPF_REG_FP));
	EMIT(codegen, BPF_MOV32_IMM(CODEGEN_REG_RETVAL, TC_ACT_OK));

	return 0;
}

static int tc_load_packet_data(struct codegen *codegen, int dst_reg)
{
	EMIT(codegen, BPF_LDX_MEM(BPF_W, dst_reg, CODEGEN_REG_CTX,
				  offsetof(struct __sk_buff, data)));

	return 0;
}

static int tc_load_packet_data_end(struct codegen *codegen, int dst_reg)
{
	EMIT(codegen, BPF_LDX_MEM(BPF_W, CODEGEN_REG_DATA_END, CODEGEN_REG_CTX,
				  offsetof(struct __sk_buff, data_end)));

	return 0;
}

static int tc_emit_ret_code(struct codegen *codegen, int ret_code)
{
	int tc_ret_code;

	if (ret_code == BPFILTER_NF_ACCEPT)
		tc_ret_code = TC_ACT_UNSPEC;
	else if (ret_code == BPFILTER_NF_DROP)
		tc_ret_code = TC_ACT_SHOT;
	else
		return -EINVAL;

	EMIT(codegen, BPF_MOV32_IMM(BPF_REG_0, tc_ret_code));

	return 0;
}

static int tc_gen_inline_epilogue(struct codegen *codegen)
{
	EMIT(codegen, BPF_EXIT_INSN());

	return 0;
}

struct tc_img_ctx {
	int fd;
	struct bpf_tc_hook hook;
	struct bpf_tc_opts opts;
};

static int tc_load_img(struct codegen *codegen)
{
	struct tc_img_ctx *img_ctx;
	int fd;
	int r;

	if (codegen->img_ctx) {
		BFLOG_ERR("TC context missing from codegen");
		return -EINVAL;
	}

	img_ctx = calloc(1, sizeof(*img_ctx));
	if (!img_ctx) {
		BFLOG_ERR("out of memory");
		return -ENOMEM;
	}

	img_ctx->hook.sz = sizeof(img_ctx->hook);
	img_ctx->hook.ifindex = 2;
	img_ctx->hook.attach_point = codegen->bpf_tc_hook;

	fd = load_img(codegen);
	if (fd < 0) {
		BFLOG_ERR("failed to load TC codegen image: %s", STRERR(fd));
		r = fd;
		goto err_free;
	}

	r = bpf_tc_hook_create(&img_ctx->hook);
	if (r && r != -EEXIST) {
		BFLOG_ERR("failed to create TC hook: %s\n", STRERR(r));
		goto err_free;
	}

	img_ctx->opts.sz = sizeof(img_ctx->opts);
	img_ctx->opts.handle = codegen->iptables_hook;
	img_ctx->opts.priority = 0;
	img_ctx->opts.prog_fd = fd;
	r = bpf_tc_attach(&img_ctx->hook, &img_ctx->opts);
	if (r) {
		BFLOG_ERR("failed to attach TC program: %s", STRERR(r));
		goto err_free;
	}

	img_ctx->fd = fd;
	codegen->img_ctx = img_ctx;

	return fd;

err_free:
	if (fd > -1)
		close(fd);
	free(img_ctx);
	return r;
}

static void tc_unload_img(struct codegen *codegen)
{
	struct tc_img_ctx *img_ctx;
	int r;

	BUG_ON(!codegen->img_ctx);

	img_ctx = (struct tc_img_ctx *)codegen->img_ctx;
	img_ctx->opts.flags = 0;
	img_ctx->opts.prog_fd = 0;
	img_ctx->opts.prog_id = 0;
	r = bpf_tc_detach(&img_ctx->hook, &img_ctx->opts);
	if (r)
		BFLOG_EMERG("failed to detach TC program: %s", STRERR(r));

	BUG_ON(img_ctx->fd < 0);
	close(img_ctx->fd);
	free(img_ctx);

	codegen->img_ctx = NULL;

	unload_img(codegen);
}

static const struct codegen_ops tc_codegen_ops = {
	.gen_inline_prologue = tc_gen_inline_prologue,
	.load_packet_data = tc_load_packet_data,
	.load_packet_data_end = tc_load_packet_data_end,
	.emit_ret_code = tc_emit_ret_code,
	.gen_inline_epilogue = tc_gen_inline_epilogue,
	.load_img = tc_load_img,
	.unload_img = tc_unload_img,
};

void create_shared_codegen(struct shared_codegen *shared_codegen)
{
	shared_codegen->maps_refcnt = 0;

	shared_codegen->maps[CODEGEN_MAP_COUNTERS].map_type =
		BPF_MAP_TYPE_PERCPU_ARRAY;
	shared_codegen->maps[CODEGEN_MAP_COUNTERS].key_size = 4;
	shared_codegen->maps[CODEGEN_MAP_COUNTERS].value_size =
		sizeof(struct bpfilter_ipt_counters);
	shared_codegen->maps[CODEGEN_MAP_COUNTERS].max_entries = 0;
	snprintf(shared_codegen->maps[CODEGEN_MAP_COUNTERS].map_name,
		 sizeof(shared_codegen->maps[CODEGEN_MAP_COUNTERS].map_name),
			"bpfilter_cntrs");
	shared_codegen->maps_fd[CODEGEN_MAP_COUNTERS] = -1;
}

int create_codegen(struct codegen *codegen, enum bpf_prog_type type)
{
	int r;

	memset(codegen, 0, sizeof(*codegen));

	switch (type) {
	case BPF_PROG_TYPE_SCHED_CLS:
		codegen->codegen_ops = &tc_codegen_ops;
		break;
	default:
		BFLOG_ERR("unsupported BPF program type %d", type);
		return -EINVAL;
	}

	codegen->prog_type = type;

	codegen->log_buf_size = 1 << 20;
	codegen->log_buf = malloc(codegen->log_buf_size);
	if (!codegen->log_buf) {
		BFLOG_ERR("out of memory");
		r = -ENOMEM;
		goto err_free;
	}

	codegen->len_max = BPF_MAXINSNS;
	codegen->img = malloc(codegen->len_max * sizeof(codegen->img[0]));
	if (!codegen->img) {
		BFLOG_ERR("out of memory");
		r = -ENOMEM;
		goto err_free;
	}

	codegen->shared_codegen = NULL;

	INIT_LIST_HEAD(&codegen->fixup);
	INIT_LIST_HEAD(&codegen->relocs);
	INIT_LIST_HEAD(&codegen->awaiting_subprogs);

	return 0;

err_free:
	free(codegen->img);

	return r;
}

static int try_codegen_rules(struct codegen *codegen, struct rule *rule_front,
			     struct rule *rule_last)
{
	int r;

	for (; rule_front <= rule_last; ++rule_front, ++codegen->rule_index) {
		rule_front->index = codegen->rule_index;
		r = gen_inline_rule(codegen, rule_front);
		if (r) {
			BFLOG_ERR("failed to generate inline rule: %s",
				  STRERR(r));
			return r;
		}

		r = codegen_fixup(codegen, CODEGEN_FIXUP_NEXT_RULE);
		if (r) {
			BFLOG_ERR("failed to generate next rule fixups: %s",
				  STRERR(r));
			return r;
		}

		r = codegen_fixup(codegen, CODEGEN_FIXUP_COUNTERS_INDEX);
		if (r) {
			BFLOG_ERR("failed to generate counters fixups: %s",
				  STRERR(r));
			return r;
		}
	}

	r = codegen_fixup(codegen, CODEGEN_FIXUP_END_OF_CHAIN);
	if (r) {
		BFLOG_ERR("failed to generate end of chain fixups: %s",
			  STRERR(r));
		return r;
	}

	return 0;
}

static struct rule *table_find_last_rule(const struct table *table,
					 struct rule *rule_front)
{
	for (; rule_front; ++rule_front) {
		if (!rule_is_unconditional(rule_front))
			continue;

		if (!rule_has_standard_target(rule_front))
			continue;

		if (standard_target_verdict(rule_front->target.ipt_target) >= 0)
			continue;

		return rule_front;
	}

	return rule_front;
}

static int try_codegen_user_chain_subprog(struct codegen *codegen,
					  const struct table *table,
					  struct codegen_subprog_desc *subprog)
{
	struct rule *rule_front;
	struct rule *rule_last;
	int r;

	rule_front = table_find_rule_by_offset(table, subprog->offset);
	if (!rule_front) {
		BFLOG_ERR("failed to get rule at offset %d", subprog->offset);
		return -EINVAL;
	}

	rule_last = table_find_last_rule(table, rule_front);
	if (!rule_last) {
		BFLOG_ERR("failed to find last rule");
		return -EINVAL;
	}

	subprog->insn = codegen->len_cur;
	codegen->rule_index = rule_front - table->rules;
	r = try_codegen_rules(codegen, rule_front, rule_last);
	if (r) {
		BFLOG_ERR("failed to generate rules");
		return r;
	}

	return codegen_push_subprog(codegen, subprog);
}

static int try_codegen_subprogs(struct codegen *codegen, const struct table *table)
{
	while (!list_empty(&codegen->awaiting_subprogs)) {
		struct codegen_subprog_desc *subprog;
		int r = -EINVAL;

		subprog = list_entry(codegen->awaiting_subprogs.next,
				     struct codegen_subprog_desc,
				     list);

		if (subprog->type == CODEGEN_SUBPROG_USER_CHAIN) {
			r = try_codegen_user_chain_subprog(codegen, table,
							   subprog);
			if (r < 0) {
				BFLOG_ERR("failed to generate code for user defined chain: %s",
					  STRERR(r));
				return r;
			}
		} else {
			BFLOG_ERR("code generation for subprogram of type %d is not supported",
				  subprog->type);
			return -EINVAL;
		}

		list_del(&subprog->list);
	}

	return 0;
}

/**
 * generate_inline_forward_packet_assessment() - Add eBPF bytecode to assess
 *	whether the current packet is to be forwarded or not.
 * @ctx: context to add the bytecode to.
 *
 * Use bpf_fib_lookup() to find out whether the current packet is to be
 * forwarded or not. bpf_fib_lookup() requires a struct bpf_fib_lookup to be
 * filled with data from the packet.
 * The outcome of the bytecode will depend on the actual iptables hook used:
 * BPFILTER_INET_HOOK_FORWARD's chain will be processed if the packet is to be
 * forwarded, or will be skipped otherwise and jump to the next chain. The
 * opposite behaviour apply if hook is BPFILTER_INET_HOOK_LOCAL_IN.
 *
 * Return: 0 on success, negative errno value on error.
 */
static int generate_inline_forward_packet_assessment(struct codegen *ctx)
{
	// Set ARG2 to contain the address of the struct bpf_fib_lookup.
	EMIT(ctx, BPF_MOV64_REG(BPF_REG_ARG2, BPF_REG_10));
	EMIT(ctx, BPF_ALU64_IMM(BPF_ADD, BPF_REG_ARG2,
				(-(unsigned int)sizeof(struct bpf_fib_lookup)) - sizeof(struct runtime_context)));

	codegen_inline_memset_zero_64(ctx, BPF_REG_ARG2,
				      sizeof(struct bpf_fib_lookup));

	// Store h_proto for further decision
	EMIT(ctx, BPF_LDX_MEM(BPF_H, CODEGEN_REG_SCRATCH3, CODEGEN_REG_L3,
			      -(short int)(ETH_HLEN) + (short int)offsetof(struct ethhdr, h_proto)));
	EMIT(ctx, BPF_JMP_IMM(BPF_JEQ, CODEGEN_REG_SCRATCH3,
			      bpf_htons(ETH_P_IP), 2));

	// Not IPv4? Then do no process any FORWARD rule and move to the next chain (program).
	EMIT(ctx, BPF_MOV64_IMM(CODEGEN_REG_RETVAL, TC_ACT_UNSPEC));
	EMIT_FIXUP(ctx, CODEGEN_FIXUP_END_OF_CHAIN, BPF_JMP_A(0));

	// bpf_fib_lookup.family field
	EMIT(ctx, BPF_ST_MEM(BPF_B, BPF_REG_ARG2,
			     offsetof(struct bpf_fib_lookup, family), AF_INET));

	// bpf_fib_lookup.l4_protocol field
	EMIT(ctx, BPF_LDX_MEM(BPF_B, CODEGEN_REG_SCRATCH3, CODEGEN_REG_L3,
			      offsetof(struct iphdr, protocol)));
	EMIT(ctx, BPF_STX_MEM(BPF_B, BPF_REG_ARG2, CODEGEN_REG_SCRATCH3,
			      offsetof(struct bpf_fib_lookup, l4_protocol)));

	// bpf_fib_lookup.tot_len field
	EMIT(ctx, BPF_LDX_MEM(BPF_H, CODEGEN_REG_SCRATCH3, CODEGEN_REG_L3,
			      offsetof(struct iphdr, tot_len)));
	EMIT(ctx, BPF_STX_MEM(BPF_H, BPF_REG_ARG2, CODEGEN_REG_SCRATCH3,
			      offsetof(struct bpf_fib_lookup, tot_len)));

	// bpf_fib_lookup.ifindex field
	EMIT(ctx, BPF_LDX_MEM(BPF_W, CODEGEN_REG_SCRATCH3, CODEGEN_REG_CTX,
			      offsetof(struct __sk_buff, ingress_ifindex)));
	EMIT(ctx, BPF_STX_MEM(BPF_W, BPF_REG_ARG2, CODEGEN_REG_SCRATCH3,
			      offsetof(struct bpf_fib_lookup, ifindex)));

	// bpf_fib_lookup.tos field
	EMIT(ctx, BPF_LDX_MEM(BPF_B, CODEGEN_REG_SCRATCH3, CODEGEN_REG_L3,
			      offsetof(struct iphdr, tos)));
	EMIT(ctx, BPF_STX_MEM(BPF_B, BPF_REG_ARG2, CODEGEN_REG_SCRATCH3,
			      offsetof(struct bpf_fib_lookup, tos)));

	// bpf_fib_lookup.ipv4_src and bpf_fib_lookup.ipv4_dst fields
	EMIT(ctx, BPF_LDX_MEM(BPF_W, CODEGEN_REG_SCRATCH3, CODEGEN_REG_L3,
			      offsetof(struct iphdr, saddr)));
	EMIT(ctx, BPF_STX_MEM(BPF_W, BPF_REG_ARG2, CODEGEN_REG_SCRATCH3,
			      offsetof(struct bpf_fib_lookup, ipv4_src)));
	EMIT(ctx, BPF_LDX_MEM(BPF_W, CODEGEN_REG_SCRATCH3, CODEGEN_REG_L3,
			      offsetof(struct iphdr, daddr)));
	EMIT(ctx, BPF_STX_MEM(BPF_W, BPF_REG_ARG2, CODEGEN_REG_SCRATCH3,
			      offsetof(struct bpf_fib_lookup, ipv4_dst)));

	EMIT(ctx, BPF_MOV64_REG(BPF_REG_ARG1, CODEGEN_REG_CTX));
	EMIT(ctx, BPF_MOV64_IMM(BPF_REG_ARG3, sizeof(struct bpf_fib_lookup)));
	EMIT(ctx, BPF_MOV64_IMM(BPF_REG_ARG4, 0));

	EMIT(ctx, BPF_EMIT_CALL(BPF_FUNC_fib_lookup));
	EMIT(ctx, BPF_MOV64_REG(CODEGEN_REG_SCRATCH3, CODEGEN_REG_RETVAL));
	EMIT(ctx, BPF_MOV64_IMM(CODEGEN_REG_RETVAL, TC_ACT_UNSPEC));
	EMIT_FIXUP(ctx, CODEGEN_FIXUP_END_OF_CHAIN,
		   BPF_JMP_IMM(ctx->iptables_hook == BPFILTER_INET_HOOK_FORWARD ? BPF_JNE : BPF_JEQ,
			       CODEGEN_REG_SCRATCH3, BPF_FIB_LKUP_RET_SUCCESS, 0));

	return 0;
}

int try_codegen(struct codegen *codegen, const struct table *table)
{
	struct rule *rule_front;
	struct rule *rule_last;
	int r;

	r = codegen->codegen_ops->gen_inline_prologue(codegen);
	if (r) {
		BFLOG_ERR("failed to generate inline prologue: %s", STRERR(r));
		return r;
	}

	r = codegen->codegen_ops->load_packet_data(codegen, CODEGEN_REG_L3);
	if (r) {
		BFLOG_ERR("failed to generate code to load packet data: %s",
			  STRERR(r));
		return r;
	}

	r = codegen->codegen_ops->load_packet_data_end(codegen,
						       CODEGEN_REG_DATA_END);
	if (r) {
		BFLOG_ERR("failed to generate code to load packet data end: %s",
			  STRERR(r));
		return r;
	}

	// save packet size once
	EMIT(codegen, BPF_MOV64_REG(CODEGEN_REG_SCRATCH2, CODEGEN_REG_DATA_END));
	EMIT(codegen, BPF_ALU64_REG(BPF_SUB, CODEGEN_REG_SCRATCH2, CODEGEN_REG_L3));
	EMIT(codegen, BPF_STX_MEM(BPF_W, CODEGEN_REG_RUNTIME_CTX, CODEGEN_REG_SCRATCH2,
				  STACK_RUNTIME_CONTEXT_OFFSET(data_size)));

	EMIT(codegen, BPF_ALU64_IMM(BPF_ADD, CODEGEN_REG_L3, ETH_HLEN));
	EMIT_FIXUP(codegen, CODEGEN_FIXUP_END_OF_CHAIN,
		   BPF_JMP_REG(BPF_JGT, CODEGEN_REG_L3, CODEGEN_REG_DATA_END, 0));
	EMIT(codegen, BPF_MOV64_REG(CODEGEN_REG_SCRATCH1, CODEGEN_REG_L3));
	EMIT(codegen, BPF_ALU64_IMM(BPF_ADD, CODEGEN_REG_SCRATCH1, sizeof(struct iphdr)));
	EMIT_FIXUP(codegen, CODEGEN_FIXUP_END_OF_CHAIN,
		   BPF_JMP_REG(BPF_JGT, CODEGEN_REG_SCRATCH1, CODEGEN_REG_DATA_END, 0));

	if (codegen->iptables_hook == BPFILTER_INET_HOOK_LOCAL_IN ||
	    codegen->iptables_hook == BPFILTER_INET_HOOK_FORWARD) {
		/* There is no XDP nor TC forward hook to attach to. So, we
		 * need to add code to assess whether a incoming packet it
		 * to be forwarded or not.
		 */
		BFLOG_NOTICE("generate forward packet assessment");
		generate_inline_forward_packet_assessment(codegen);
	}

	rule_front = &table->rules[table->hook_entry[codegen->iptables_hook]];
	rule_last = &table->rules[table->underflow[codegen->iptables_hook]];

	codegen->rule_index = rule_front - table->rules;
	r = try_codegen_rules(codegen, rule_front, rule_last);
	if (r) {
		BFLOG_ERR("failed to generate rules: %s", STRERR(r));
		return r;
	}

	r = codegen->codegen_ops->gen_inline_epilogue(codegen);
	if (r) {
		BFLOG_ERR("failed to generate inline epilogue: %s",
			  STRERR(r));
		return r;
	}

	r = try_codegen_subprogs(codegen, table);
	if (r) {
		BFLOG_ERR("failed to generate subprograms: %s", STRERR(r));
		return r;
	}

	r = codegen_fixup(codegen, CODEGEN_FIXUP_JUMP_TO_CHAIN);
	if (r) {
		BFLOG_ERR("failed to generate fixups: %s", STRERR(r));
		return r;
	}

	codegen->shared_codegen->maps[CODEGEN_RELOC_MAP].max_entries = table->num_rules;

	return 0;
}

int load_img(struct codegen *codegen)
{
	union bpf_attr attr = {};
	int fd;
	int r;

	r = load_maps(codegen);
	if (r) {
		BFLOG_ERR("failed to load maps: %s", STRERR(r));
		return r;
	}

	r = codegen_reloc(codegen);
	if (r) {
		BFLOG_ERR("failed to generate relocations: %s", STRERR(r));
		return r;
	}

	attr.prog_type = codegen->prog_type;
	attr.insns = bpf_ptr_to_u64(codegen->img);
	attr.insn_cnt = codegen->len_cur;
	attr.license = bpf_ptr_to_u64("GPL");
	attr.prog_ifindex = 0;
	snprintf(attr.prog_name, sizeof(attr.prog_name), "bpfilter");

	if (codegen->log_buf && codegen->log_buf_size) {
		attr.log_buf = bpf_ptr_to_u64(codegen->log_buf);
		attr.log_size = codegen->log_buf_size;
		attr.log_level = 1;
	}

	fd = sys_bpf(BPF_PROG_LOAD, &attr, sizeof(attr));
	if (fd == -1) {
		BFLOG_ERR("failed to load BPF program: %s", codegen->log_buf);
		return -errno;
	}

	return fd;
}

void unload_img(struct codegen *codegen)
{
	unload_maps(codegen);
}

void free_codegen(struct codegen *codegen)
{
	struct list_head *t, *n;
	int i;

	list_for_each_safe(t, n, &codegen->fixup) {
		struct codegen_fixup_desc *fixup;

		fixup = list_entry(t, struct codegen_fixup_desc, list);
		free(fixup);
	}

	list_for_each_safe(t, n, &codegen->relocs) {
		struct codegen_reloc_desc *reloc;

		reloc = list_entry(t, struct codegen_reloc_desc, list);
		free(reloc);
	}

	list_for_each_safe(t, n, &codegen->awaiting_subprogs) {
		struct codegen_subprog_desc *subprog;

		subprog = list_entry(t, struct codegen_subprog_desc, list);
		free(subprog);
	}

	for (i = 0; i < codegen->subprogs_cur; ++i)
		free(codegen->subprogs[i]);
	free(codegen->subprogs);

	free(codegen->log_buf);
	free(codegen->img);
}
