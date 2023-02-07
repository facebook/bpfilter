// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2021 Telegram FZ-LLC
 * Copyright (c) 2022 Meta Platforms, Inc. and affiliates.
 */

#define _GNU_SOURCE

#include <linux/filter.h>
#include <linux/netfilter/x_tables.h>
#include <linux/netfilter/xt_tcpudp.h>
#include <linux/udp.h>

#include <arpa/inet.h>
#include <errno.h>

#include "codegen.h"
#include "context.h"
#include "logger.h"
#include "match.h"

static int xt_udp_check(struct context *ctx,
			const struct bpfilter_ipt_match *ipt_match)
{
	const struct xt_udp *udp;

	udp = (const struct xt_udp *)&ipt_match->data;

	if (udp->invflags & XT_UDP_INV_MASK) {
		BFLOG_ERR("cannot check match 'udp': invalid flags\n");
		return -EINVAL;
	}

	return 0;
}

static int xt_udp_gen_inline_ports(struct codegen *ctx, int regno, bool inv,
				   const u16 (*ports)[2])
{
	if ((*ports)[0] == 0 && (*ports)[1] == 65535) {
		if (inv)
			EMIT_FIXUP(ctx, CODEGEN_FIXUP_NEXT_RULE,
				   BPF_JMP_IMM(BPF_JA, 0, 0, 0));
	} else if ((*ports)[0] == (*ports)[1]) {
		const u16 port = htons((*ports)[0]);

		EMIT_FIXUP(ctx, CODEGEN_FIXUP_NEXT_RULE,
			   BPF_JMP_IMM((inv ? BPF_JEQ : BPF_JNE), regno, port, 0));
	} else {
		EMIT_LITTLE_ENDIAN(ctx, BPF_ENDIAN(BPF_TO_BE, regno, 16));
		EMIT_FIXUP(ctx, CODEGEN_FIXUP_NEXT_RULE,
			   BPF_JMP_IMM(inv ? BPF_JGT : BPF_JLT, regno, (*ports)[0], 0));
		EMIT_FIXUP(ctx, CODEGEN_FIXUP_NEXT_RULE,
			   BPF_JMP_IMM(inv ? BPF_JLT : BPF_JGT, regno, (*ports)[1], 0));
	}

	return 0;
}

static int xt_udp_gen_inline(struct codegen *ctx, const struct match *match)
{
	const struct xt_udp *udp;
	int r;

	udp = (const struct xt_udp *)&match->ipt_match->data;

	EMIT(ctx, BPF_MOV64_REG(CODEGEN_REG_SCRATCH1, CODEGEN_REG_L4));
	EMIT(ctx, BPF_ALU64_IMM(BPF_ADD, CODEGEN_REG_SCRATCH1, sizeof(struct udphdr)));
	r = ctx->codegen_ops->load_packet_data_end(ctx, CODEGEN_REG_DATA_END);
	if (r) {
		BFLOG_ERR("failed to generate code to load packet data end: %s",
			  STRERR(r));
		return r;
	}

	EMIT_FIXUP(ctx, CODEGEN_FIXUP_NEXT_RULE,
		   BPF_JMP_REG(BPF_JGT, CODEGEN_REG_SCRATCH1, CODEGEN_REG_DATA_END, 0));

	EMIT(ctx, BPF_LDX_MEM(BPF_H, CODEGEN_REG_SCRATCH4, CODEGEN_REG_L4,
			      offsetof(struct udphdr, source)));
	EMIT(ctx, BPF_LDX_MEM(BPF_H, CODEGEN_REG_SCRATCH5, CODEGEN_REG_L4,
			      offsetof(struct udphdr, dest)));

	r = xt_udp_gen_inline_ports(ctx, CODEGEN_REG_SCRATCH4,
				    udp->invflags & XT_UDP_INV_SRCPT,
				    &udp->spts);
	if (r) {
		BFLOG_ERR("failed to generate code to match source ports: %s",
			  STRERR(r));
		return r;
	}

	r = xt_udp_gen_inline_ports(ctx, CODEGEN_REG_SCRATCH5,
				    udp->invflags & XT_UDP_INV_DSTPT,
				    &udp->dpts);
	if (r) {
		BFLOG_ERR("failed to generate code to match destination ports: %s",
			  STRERR(r));
		return r;
	}

	return 0;
}

const struct match_ops xt_udp = {
	.name = "udp",
	.size = XT_ALIGN(sizeof(struct xt_udp)),
	.revision = 0,
	.check = xt_udp_check,
	.gen_inline = xt_udp_gen_inline
};
