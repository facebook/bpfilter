/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2021 Telegram FZ-LLC
 * Copyright (c) 2022 Meta Platforms, Inc. and affiliates.
 */

#ifndef NET_BPFILTER_TARGET_H
#define NET_BPFILTER_TARGET_H

#include "../../include/uapi/linux/bpfilter.h"

#include <stdint.h>

struct codegen;
struct context;
struct target;
struct target_ops_map;

struct target_ops {
	char name[BPFILTER_EXTENSION_MAXNAMELEN];
	uint8_t revision;
	uint16_t size;
	int (*check)(struct context *ctx,
		     const struct bpfilter_ipt_target *ipt_target);
	int (*gen_inline)(struct codegen *ctx, const struct target *target);
};

struct target {
	const struct target_ops *target_ops;
	const struct bpfilter_ipt_target *ipt_target;
};

extern const struct target_ops standard_target_ops;
extern const struct target_ops error_target_ops;

/* Restore verdict's special value(ACCEPT, DROP, etc.) from its negative
 * representation.
 */
static inline int convert_verdict(int verdict)
{
	return -verdict - 1;
}

static inline int standard_target_verdict(const struct bpfilter_ipt_target *ipt_target)
{
	const struct bpfilter_ipt_standard_target *standard_target;

	standard_target = (const struct bpfilter_ipt_standard_target *)ipt_target;

	return standard_target->verdict;
}

int init_target(struct context *ctx,
		const struct bpfilter_ipt_target *ipt_target,
		struct target *target);

#endif // NET_BPFILTER_TARGET_H
