/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2022 Meta Platforms, Inc. and affiliates.
 */

#pragma once

#include <linux/netfilter_ipv4/ip_tables.h>

#include "xlate/frontend.h"

extern const struct bf_frontend ipt_frontend;

int bf_ipt_translate(void *data, size_t data_size,
                     bf_list (*codegens)[__BF_HOOK_MAX]);
int bf_ipt_dump(struct ipt_replace *ipt);
