/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2022 Meta Platforms, Inc. and affiliates.
 */

#pragma once

#include <linux/netfilter_ipv4/ip_tables.h>

/**
 * @brief Dump content of bpfilter_ipt_replace structure.
 *
 * @param ipt iptable's ipt_replace structure. Must be non-NULL.
 */
void bf_ipt_dump_replace(struct ipt_replace *ipt);
