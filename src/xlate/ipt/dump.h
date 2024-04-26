/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2022 Meta Platforms, Inc. and affiliates.
 */

#pragma once

#include "core/dump.h"

struct ipt_replace;

/**
 * @brief Dump content of bpfilter_ipt_replace structure.
 *
 * @param ipt iptable's ipt_replace structure. Must be non-NULL.
 * @param prefix Prefix to print on each line.
 */
void bf_ipt_dump_replace(struct ipt_replace *ipt, prefix_t *prefix);
