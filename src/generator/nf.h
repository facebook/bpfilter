/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#pragma once

#include <linux/netfilter.h>

#include "core/flavor.h"
#include "core/hook.h"

extern const struct bf_flavor_ops bf_flavor_ops_nf;

enum nf_inet_hooks bf_hook_to_nf_hook(enum bf_hook hook);
