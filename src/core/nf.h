// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#pragma once

#include <linux/netfilter.h>

#include "core/hook.h"

enum nf_inet_hooks bf_hook_to_nf_hook(enum bf_hook hook);