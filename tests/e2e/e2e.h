/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#pragma once

#include "core/chain.h"
#include "core/verdict.h"
#include "packets.h"

int bft_e2e_test(struct bf_chain *chain, enum bf_verdict expect,
                 const struct bft_prog_run_args *args);
