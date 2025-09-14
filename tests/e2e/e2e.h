/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#pragma once

#include <limits.h>
#include <stddef.h>

#include "bpfilter/chain.h"
#include "bpfilter/counter.h"
#include "bpfilter/verdict.h"
#include "packets.h"

#define BFT_NO_PKTS SIZE_MAX
#define BFT_NO_BYTES SIZE_MAX

struct bft_counter
{
    size_t index;
    struct bf_counter counter;
};

#define bft_counter_p(idx, npkts, nbytes)                                      \
    (struct bft_counter []) {                                                  \
        {                                                                      \
            .index = (idx),                                                    \
            .counter = {                                                       \
                .packets = (npkts),                                            \
                .bytes = (nbytes),                                             \
            },                                                                 \
        }                                                                      \
    }

int bft_e2e_test_with_counter(struct bf_chain *chain, enum bf_verdict expect,
                              const struct bft_prog_run_args *args,
                              const struct bft_counter *counter);
int bft_e2e_test(struct bf_chain *chain, enum bf_verdict expect,
                 const struct bft_prog_run_args *args);
