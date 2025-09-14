/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#include "fake.h"

// clang-format off
#include <setjmp.h> // NOLINT: required by cmocka.h
#include <cmocka.h>
// clang-format on

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "bpfilter/cgen/cgen.h"
#include "bpfilter/cgen/program.h"
#include "bpfilter/xlate/nft/nfgroup.h"
#include "bpfilter/chain.h"
#include "bpfilter/front.h"
#include "bpfilter/helper.h"
#include "bpfilter/hook.h"
#include "bpfilter/rule.h"
#include "bpfilter/verdict.h"

struct nlmsghdr;

struct bf_chain *bf_test_chain(enum bf_hook hook, enum bf_verdict policy)
{
    struct bf_chain *chain;

    assert_int_equal(0, bf_chain_new(&chain, "bf_chain", hook, policy, NULL, NULL));

    return chain;
}

struct bf_cgen *bf_test_cgen(enum bf_front front, enum bf_hook hook,
                             enum bf_verdict verdict)
{
    struct bf_cgen *cgen;
    struct bf_chain *chain = bf_test_chain(hook, verdict);

    assert_int_equal(0, bf_cgen_new(&cgen, front, &chain));

    return cgen;
}

struct bf_rule *bf_test_get_rule(size_t nmatchers)
{
    _free_bf_rule_ struct bf_rule *rule = NULL;

    assert_int_equal(0, bf_rule_new(&rule));

    rule->index = 1;

    for (size_t i = 0; i < nmatchers; ++i)
        assert_int_equal(
            0, bf_rule_add_matcher(rule, 0, 0, (void *)&i, sizeof(i)));

    rule->counters = true;
    rule->verdict = 1;

    return TAKE_PTR(rule);
}
