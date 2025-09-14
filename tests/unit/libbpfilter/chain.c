/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#include "libbpfilter/chain.c"

#include "harness/filters.h"
#include "harness/test.h"
#include "mock.h"

Test(chain, new_free_assert_failure)
{
    expect_assert_failure(bf_chain_new(NULL, NOT_NULL, 0, 0, NULL, NULL));
    expect_assert_failure(bf_chain_new(NOT_NULL, NULL, 0, 0, NULL, NULL));
    expect_assert_failure(bf_chain_new(NOT_NULL, NOT_NULL, 0, _BF_TERMINAL_VERDICT_MAX + 1, NULL, NULL));

    expect_assert_failure(bf_chain_free(NULL));
}

Test(chain, new_free)
{
    _free_bf_chain_ struct bf_chain *chain = NULL;
    _clean_bf_list_ bf_list rules = bf_list_default(bf_rule_free, NULL);
    size_t i;

    assert_success(bf_chain_new(&chain, "name", 0, 0, NULL, NULL));
    bf_chain_free(&chain);
    assert_null(chain);

    assert_success(bf_list_add_tail(&rules, bf_rule_get(0, false, 0, bft_fake_matchers)));
    assert_success(bf_list_add_tail(&rules, bf_rule_get(0, false, 0, bft_fake_matchers)));

    i = 0;
    assert_success(bf_chain_new(&chain, "name", 0, 0, NULL, &rules));
    bf_list_foreach (&chain->rules, rule_node) {
        assert_int_equal(i++, ((struct bf_rule *)(bf_list_node_get_data(rule_node)))->index);
    }
}

Test(chain, pack_unpack)
{
    _free_bf_chain_ struct bf_chain *chain0 = NULL;
    _free_bf_chain_ struct bf_chain *chain1 = NULL;
    _free_bf_wpack_ bf_wpack_t *wpack = NULL;
    _free_bf_rpack_ bf_rpack_t *rpack = NULL;
    const void *data;
    size_t data_len;

    expect_assert_failure(bf_chain_pack(NULL, NOT_NULL));
    expect_assert_failure(bf_chain_pack(NOT_NULL, NULL));

    assert_non_null(chain0 = bf_test_chain_get(0, 0, NULL, bft_fake_rules));

    assert_success(bf_wpack_new(&wpack));
    assert_success(bf_chain_pack(chain0, wpack));
    assert_success(bf_wpack_get_data(wpack, &data, &data_len));

    assert_success(bf_rpack_new(&rpack, data, data_len));
    assert_success(bf_chain_new_from_pack(&chain1, bf_rpack_root(rpack)));

    assert_int_equal(bf_list_size(&chain0->rules), bf_list_size(&chain1->rules));
    assert_int_equal(bf_list_size(&chain0->sets), bf_list_size(&chain1->sets));

    {
        struct bf_list_node *n0 = bf_list_get_head(&chain0->rules);
        struct bf_list_node *n1 = bf_list_get_head(&chain1->rules);

        while (n0) {
            assert_int_equal(((struct bf_rule *)(bf_list_node_get_data(n0)))->index,
                             ((struct bf_rule *)(bf_list_node_get_data(n1)))->index);
            n0 = bf_list_node_next(n0);
            n1 = bf_list_node_next(n1);
        }
    }
}
