/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#include "core/set.c"

#include "core/list.h"
#include "core/logger.h"
#include "core/matcher.h"
#include "core/set.h"
#include "harness/test.h"

Test(set, new_and_free)
{
    _free_bf_set_ struct bf_set *set = NULL;

    expect_assert_failure(bf_set_new(NULL, NOT_NULL, 1));
    expect_assert_failure(bf_set_new(NOT_NULL, NULL, 1));
    expect_assert_failure(bf_set_free(NULL));

    // NOK: no components in key
    assert_error(bf_set_new(&set, (enum bf_matcher_type[]){
        BF_MATCHER_IP4_PROTO
    }, 0));

    // NOK: more components than the maximum value allowed
    assert_error(bf_set_new(&set, (enum bf_matcher_type[]){
        BF_MATCHER_IP4_PROTO
    }, BF_SET_MAX_N_COMPS + 1));

    // NOK: key contains an invalid matcher type
    assert_error(bf_set_new(&set, (enum bf_matcher_type[]){
        _BF_MATCHER_TYPE_MAX + 1, BF_MATCHER_IP4_PROTO
    }, 2));

    // NOK: using a CIDR matcher in combination with any other matcher
    assert_error(bf_set_new(&set, (enum bf_matcher_type[]){
        BF_MATCHER_IP6_DNET, BF_MATCHER_IP4_PROTO
    }, 2));
    assert_error(bf_set_new(&set, (enum bf_matcher_type[]){
        BF_MATCHER_IP6_DNET, BF_MATCHER_IP6_SNET
    }, 2));

    // OK: single component
    assert_success(bf_set_new(&set, (enum bf_matcher_type[]){
        BF_MATCHER_IP4_PROTO,
    }, 1));
    bf_set_free(&set);

    // OK: multiple components
    assert_success(bf_set_new(&set, (enum bf_matcher_type[]){
        BF_MATCHER_IP4_PROTO, BF_MATCHER_IP4_DADDR, BF_MATCHER_IP6_SADDR
    }, 3));
    assert_false(set->use_trie);
    bf_set_free(&set);

    // OK: single component, use trie
    assert_success(bf_set_new(&set, (enum bf_matcher_type[]){
        BF_MATCHER_IP6_SNET
    }, 1));
    assert_true(set->elem_size);

    // Let _free_bf_set_ free the set
}

Test(set, new_from_raw)
{
    _free_bf_set_ struct bf_set *set = NULL;

    expect_assert_failure(bf_set_new_from_raw(NULL, NOT_NULL, NOT_NULL));
    expect_assert_failure(bf_set_new_from_raw(NOT_NULL, NULL, NOT_NULL));
    expect_assert_failure(bf_set_new_from_raw(NOT_NULL, NOT_NULL, NULL));

    // NOK: empty key
    assert_error(bf_set_new_from_raw(&set, "()", "{}"));

    // NOK: too many key components
    assert_error(bf_set_new_from_raw(&set,
        "(ip4.proto,ip4.proto,ip4.proto,ip4.proto,"
        "ip4.proto,ip4.proto,ip4.proto,ip4.proto,ip4.proto)",
        "{}"
    ));

    // NOK: invalid key component
    assert_error(bf_set_new_from_raw(&set, "(ip4.invalid)", "{}"));

    // NOK: invalid delimiter
    assert_error(bf_set_new_from_raw(&set, "(ip4.proto; ip4.proto)", "{}"));

    // NOK: more components in element than key
    assert_error(bf_set_new_from_raw(&set, "(ip4.proto)", "{tcp, 21}"));

    // OK: no element
    assert_success(bf_set_new_from_raw(&set, "(ip4.proto)", "{}"));
    assert_int_equal(bf_list_size(&set->elems), 0);
    bf_set_free(&set);

    // OK: single element
    assert_success(bf_set_new_from_raw(&set, "(ip4.proto)", "{tcp}"));
    assert_int_equal(bf_list_size(&set->elems), 1);
    bf_set_free(&set);

    // OK: multiple elements
    assert_success(bf_set_new_from_raw(&set, "(ip4.proto)", "{tcp; udp; icmp}"));
    assert_int_equal(bf_list_size(&set->elems), 3);
    bf_set_free(&set);

    // OK: extra spaces
    assert_success(bf_set_new_from_raw(&set, "(ip4.proto)", "{tcp    ;    udp;    icmp}"));
    assert_int_equal(bf_list_size(&set->elems), 3);
    bf_set_free(&set);

    // OK: using \n as a delimiter
    assert_success(bf_set_new_from_raw(&set, "(ip4.proto)", "{tcp   \n  udp \n  icmp}"));
    assert_int_equal(bf_list_size(&set->elems), 3);
    bf_set_free(&set);

    // OK: contain an empty element
    assert_success(bf_set_new_from_raw(&set, "(ip4.proto)", "{tcp   \n\n udp \n  icmp}"));
    assert_int_equal(bf_list_size(&set->elems), 3);
    bf_set_free(&set);

    // OK: multiple components
    assert_success(bf_set_new_from_raw(&set,
        "(ip4.proto, ip4.saddr, ip4.daddr)",
        "{"
            "tcp, 192.168.1.1, 192.168.1.10\n"
            "tcp, 192.168.1.10, 192.168.71.10\n"
            "udp, 192.168.1.11, 192.168.12.140\n"
        "}"
    ));
    assert_int_equal(bf_list_size(&set->elems), 3);
    bf_set_free(&set);
}

Test(set, marsh_and_unmarsh)
{
    _free_bf_set_ struct bf_set *in = NULL;
    _free_bf_set_ struct bf_set *out = NULL;
    _free_bf_marsh_ struct bf_marsh *marsh = NULL;

    expect_assert_failure(bf_set_marsh(NOT_NULL, NULL));
    expect_assert_failure(bf_set_marsh(NULL, NOT_NULL));
    expect_assert_failure(bf_set_new_from_marsh(NOT_NULL, NULL));
    expect_assert_failure(bf_set_new_from_marsh(NULL, NOT_NULL));

    // Create a non-empty set
    assert_success(bf_set_new_from_raw(&in,
        "(ip4.proto, ip4.saddr, ip4.daddr)",
        "{"
            "tcp, 192.168.1.1, 192.168.1.10\n"
            "tcp, 192.168.1.10, 192.168.71.10\n"
            "udp, 192.168.1.11, 192.168.12.140\n"
        "}"
    ));

    // Marsh and unmarsh
    assert_success(bf_set_marsh(in, &marsh));
    assert_success(bf_set_new_from_marsh(&out, marsh));

    // Compare in and out
    assert_int_equal(in->n_comps, out->n_comps);
    assert_memory_equal(in->key, out->key, in->n_comps * sizeof(enum bf_matcher_type));
    assert_int_equal(in->elem_size, out->elem_size);
    assert_int_equal(in->use_trie, out->use_trie);
    assert_int_equal(bf_list_size(&in->elems), bf_list_size(&out->elems));

    for (size_t i = 0; i < bf_list_size(&in->elems); ++i) {
        void *in_data = bf_list_get_at(&in->elems, i);
        void *out_data = bf_list_get_at(&out->elems, i);

        assert_non_null(in_data);
        assert_non_null(out_data);

        assert_memory_equal(in_data, out_data, in->elem_size);
    }
}

Test(set, dump)
{
    _free_bf_set_ struct bf_set *set = NULL;
    enum bf_log_level cur_level = bf_log_get_level();

    expect_assert_failure(bf_set_dump(NOT_NULL, NULL));
    expect_assert_failure(bf_set_dump(NULL, NOT_NULL));

    // Create a non-empty set
    assert_success(bf_set_new_from_raw(&set,
        "(ip4.proto, ip4.saddr, ip4.daddr)",
        "{"
            "tcp, 192.168.1.1, 192.168.1.10\n"
            "tcp, 192.168.1.10, 192.168.71.10\n"
            "udp, 192.168.1.1, 192.168.1.10\n"
            "udp, 192.168.1.10, 192.168.71.10\n"
        "}"
    ));

    bf_log_set_level(BF_LOG_DBG);
    bf_set_dump(set, EMPTY_PREFIX);
    bf_log_set_level(cur_level);
}

Test(set, add_element)
{
    _free_bf_set_ struct bf_set *set = NULL;
    uint8_t elem[9] = {
        6, 127, 0, 0, 1, 192, 168, 1, 1,
    };

    expect_assert_failure(bf_set_add_elem(NOT_NULL, NULL));
    expect_assert_failure(bf_set_add_elem(NULL, NOT_NULL));

    // Create a non-empty set
    assert_success(bf_set_new_from_raw(&set,
        "(ip4.proto, ip4.saddr, ip4.daddr)", "{}"
    ));

    assert_success(bf_set_add_elem(set, elem));
}
