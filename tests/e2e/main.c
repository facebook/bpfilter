/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#include "core/chain.h"
#include "core/logger.h"
#include "harness/filters.h"
#include "harness/test.h"
#include "e2e.h"
#include "opts.h"
#include "packets.h"

Test(policy, accept_no_rule)
{
    _cleanup_bf_chain_ struct bf_chain *chain = bf_test_chain_get(
        BF_HOOK_XDP,
        BF_VERDICT_ACCEPT,
        NULL,
        (struct bf_rule *[]) {
            NULL,
        }
    );

    bft_e2e_test(chain, BF_VERDICT_ACCEPT, pkt_local_ip6_tcp);
}

Test(ip6, saddr_eq_nomask_match)
{
    _cleanup_bf_chain_ struct bf_chain *chain = bf_test_chain_get(
        BF_HOOK_XDP,
        BF_VERDICT_ACCEPT,
        NULL,
        (struct bf_rule *[]) {
            bf_rule_get(
                false,
                BF_VERDICT_DROP,
                (struct bf_matcher *[]) {
                    bf_matcher_get(BF_MATCHER_IP6_SADDR, BF_MATCHER_EQ,
                        (uint8_t[]) {
                            // IP address
                            0x54, 0x2c, 0x1a, 0x31, 0xf9, 0x64, 0x94, 0x6c,
                            0x5a, 0x24, 0xe7, 0x1e, 0x4d, 0x26, 0xb8, 0x7e,
                            // Prefix
                            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                        },
                        32
                    ),
                    NULL,
                }
            ),
            NULL,
        }
    );

    bft_e2e_test(chain, BF_VERDICT_DROP, pkt_remote_ip6_tcp);
}

Test(ip6, saddr_eq_nomask_nomatch)
{
    _cleanup_bf_chain_ struct bf_chain *chain = bf_test_chain_get(
        BF_HOOK_XDP,
        BF_VERDICT_ACCEPT,
        NULL,
        (struct bf_rule *[]) {
            bf_rule_get(
                false,
                BF_VERDICT_DROP,
                (struct bf_matcher *[]) {
                    bf_matcher_get(BF_MATCHER_IP6_SADDR, BF_MATCHER_EQ,
                        (uint8_t[]) {
                            // IP address
                            0x54, 0x2c, /* Modified */ 0x11, 0x31, 0xf9, 0x64, 0x94, 0x6c,
                            0x5a, 0x24, 0xe7, 0x1e, 0x4d, 0x26, 0xb8, 0x7e,
                            // Prefix
                            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                        },
                        32
                    ),
                    NULL,
                }
            ),
            NULL,
        }
    );

    bft_e2e_test(chain, BF_VERDICT_ACCEPT, pkt_remote_ip6_tcp);
}

Test(ip6, saddr_ne_nomask_match)
{
    _cleanup_bf_chain_ struct bf_chain *chain = bf_test_chain_get(
        BF_HOOK_XDP,
        BF_VERDICT_ACCEPT,
        NULL,
        (struct bf_rule *[]) {
            bf_rule_get(
                false,
                BF_VERDICT_DROP,
                (struct bf_matcher *[]) {
                    bf_matcher_get(BF_MATCHER_IP6_SADDR, BF_MATCHER_NE,
                        (uint8_t[]) {
                            // IP address
                            0x54, 0x2c, 0x1a, 0x31, 0xf9, 0x64, 0x94, 0x6c,
                            0x5a, 0x24, 0xe7, 0x1e, 0x4d, 0x26, 0xb8, 0x7e,
                            // Prefix
                            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                        },
                        32
                    ),
                    NULL,
                }
            ),
            NULL,
        }
    );

    bft_e2e_test(chain, BF_VERDICT_ACCEPT, pkt_remote_ip6_tcp);
}

Test(ip6, saddr_ne_nomask_nomatch)
{
    _cleanup_bf_chain_ struct bf_chain *chain = bf_test_chain_get(
        BF_HOOK_XDP,
        BF_VERDICT_ACCEPT,
        NULL,
        (struct bf_rule *[]) {
            bf_rule_get(
                false,
                BF_VERDICT_DROP,
                (struct bf_matcher *[]) {
                    bf_matcher_get(BF_MATCHER_IP6_SADDR, BF_MATCHER_NE,
                        (uint8_t[]) {
                            // IP address
                            0x54, 0x2c, /* Modified */ 0x11, 0x31, 0xf9, 0x64, 0x94, 0x6c,
                            0x5a, 0x24, 0xe7, 0x1e, 0x4d, 0x26, 0xb8, 0x7e,
                            // Prefix
                            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                        },
                        32
                    ),
                    NULL,
                }
            ),
            NULL,
        }
    );

    bft_e2e_test(chain, BF_VERDICT_DROP, pkt_remote_ip6_tcp);
}

Test(ip6, saddr_eq_8mask_match)
{
    _cleanup_bf_chain_ struct bf_chain *chain = bf_test_chain_get(
        BF_HOOK_XDP,
        BF_VERDICT_ACCEPT,
        NULL,
        (struct bf_rule *[]) {
            bf_rule_get(
                false,
                BF_VERDICT_DROP,
                (struct bf_matcher *[]) {
                    bf_matcher_get(BF_MATCHER_IP6_SADDR, BF_MATCHER_EQ,
                        (uint8_t[]) {
                            // IP address
                            0x54, /* Modified */ 0x2d, 0x1a, 0x31, 0xf9, 0x64, 0x94, 0x6c,
                            0x5a, 0x24, 0xe7, 0x1e, 0x4d, 0x26, 0xb8, 0x7e,
                            // Prefix
                            0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                        },
                        32
                    ),
                    NULL,
                }
            ),
            NULL,
        }
    );

    bft_e2e_test(chain, BF_VERDICT_DROP, pkt_remote_ip6_tcp);
}

Test(ip6, saddr_eq_8mask_nomatch)
{
    _cleanup_bf_chain_ struct bf_chain *chain = bf_test_chain_get(
        BF_HOOK_XDP,
        BF_VERDICT_ACCEPT,
        NULL,
        (struct bf_rule *[]) {
            bf_rule_get(
                false,
                BF_VERDICT_DROP,
                (struct bf_matcher *[]) {
                    bf_matcher_get(BF_MATCHER_IP6_SADDR, BF_MATCHER_EQ,
                        (uint8_t[]) {
                            // IP address
                            /* Modified */ 0x55, 0x2c, 0x1a, 0x31, 0xf9, 0x64, 0x94, 0x6c,
                            0x5a, 0x24, 0xe7, 0x1e, 0x4d, 0x26, 0xb8, 0x7e,
                            // Prefix
                            0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                        },
                        32
                    ),
                    NULL,
                }
            ),
            NULL,
        }
    );

    bft_e2e_test(chain, BF_VERDICT_ACCEPT, pkt_remote_ip6_tcp);
}

Test(ip6, saddr_ne_8mask_match)
{
    _cleanup_bf_chain_ struct bf_chain *chain = bf_test_chain_get(
        BF_HOOK_XDP,
        BF_VERDICT_ACCEPT,
        NULL,
        (struct bf_rule *[]) {
            bf_rule_get(
                false,
                BF_VERDICT_DROP,
                (struct bf_matcher *[]) {
                    bf_matcher_get(BF_MATCHER_IP6_SADDR, BF_MATCHER_NE,
                        (uint8_t[]) {
                            // IP address
                            /* Modified */ 0x55, 0x2c, 0x1a, 0x31, 0xf9, 0x64, 0x94, 0x6c,
                            0x5a, 0x24, 0xe7, 0x1e, 0x4d, 0x26, 0xb8, 0x7e,
                            // Prefix
                            0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                        },
                        32
                    ),
                    NULL,
                }
            ),
            NULL,
        }
    );

    bft_e2e_test(chain, BF_VERDICT_DROP, pkt_remote_ip6_tcp);
}

Test(ip6, saddr_ne_8mask_nomatch)
{
    _cleanup_bf_chain_ struct bf_chain *chain = bf_test_chain_get(
        BF_HOOK_XDP,
        BF_VERDICT_ACCEPT,
        NULL,
        (struct bf_rule *[]) {
            bf_rule_get(
                false,
                BF_VERDICT_DROP,
                (struct bf_matcher *[]) {
                    bf_matcher_get(BF_MATCHER_IP6_SADDR, BF_MATCHER_NE,
                        (uint8_t[]) {
                            // IP address
                            0x54, 0x2c, 0x1a, 0x31, 0xf9, 0x64, 0x94, 0x6c,
                            /* Modified */ 0x5b, 0x24, 0xe7, 0x1e, 0x4d, 0x26, 0xb8, 0x7e,
                            // Prefix
                            0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                        },
                        32
                    ),
                    NULL,
                }
            ),
            NULL,
        }
    );

    bft_e2e_test(chain, BF_VERDICT_ACCEPT, pkt_remote_ip6_tcp);
}

Test(ip6, saddr_eq_120mask_match)
{
    _cleanup_bf_chain_ struct bf_chain *chain = bf_test_chain_get(
        BF_HOOK_XDP,
        BF_VERDICT_ACCEPT,
        NULL,
        (struct bf_rule *[]) {
            bf_rule_get(
                false,
                BF_VERDICT_DROP,
                (struct bf_matcher *[]) {
                    bf_matcher_get(BF_MATCHER_IP6_SADDR, BF_MATCHER_EQ,
                        (uint8_t[]) {
                            0x54, 0x2c, 0x1a, 0x31, 0xf9, 0x64, 0x94, 0x6c,
                            0x5a, 0x24, 0xe7, 0x1e, 0x4d, 0x26, 0xb8, /* Modified */ 0x7f,
                            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00,
                        },
                        32
                    ),
                    NULL,
                }
            ),
            NULL,
        }
    );

    bft_e2e_test(chain, BF_VERDICT_DROP, pkt_remote_ip6_tcp);
}

Test(ip6, saddr_eq_120mask_nomatch)
{
    _cleanup_bf_chain_ struct bf_chain *chain = bf_test_chain_get(
        BF_HOOK_XDP,
        BF_VERDICT_ACCEPT,
        NULL,
        (struct bf_rule *[]) {
            bf_rule_get(
                false,
                BF_VERDICT_DROP,
                (struct bf_matcher *[]) {
                    bf_matcher_get(BF_MATCHER_IP6_SADDR, BF_MATCHER_EQ,
                        (uint8_t[]) {
                            // IP address
                            /* Modified */ 0x55, 0x2c, 0x1a, 0x31, 0xf9, 0x64, 0x94, 0x6c,
                            0x5a, 0x24, 0xe7, 0x1e, 0x4d, 0x26, 0xb8, 0x7e,
                            // Prefix
                            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00,
                        },
                        32
                    ),
                    NULL,
                }
            ),
            NULL,
        }
    );

    bft_e2e_test(chain, BF_VERDICT_ACCEPT, pkt_remote_ip6_tcp);
}

Test(ip6, saddr_ne_120mask_nomatch)
{
    _cleanup_bf_chain_ struct bf_chain *chain = bf_test_chain_get(
        BF_HOOK_XDP,
        BF_VERDICT_ACCEPT,
        NULL,
        (struct bf_rule *[]) {
            bf_rule_get(
                false,
                BF_VERDICT_DROP,
                (struct bf_matcher *[]) {
                    bf_matcher_get(BF_MATCHER_IP6_SADDR, BF_MATCHER_NE,
                        (uint8_t[]) {
                            // IP address
                            0x54, 0x2c, 0x1a, 0x31, 0xf9, 0x64, 0x94, 0x6c,
                            0x5a, 0x24, 0xe7, 0x1e, 0x4d, 0x26, 0xb8, /* Modified */ 0x7f,
                            // Prefix
                            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00,
                        },
                        32
                    ),
                    NULL,
                }
            ),
            NULL,
        }
    );

    bft_e2e_test(chain, BF_VERDICT_ACCEPT, pkt_remote_ip6_tcp);
}

Test(ip6, saddr_ne_120mask_match)
{
    _cleanup_bf_chain_ struct bf_chain *chain = bf_test_chain_get(
        BF_HOOK_XDP,
        BF_VERDICT_ACCEPT,
        NULL,
        (struct bf_rule *[]) {
            bf_rule_get(
                false,
                BF_VERDICT_DROP,
                (struct bf_matcher *[]) {
                    bf_matcher_get(BF_MATCHER_IP6_SADDR, BF_MATCHER_NE,
                        (uint8_t[]) {
                            // IP address
                            0x54, 0x2c, 0x1a, 0x31, 0xf9, /* Modified */ 0x65, 0x94, 0x6c,
                            0x5a, 0x24, 0xe7, 0x1e, 0x4d, 0x26, 0xb8, 0x7e,
                            // Prefix
                            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00,
                        },
                        32
                    ),
                    NULL,
                }
            ),
            NULL,
        }
    );

    bft_e2e_test(chain, BF_VERDICT_DROP, pkt_remote_ip6_tcp);
}

struct bf_set *make_ip6port_set(size_t nelems, uint8_t *matching_elem)
{
    _cleanup_bf_set_ struct bf_set *set = NULL;
    int r;

    r = bf_set_new(&set, BF_SET_SRCIP6PORT);
    if (r < 0) {
        bf_err_r(r, "failed to create a new set");
        return NULL;
    }

    if (matching_elem) {
        r = bf_set_add_elem(set, matching_elem);
        if (r < 0) {
            bf_err_r(r, "failed to add matching element to set");
            return NULL;
        }
    }

    for (size_t i = 0; i < nelems; i++) {
        uint8_t elem[18] = {};

        for (int j = 0; j < (int)ARRAY_SIZE(elem); j++)
            elem[j] = rand() % 256;

        r = bf_set_add_elem(set, elem);
        if (r < 0) {
            bf_err_r(r, "failed to add key to set");
            return NULL;
        }
    }

    return TAKE_PTR(set);
}

Test(ip6, port_200kset_match)
{
    _cleanup_bf_chain_ struct bf_chain *chain = bf_test_chain_get(
        BF_HOOK_XDP,
        BF_VERDICT_ACCEPT,
        (struct bf_set *[]) {
            make_ip6port_set(200000, (uint8_t[]){0x54, 0x2c, 0x1a, 0x31, 0xf9, 0x64, 0x94, 0x6c, 0x5a, 0x24, 0xe7, 0x1e, 0x4d, 0x26, 0xb8, 0x7e, 0x7a, 0x69}),
            NULL,
        },
        (struct bf_rule *[]) {
            bf_rule_get(
                false,
                BF_VERDICT_DROP,
                (struct bf_matcher *[]) {
                    bf_matcher_get(BF_MATCHER_SET_SRCIP6PORT, BF_MATCHER_IN,
                        (uint32_t[]) {0}, 4
                    ),
                    NULL,
                }
            ),
            NULL,
        }
    );

    bft_e2e_test(chain, BF_VERDICT_DROP, pkt_remote_ip6_tcp);
}

Test(ip6, port_200kset_nomatch)
{
    _cleanup_bf_chain_ struct bf_chain *chain = bf_test_chain_get(
        BF_HOOK_XDP,
        BF_VERDICT_ACCEPT,
        (struct bf_set *[]) {
            make_ip6port_set(200000, NULL),
            NULL,
        },
        (struct bf_rule *[]) {
            bf_rule_get(
                false,
                BF_VERDICT_DROP,
                (struct bf_matcher *[]) {
                    bf_matcher_get(BF_MATCHER_SET_SRCIP6PORT, BF_MATCHER_IN,
                        (uint32_t[]) {0}, 4
                    ),
                    NULL,
                }
            ),
            NULL,
        }
    );

    bft_e2e_test(chain, BF_VERDICT_ACCEPT, pkt_remote_ip6_tcp);
}

struct bf_set *make_ip6_set(size_t nelems, uint8_t *matching_elem)
{
    _cleanup_bf_set_ struct bf_set *set = NULL;
    int r;

    r = bf_set_new(&set, BF_SET_SRCIP6);
    if (r < 0) {
        bf_err_r(r, "failed to create a new set");
        return NULL;
    }

    if (matching_elem) {
        r = bf_set_add_elem(set, matching_elem);
        if (r < 0) {
            bf_err_r(r, "failed to add matching element to set");
            return NULL;
        }
    }

    for (size_t i = 0; i < nelems; i++) {
        uint8_t elem[16] = {};

        for (int j = 0; j < (int)ARRAY_SIZE(elem); j++)
            elem[j] = rand() % 256;

        r = bf_set_add_elem(set, elem);
        if (r < 0) {
            bf_err_r(r, "failed to add key to set");
            return NULL;
        }
    }

    return TAKE_PTR(set);
}

Test(ip6, addrport_200kset_match)
{
    _cleanup_bf_chain_ struct bf_chain *chain = bf_test_chain_get(
        BF_HOOK_XDP,
        BF_VERDICT_ACCEPT,
        (struct bf_set *[]) {
            make_ip6_set(200000, (uint8_t[]){0x54, 0x2c, 0x1a, 0x31, 0xf9, 0x64, 0x94, 0x6c, 0x5a, 0x24, 0xe7, 0x1e, 0x4d, 0x26, 0xb8, 0x7e}),
            NULL,
        },
        (struct bf_rule *[]) {
            bf_rule_get(
                false,
                BF_VERDICT_DROP,
                (struct bf_matcher *[]) {
                    bf_matcher_get(BF_MATCHER_SET_SRCIP6PORT, BF_MATCHER_IN,
                        (uint32_t[]) {0}, 4
                    ),
                    NULL,
                }
            ),
            NULL,
        }
    );

    bft_e2e_test(chain, BF_VERDICT_DROP, pkt_remote_ip6_tcp);
}

Test(ip6, addrport_200kset_nomatch)
{
    _cleanup_bf_chain_ struct bf_chain *chain = bf_test_chain_get(
        BF_HOOK_XDP,
        BF_VERDICT_ACCEPT,
        (struct bf_set *[]) {
            make_ip6_set(200000, NULL),
            NULL,
        },
        (struct bf_rule *[]) {
            bf_rule_get(
                false,
                BF_VERDICT_DROP,
                (struct bf_matcher *[]) {
                    bf_matcher_get(BF_MATCHER_SET_SRCIP6PORT, BF_MATCHER_IN,
                        (uint32_t[]) {0}, 4
                    ),
                    NULL,
                }
            ),
            NULL,
        }
    );

    bft_e2e_test(chain, BF_VERDICT_ACCEPT, pkt_remote_ip6_tcp);
}

int main(int argc, char *argv[])
{
    _free_bf_test_suite_ bf_test_suite *suite = NULL;
    int failed = 0;
    int r;

    r = bft_e2e_parse_args(argc, argv);
    if (r)
        return r;

    r = bf_test_discover_test_suite(&suite);
    if (r < 0)
        return bf_err_r(r, "test suite discovery failed");

    bf_list_foreach (&suite->groups, group_node) {
        bf_test_group *group = bf_list_node_get_data(group_node);

        r = _cmocka_run_group_tests(group->name, group->cmtests,
                                    bf_list_size(&group->tests), NULL, NULL);
        if (r) {
            failed = 1;
            break;
        }
    }

    if (failed)
        fail_msg("At least one test group failed!");

    return 0;
}
