/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#include "cgen/runtime.h"
#include "bpfilter/chain.h"
#include "bpfilter/logger.h"
#include "bpfilter/matcher.h"
#include "bpfilter/runtime.h"
#include "e2e.h"
#include "harness/filters.h"
#include "harness/test.h"
#include "opts.h"
#include "packets.h"

Test(policy, accept_no_rule)
{
    _free_bf_chain_ struct bf_chain *chain =
        bf_test_chain_get(BF_HOOK_XDP, BF_VERDICT_ACCEPT, NULL,
                          (struct bf_rule *[]) {
                              NULL,
                          });

    bft_e2e_test(chain, BF_VERDICT_ACCEPT, pkt_local_ip6_tcp);
}

Test(counters, update_partially_disabled)
{
    // Counters should be properly updated, even though some rules have counters
    // disabled
    _free_bf_chain_ struct bf_chain *chain = bf_test_chain_get(
        BF_HOOK_XDP, BF_VERDICT_ACCEPT, NULL,
        (struct bf_rule *[]) {
            // Do not match
            bf_rule_get(0, false, BF_VERDICT_ACCEPT,
                        (struct bf_matcher *[]) {
                            bf_matcher_get(BF_MATCHER_IP6_SADDR, BF_MATCHER_EQ,
                                           (uint8_t[]) {
                                               // IP address
                                               0x54, /* Modified */ 0x2d, 0x1a, 0x31, 0xf9, 0x64, 0x94, 0x6c,
                                               0x5a, 0x24, 0xe7, 0x1e, 0x4d, 0x26, 0xb8, 0x7e,
                                               // Prefix
                                               0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                                               0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                                           },
                                           32),
                            NULL,
                        }),
            // Match
            bf_rule_get(0, true, BF_VERDICT_DROP,
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
                                           32),
                            NULL,
                        }),
            NULL,
        });

    bft_e2e_test_with_counter(chain, BF_VERDICT_DROP, pkt_remote_ip6_tcp,
                              bft_counter_p(1, 1, BFT_NO_BYTES));
}

Test(counters, packet_size)
{
    // Counters should be properly updated, even though some rules have counters
    // disabled
    _free_bf_chain_ struct bf_chain *chain = bf_test_chain_get(
        BF_HOOK_XDP, BF_VERDICT_ACCEPT, NULL,
        (struct bf_rule *[]) {
            // Do not match
            bf_rule_get(0, true, BF_VERDICT_ACCEPT,
                        (struct bf_matcher *[]) {
                            bf_matcher_get(BF_MATCHER_IP4_SADDR, BF_MATCHER_EQ,
                                           (uint8_t[]) {
                                                127, 2, 10, 10
                                           },
                                           4),
                            NULL,
                        }),
            NULL,
        });

    bft_e2e_test_with_counter(chain, BF_VERDICT_ACCEPT, pkt_local_ip4,
                              bft_counter_p(0, 1, pkt_local_ip4[0].pkt_len));
}

Test(mark, set_mark_then_read)
{
    _free_bf_rule_ struct bf_rule *rule_mark = 
        bf_rule_get(0, true, BF_VERDICT_CONTINUE, (struct bf_matcher *[]) {
            bf_matcher_get(BF_MATCHER_IP4_SADDR, BF_MATCHER_EQ,
                (uint8_t[]) {
                    127, 2, 10, 10
                },
                4),
            NULL,
        });
    bf_rule_mark_set(rule_mark, 0xff);

    _free_bf_rule_ struct bf_rule *rule_match = 
        bf_rule_get(0, true, BF_VERDICT_ACCEPT, (struct bf_matcher *[]) {
            bf_matcher_get(BF_MATCHER_META_MARK, BF_MATCHER_EQ,
                (uint32_t[]) {
                    0xff
                },
                4),
            NULL,
        });

    _free_bf_chain_ struct bf_chain *chain = bf_test_chain_get(
        BF_HOOK_XDP, BF_VERDICT_ACCEPT, NULL,
        (struct bf_rule *[]) {
            TAKE_PTR(rule_mark),
            TAKE_PTR(rule_match),
            NULL,
         });

    bft_e2e_test_with_counter(chain, BF_VERDICT_ACCEPT, pkt_local_ip4,
                              bft_counter_p(1, 1, pkt_local_ip4[0].pkt_len));
}

Test(meta, l4_proto)
{
    _free_bf_chain_ struct bf_chain *match_eq = bf_test_chain_get(
        BF_HOOK_XDP,
        BF_VERDICT_ACCEPT,
        NULL,
        (struct bf_rule *[]) {
            bf_rule_get(
                0,
                false,
                BF_VERDICT_DROP,
                (struct bf_matcher *[]) {
                    bf_matcher_get(BF_MATCHER_META_L4_PROTO, BF_MATCHER_EQ,
                        (uint8_t[]) {
                            0x06,
                        },
                        1
                    ),
                    NULL,
                }
            ),
            NULL,
        }
    );

    _free_bf_chain_ struct bf_chain *nomatch_eq = bf_test_chain_get(
        BF_HOOK_XDP,
        BF_VERDICT_ACCEPT,
        NULL,
        (struct bf_rule *[]) {
            bf_rule_get(
                0,
                false,
                BF_VERDICT_DROP,
                (struct bf_matcher *[]) {
                    bf_matcher_get(BF_MATCHER_META_L4_PROTO, BF_MATCHER_EQ,
                        (uint8_t[]) {
                            0x01,
                        },
                        1
                    ),
                    NULL,
                }
            ),
            NULL,
        }
    );

    _free_bf_chain_ struct bf_chain *match_ne = bf_test_chain_get(
        BF_HOOK_XDP,
        BF_VERDICT_ACCEPT,
        NULL,
        (struct bf_rule *[]) {
            bf_rule_get(
                0,
                false,
                BF_VERDICT_DROP,
                (struct bf_matcher *[]) {
                    bf_matcher_get(BF_MATCHER_META_L4_PROTO, BF_MATCHER_NE,
                        (uint8_t[]) {
                            0x01,
                        },
                        1
                    ),
                    NULL,
                }
            ),
            NULL,
        }
    );

    _free_bf_chain_ struct bf_chain *nomatch_ne = bf_test_chain_get(
        BF_HOOK_XDP,
        BF_VERDICT_ACCEPT,
        NULL,
        (struct bf_rule *[]) {
            bf_rule_get(
                0,
                false,
                BF_VERDICT_DROP,
                (struct bf_matcher *[]) {
                    bf_matcher_get(BF_MATCHER_META_L4_PROTO, BF_MATCHER_NE,
                        (uint8_t[]) {
                            0x06,
                        },
                        1
                    ),
                    NULL,
                }
            ),
            NULL,
        }
    );

    bft_e2e_test(match_eq, BF_VERDICT_DROP, pkt_remote_ip6_eh_tcp);
    bft_e2e_test(nomatch_eq, BF_VERDICT_ACCEPT, pkt_remote_ip6_eh_tcp);
    bft_e2e_test(match_ne, BF_VERDICT_DROP, pkt_remote_ip6_eh_tcp);
    bft_e2e_test(nomatch_ne, BF_VERDICT_ACCEPT, pkt_remote_ip6_eh_tcp);
}

Test(meta, probability)
{
    _free_bf_chain_ struct bf_chain *always_drop = bf_test_chain_get(
        BF_HOOK_XDP, BF_VERDICT_ACCEPT, NULL,
        (struct bf_rule *[]) {
            bf_rule_get(
                0, false, BF_VERDICT_DROP,
                (struct bf_matcher *[]) {
                    bf_matcher_get(BF_MATCHER_META_PROBABILITY, BF_MATCHER_EQ,
                                   (uint8_t[]) { 100 },
                                   1),
                    NULL,
                }),
            NULL,
        });
    bft_e2e_test(always_drop, BF_VERDICT_DROP, pkt_local_ip6_hop);

    _free_bf_chain_ struct bf_chain *never_drop = bf_test_chain_get(
        BF_HOOK_XDP, BF_VERDICT_ACCEPT, NULL,
        (struct bf_rule *[]) {
            bf_rule_get(
                0, false, BF_VERDICT_DROP,
                (struct bf_matcher *[]) {
                    bf_matcher_get(BF_MATCHER_META_PROBABILITY, BF_MATCHER_EQ,
                                   (uint8_t[]) { 0 },
                                   1),
                    NULL,
                }),
            NULL,
        });
    bft_e2e_test(never_drop, BF_VERDICT_ACCEPT, pkt_local_ip6_hop);
}

Test(ip4, proto)
{
    _free_bf_chain_ struct bf_chain *match_eq = bf_test_chain_get(
        BF_HOOK_XDP,
        BF_VERDICT_ACCEPT,
        NULL,
        (struct bf_rule *[]) {
            bf_rule_get(
                0,
                false,
                BF_VERDICT_DROP,
                (struct bf_matcher *[]) {
                    bf_matcher_get(BF_MATCHER_IP4_PROTO, BF_MATCHER_EQ,
                        (uint8_t[]) {
                            0x01,
                        },
                        1
                    ),
                    NULL,
                }
            ),
            NULL,
        }
    );

    _free_bf_chain_ struct bf_chain *nomatch_eq = bf_test_chain_get(
        BF_HOOK_XDP,
        BF_VERDICT_ACCEPT,
        NULL,
        (struct bf_rule *[]) {
            bf_rule_get(
                0,
                false,
                BF_VERDICT_DROP,
                (struct bf_matcher *[]) {
                    bf_matcher_get(BF_MATCHER_IP4_PROTO, BF_MATCHER_EQ,
                        (uint8_t[]) {
                            0x06,
                        },
                        1
                    ),
                    NULL,
                }
            ),
            NULL,
        }
    );

    _free_bf_chain_ struct bf_chain *match_ne = bf_test_chain_get(
        BF_HOOK_XDP,
        BF_VERDICT_ACCEPT,
        NULL,
        (struct bf_rule *[]) {
            bf_rule_get(
                0,
                false,
                BF_VERDICT_DROP,
                (struct bf_matcher *[]) {
                    bf_matcher_get(BF_MATCHER_IP4_PROTO, BF_MATCHER_NE,
                        (uint8_t[]) {
                            0x06
                        },
                        1
                    ),
                    NULL,
                }
            ),
            NULL,
        }
    );

    _free_bf_chain_ struct bf_chain *nomatch_ne = bf_test_chain_get(
        BF_HOOK_XDP,
        BF_VERDICT_ACCEPT,
        NULL,
        (struct bf_rule *[]) {
            bf_rule_get(
                0,
                false,
                BF_VERDICT_DROP,
                (struct bf_matcher *[]) {
                    bf_matcher_get(BF_MATCHER_IP4_PROTO, BF_MATCHER_NE,
                        (uint8_t[]) {
                            0x01
                        },
                        1
                    ),
                    NULL,
                }
            ),
            NULL,
        }
    );

    bft_e2e_test(match_eq, BF_VERDICT_DROP, pkt_local_ip4_icmp);
    bft_e2e_test(nomatch_eq, BF_VERDICT_ACCEPT, pkt_local_ip4_icmp);
    bft_e2e_test(match_ne, BF_VERDICT_DROP, pkt_local_ip4_icmp);
    bft_e2e_test(nomatch_ne, BF_VERDICT_ACCEPT, pkt_local_ip4_icmp);
}

Test(ip4, saddr)
{
    _free_bf_chain_ struct bf_chain *match_eq_pkt = bf_test_chain_get(
        BF_HOOK_XDP,
        BF_VERDICT_ACCEPT,
        NULL,
        (struct bf_rule *[]) {
            bf_rule_get(
                0,
                false,
                BF_VERDICT_DROP,
                (struct bf_matcher *[]) {
                    bf_matcher_get(BF_MATCHER_IP4_SADDR, BF_MATCHER_EQ,
                        (uint8_t[]) {
                            // IP address
                            0x7f, 0x02, 0x0a, 0x0a
                        },
                        4
                    ),
                    NULL,
                }
            ),
            NULL,
        }
    );

    _free_bf_chain_ struct bf_chain *nomatch_eq_pkt = bf_test_chain_get(
        BF_HOOK_XDP,
        BF_VERDICT_ACCEPT,
        NULL,
        (struct bf_rule *[]) {
            bf_rule_get(
                0,
                false,
                BF_VERDICT_DROP,
                (struct bf_matcher *[]) {
                    bf_matcher_get(BF_MATCHER_IP4_SADDR, BF_MATCHER_EQ,
                        (uint8_t[]) {
                            // IP address
                            0x7f, 0x02, 0x0a, 0x0b
                        },
                        4
                    ),
                    NULL,
                }
            ),
            NULL,
        }
    );

    _free_bf_chain_ struct bf_chain *match_ne_pkt = bf_test_chain_get(
        BF_HOOK_XDP,
        BF_VERDICT_ACCEPT,
        NULL,
        (struct bf_rule *[]) {
            bf_rule_get(
                0,
                false,
                BF_VERDICT_DROP,
                (struct bf_matcher *[]) {
                    bf_matcher_get(BF_MATCHER_IP4_SADDR, BF_MATCHER_NE,
                        (uint8_t[]) {
                            // IP address
                            0x7f, 0x02, 0x0a, 0x0b
                        },
                        4
                    ),
                    NULL,
                }
            ),
            NULL,
        }
    );

    _free_bf_chain_ struct bf_chain *nomatch_ne_pkt = bf_test_chain_get(
        BF_HOOK_XDP,
        BF_VERDICT_ACCEPT,
        NULL,
        (struct bf_rule *[]) {
            bf_rule_get(
                0,
                false,
                BF_VERDICT_DROP,
                (struct bf_matcher *[]) {
                    bf_matcher_get(BF_MATCHER_IP4_SADDR, BF_MATCHER_NE,
                        (uint8_t[]) {
                            // IP address
                            0x7f, 0x02, 0x0a, 0x0a
                        },
                        4
                    ),
                    NULL,
                }
            ),
            NULL,
        }
    );

    bft_e2e_test(match_eq_pkt, BF_VERDICT_DROP, pkt_local_ip4);
    bft_e2e_test(nomatch_eq_pkt, BF_VERDICT_ACCEPT, pkt_local_ip4);
    bft_e2e_test(match_ne_pkt, BF_VERDICT_DROP, pkt_local_ip4);
    bft_e2e_test(nomatch_ne_pkt, BF_VERDICT_ACCEPT, pkt_local_ip4);
}

Test(ip4, daddr)
{
    _free_bf_chain_ struct bf_chain *match_eq_pkt = bf_test_chain_get(
        BF_HOOK_XDP,
        BF_VERDICT_ACCEPT,
        NULL,
        (struct bf_rule *[]) {
            bf_rule_get(
                0,
                false,
                BF_VERDICT_DROP,
                (struct bf_matcher *[]) {
                    bf_matcher_get(BF_MATCHER_IP4_DADDR, BF_MATCHER_EQ,
                        (uint8_t[]) {
                            // IP address
                            0x7f, 0x02, 0x0a, 0x0b
                        },
                        4
                    ),
                    NULL,
                }
            ),
            NULL,
        }
    );

    _free_bf_chain_ struct bf_chain *nomatch_eq_pkt = bf_test_chain_get(
        BF_HOOK_XDP,
        BF_VERDICT_ACCEPT,
        NULL,
        (struct bf_rule *[]) {
            bf_rule_get(
                0,
                false,
                BF_VERDICT_DROP,
                (struct bf_matcher *[]) {
                    bf_matcher_get(BF_MATCHER_IP4_DADDR, BF_MATCHER_EQ,
                        (uint8_t[]) {
                            // IP address
                            0x7f, 0x02, 0x0a, 0x0c
                        },
                        4
                    ),
                    NULL,
                }
            ),
            NULL,
        }
    );

    _free_bf_chain_ struct bf_chain *match_ne_pkt = bf_test_chain_get(
        BF_HOOK_XDP,
        BF_VERDICT_ACCEPT,
        NULL,
        (struct bf_rule *[]) {
            bf_rule_get(
                0,
                false,
                BF_VERDICT_DROP,
                (struct bf_matcher *[]) {
                    bf_matcher_get(BF_MATCHER_IP4_DADDR, BF_MATCHER_NE,
                        (uint8_t[]) {
                            // IP address
                            0x7f, 0x02, 0x0a, 0x0c
                        },
                        4
                    ),
                    NULL,
                }
            ),
            NULL,
        }
    );

    _free_bf_chain_ struct bf_chain *nomatch_ne_pkt = bf_test_chain_get(
        BF_HOOK_XDP,
        BF_VERDICT_ACCEPT,
        NULL,
        (struct bf_rule *[]) {
            bf_rule_get(
                0,
                false,
                BF_VERDICT_DROP,
                (struct bf_matcher *[]) {
                    bf_matcher_get(BF_MATCHER_IP4_DADDR, BF_MATCHER_NE,
                        (uint8_t[]) {
                            // IP address
                            0x7f, 0x02, 0x0a, 0x0b
                        },
                        4
                    ),
                    NULL,
                }
            ),
            NULL,
        }
    );

    bft_e2e_test(match_eq_pkt, BF_VERDICT_DROP, pkt_local_ip4);
    bft_e2e_test(nomatch_eq_pkt, BF_VERDICT_ACCEPT, pkt_local_ip4);
    bft_e2e_test(match_ne_pkt, BF_VERDICT_DROP, pkt_local_ip4);
    bft_e2e_test(nomatch_ne_pkt, BF_VERDICT_ACCEPT, pkt_local_ip4);
}

Test(ip4, snet)
{
    _free_bf_chain_ struct bf_chain *match_eq_pkt = bf_test_chain_get(
        BF_HOOK_XDP,
        BF_VERDICT_ACCEPT,
        NULL,
        (struct bf_rule *[]) {
            bf_rule_get(
                0,
                false,
                BF_VERDICT_DROP,
                (struct bf_matcher *[]) {
                    bf_matcher_get(BF_MATCHER_IP4_SNET, BF_MATCHER_EQ,
                        (struct bf_ip4_lpm_key[]){{
                            .prefixlen = 16,
                            .data = 0x0c00027f,
                        }},
                        sizeof(struct bf_ip4_lpm_key)
                    ),
                    NULL,
                }
            ),
            NULL,
        }
    );

    _free_bf_chain_ struct bf_chain *nomatch_eq_pkt = bf_test_chain_get(
        BF_HOOK_XDP,
        BF_VERDICT_ACCEPT,
        NULL,
        (struct bf_rule *[]) {
            bf_rule_get(
                0,
                false,
                BF_VERDICT_DROP,
                (struct bf_matcher *[]) {
                    bf_matcher_get(BF_MATCHER_IP4_SNET, BF_MATCHER_EQ,
                        (struct bf_ip4_lpm_key[]){{
                            .prefixlen = 24,
                            .data = 0x0c00027f,
                        }},
                        sizeof(struct bf_ip4_lpm_key)
                    ),
                    NULL,
                }
            ),
            NULL,
        }
    );

    _free_bf_chain_ struct bf_chain *match_ne_pkt = bf_test_chain_get(
        BF_HOOK_XDP,
        BF_VERDICT_ACCEPT,
        NULL,
        (struct bf_rule *[]) {
            bf_rule_get(
                0,
                false,
                BF_VERDICT_DROP,
                (struct bf_matcher *[]) {
                    bf_matcher_get(BF_MATCHER_IP4_SNET, BF_MATCHER_NE,
                        (struct bf_ip4_lpm_key[]){{
                            .prefixlen = 24,
                            .data = 0x0c00027f,
                        }},
                        sizeof(struct bf_ip4_lpm_key)
                    ),
                    NULL,
                }
            ),
            NULL,
        }
    );

    _free_bf_chain_ struct bf_chain *nomatch_ne_pkt = bf_test_chain_get(
        BF_HOOK_XDP,
        BF_VERDICT_ACCEPT,
        NULL,
        (struct bf_rule *[]) {
            bf_rule_get(
                0,
                false,
                BF_VERDICT_DROP,
                (struct bf_matcher *[]) {
                    bf_matcher_get(BF_MATCHER_IP4_SNET, BF_MATCHER_NE,
                        (struct bf_ip4_lpm_key[]){{
                            .prefixlen = 16,
                            .data = 0x0c00027f,
                        }},
                        sizeof(struct bf_ip4_lpm_key)
                    ),
                    NULL,
                }
            ),
            NULL,
        }
    );

    bft_e2e_test(match_eq_pkt, BF_VERDICT_DROP, pkt_local_ip4);
    bft_e2e_test(nomatch_eq_pkt, BF_VERDICT_ACCEPT, pkt_local_ip4);
    bft_e2e_test(match_ne_pkt, BF_VERDICT_DROP, pkt_local_ip4);
    bft_e2e_test(nomatch_ne_pkt, BF_VERDICT_ACCEPT, pkt_local_ip4);
}

Test(ip4, dnet)
{
    _free_bf_chain_ struct bf_chain *match_eq_pkt = bf_test_chain_get(
        BF_HOOK_XDP,
        BF_VERDICT_ACCEPT,
        NULL,
        (struct bf_rule *[]) {
            bf_rule_get(
                0,
                false,
                BF_VERDICT_DROP,
                (struct bf_matcher *[]) {
                    bf_matcher_get(BF_MATCHER_IP4_DNET, BF_MATCHER_EQ,
                        (struct bf_ip4_lpm_key[]) {{
                            .prefixlen = 16,
                            .data = 0x0c0b027f,
                        }},
                        sizeof(struct bf_ip4_lpm_key)
                    ),
                    NULL,
                }
            ),
            NULL,
        }
    );

    _free_bf_chain_ struct bf_chain *nomatch_eq_pkt = bf_test_chain_get(
        BF_HOOK_XDP,
        BF_VERDICT_ACCEPT,
        NULL,
        (struct bf_rule *[]) {
            bf_rule_get(
                0,
                false,
                BF_VERDICT_DROP,
                (struct bf_matcher *[]) {
                    bf_matcher_get(BF_MATCHER_IP4_DNET, BF_MATCHER_EQ,
                        (struct bf_ip4_lpm_key[]) {{
                            .prefixlen = 24,
                            .data = 0x0c0b027f,
                        }},
                        sizeof(struct bf_ip4_lpm_key)
                    ),
                    NULL,
                }
            ),
            NULL,
        }
    );

    _free_bf_chain_ struct bf_chain *match_ne_pkt = bf_test_chain_get(
        BF_HOOK_XDP,
        BF_VERDICT_ACCEPT,
        NULL,
        (struct bf_rule *[]) {
            bf_rule_get(
                0,
                false,
                BF_VERDICT_DROP,
                (struct bf_matcher *[]) {
                    bf_matcher_get(BF_MATCHER_IP4_DNET, BF_MATCHER_NE,
                        (struct bf_ip4_lpm_key[]) {{
                            .prefixlen = 24,
                            .data = 0x0c0b027f,
                        }},
                        sizeof(struct bf_ip4_lpm_key)
                    ),
                    NULL,
                }
            ),
            NULL,
        }
    );

    _free_bf_chain_ struct bf_chain *nomatch_ne_pkt = bf_test_chain_get(
        BF_HOOK_XDP,
        BF_VERDICT_ACCEPT,
        NULL,
        (struct bf_rule *[]) {
            bf_rule_get(
                0,
                false,
                BF_VERDICT_DROP,
                (struct bf_matcher *[]) {
                    bf_matcher_get(BF_MATCHER_IP4_DNET, BF_MATCHER_NE,
                        (struct bf_ip4_lpm_key[]) {{
                            .prefixlen = 16,
                            .data = 0x0c0b027f,
                        }},
                        sizeof(struct bf_ip4_lpm_key)
                    ),
                    NULL,
                }
            ),
            NULL,
        }
    );

    bft_e2e_test(match_eq_pkt, BF_VERDICT_DROP, pkt_local_ip4);
    bft_e2e_test(nomatch_eq_pkt, BF_VERDICT_ACCEPT, pkt_local_ip4);
    bft_e2e_test(match_ne_pkt, BF_VERDICT_DROP, pkt_local_ip4);
    bft_e2e_test(nomatch_ne_pkt, BF_VERDICT_ACCEPT, pkt_local_ip4);
}

Test(ip4, daddr_eq_mask_match)
{
    _free_bf_chain_ struct bf_chain *chain = bf_test_chain_get(
        BF_HOOK_XDP,
        BF_VERDICT_ACCEPT,
        NULL,
        (struct bf_rule *[]) {
            bf_rule_get(
                0,
                false,
                BF_VERDICT_DROP,
                (struct bf_matcher *[]) {
                    bf_matcher_get(BF_MATCHER_IP4_DADDR, BF_MATCHER_EQ,
                        (uint8_t[]) {
                            // IP address
                            0x7f, 0x02, 0x0a, 0x0b,
                            // Mask
                            0xff, 0xff, 0x00, 0x00,
                        },
                        8
                    ),
                    NULL,
                }
            ),
            NULL,
        }
    );

    bft_e2e_test(chain, BF_VERDICT_DROP, pkt_local_ip4);
}

Test(ip4, snet_in)
{
    _free_bf_chain_ struct bf_chain *not_in = bf_test_chain_get(
        BF_HOOK_XDP,
        BF_VERDICT_ACCEPT,
        (struct bf_set *[]) {
            bft_set_get(
                (enum bf_matcher_type[]) {
                    BF_MATCHER_IP4_SNET
                },
                1,
                (struct bf_ip4_lpm_key []){
                    (struct bf_ip4_lpm_key) {
                        .prefixlen = 24,
                        .data = 0x0AC0A801,
                    },
                },
                1
            ),
            NULL,
        },
        (struct bf_rule *[]) {
            bf_rule_get(
                0,
                false,
                BF_VERDICT_DROP,
                (struct bf_matcher *[]) {
                    bf_matcher_get(BF_MATCHER_SET, BF_MATCHER_IN,
                        (uint32_t[]) {0}, 4
                    ),
                    NULL,
                }
            ),
            NULL,
        }
    );

    bft_e2e_test(not_in, BF_VERDICT_ACCEPT, pkt_local_ip4_icmp);

    _free_bf_chain_ struct bf_chain *in = bf_test_chain_get(
        BF_HOOK_XDP,
        BF_VERDICT_ACCEPT,
        (struct bf_set *[]) {
            bft_set_get(
                (enum bf_matcher_type[]) {
                    BF_MATCHER_IP4_SNET
                },
                1,
                (struct bf_ip4_lpm_key []){
                    (struct bf_ip4_lpm_key) {
                        .prefixlen = 24,
                        // 127.2.10.10 reversed to deal with endianess
                        .data = 0x0a0a027f,
                    },
                },
                1
            ),
            NULL,
        },
        (struct bf_rule *[]) {
            bf_rule_get(
                0,
                false,
                BF_VERDICT_DROP,
                (struct bf_matcher *[]) {
                    bf_matcher_get(BF_MATCHER_SET, BF_MATCHER_IN,
                        (uint32_t[]) {0}, 4
                    ),
                    NULL,
                }
            ),
            NULL,
        }
    );

    bft_e2e_test(in, BF_VERDICT_DROP, pkt_local_ip4_icmp);
}

Test(ip4, dnet_in)
{
    _free_bf_chain_ struct bf_chain *not_in = bf_test_chain_get(
        BF_HOOK_XDP,
        BF_VERDICT_ACCEPT,
        (struct bf_set *[]) {
            bft_set_get(
                (enum bf_matcher_type[]) {
                    BF_MATCHER_IP4_DNET
                },
                1,
                (struct bf_ip4_lpm_key []){
                    (struct bf_ip4_lpm_key) {
                        .prefixlen = 24,
                        .data = 0x0AC0A801,
                    },
                },
                1
            ),
            NULL,
        },
        (struct bf_rule *[]) {
            bf_rule_get(
                0,
                false,
                BF_VERDICT_DROP,
                (struct bf_matcher *[]) {
                    bf_matcher_get(BF_MATCHER_SET, BF_MATCHER_IN,
                        (uint32_t[]) {0}, 4
                    ),
                    NULL,
                }
            ),
            NULL,
        }
    );

    bft_e2e_test(not_in, BF_VERDICT_ACCEPT, pkt_local_ip4_icmp);

    _free_bf_chain_ struct bf_chain *in = bf_test_chain_get(
        BF_HOOK_XDP,
        BF_VERDICT_ACCEPT,
        (struct bf_set *[]) {
            bft_set_get(
                (enum bf_matcher_type[]) {
                    BF_MATCHER_IP4_DNET
                },
                1,
                (struct bf_ip4_lpm_key []){
                    (struct bf_ip4_lpm_key) {
                        .prefixlen = 24,
                        // 127.2.10.10 reversed to deal with endianess
                        .data = 0x0a0a027f,
                    },
                },
                1
            ),
            NULL,
        },
        (struct bf_rule *[]) {
            bf_rule_get(
                0,
                false,
                BF_VERDICT_DROP,
                (struct bf_matcher *[]) {
                    bf_matcher_get(BF_MATCHER_SET, BF_MATCHER_IN,
                        (uint32_t[]) {0}, 4
                    ),
                    NULL,
                }
            ),
            NULL,
        }
    );

    bft_e2e_test(in, BF_VERDICT_DROP, pkt_local_ip4_icmp);
}

Test(ip6, saddr)
{
    _free_bf_chain_ struct bf_chain *match_eq = bf_test_chain_get(
        BF_HOOK_XDP,
        BF_VERDICT_ACCEPT,
        NULL,
        (struct bf_rule *[]) {
            bf_rule_get(
                0,
                false,
                BF_VERDICT_DROP,
                (struct bf_matcher *[]) {
                    bf_matcher_get(BF_MATCHER_IP6_SADDR, BF_MATCHER_EQ,
                        (uint8_t[]) {
                            0x54, 0x2c, 0x1a, 0x31, 0xf9, 0x64, 0x94, 0x6c,
                            0x5a, 0x24, 0xe7, 0x1e, 0x4d, 0x26, 0xb8, 0x7e,
                        },
                        16
                    ),
                    NULL,
                }
            ),
            NULL,
        }
    );
    _free_bf_chain_ struct bf_chain *nomatch_eq = bf_test_chain_get(
        BF_HOOK_XDP,
        BF_VERDICT_ACCEPT,
        NULL,
        (struct bf_rule *[]) {
            bf_rule_get(
                0,
                false,
                BF_VERDICT_DROP,
                (struct bf_matcher *[]) {
                    bf_matcher_get(BF_MATCHER_IP6_SADDR, BF_MATCHER_EQ,
                        (uint8_t[]) {
                            0x54, 0x2c, 0x1a, 0x31, 0xf9, 0x64, 0x94, 0x6c,
                            0x5a, 0x24, 0xe7, 0x1e, 0x4d, 0x26, 0xb8, 0x7f /* Changed */,
                        },
                        16
                    ),
                    NULL,
                }
            ),
            NULL,
        }
    );
    _free_bf_chain_ struct bf_chain *match_ne = bf_test_chain_get(
        BF_HOOK_XDP,
        BF_VERDICT_ACCEPT,
        NULL,
        (struct bf_rule *[]) {
            bf_rule_get(
                0,
                false,
                BF_VERDICT_DROP,
                (struct bf_matcher *[]) {
                    bf_matcher_get(BF_MATCHER_IP6_SADDR, BF_MATCHER_NE,
                        (uint8_t[]) {
                            0x54, 0x2c, 0x1a, 0x31, 0xf9, 0x64, 0x94, 0x6c,
                            0x5a, 0x24, 0xe7, 0x1e, 0x4d, 0x26, 0xb8, 0x7f /* Changed */,
                        },
                        16
                    ),
                    NULL,
                }
            ),
            NULL,
        }
    );
    _free_bf_chain_ struct bf_chain *nomatch_ne = bf_test_chain_get(
        BF_HOOK_XDP,
        BF_VERDICT_ACCEPT,
        NULL,
        (struct bf_rule *[]) {
            bf_rule_get(
                0,
                false,
                BF_VERDICT_DROP,
                (struct bf_matcher *[]) {
                    bf_matcher_get(BF_MATCHER_IP6_SADDR, BF_MATCHER_NE,
                        (uint8_t[]) {
                            0x54, 0x2c, 0x1a, 0x31, 0xf9, 0x64, 0x94, 0x6c,
                            0x5a, 0x24, 0xe7, 0x1e, 0x4d, 0x26, 0xb8, 0x7e,
                        },
                        16
                    ),
                    NULL,
                }
            ),
            NULL,
        }
    );

    bft_e2e_test(match_eq, BF_VERDICT_DROP, pkt_remote_ip6_tcp);
    bft_e2e_test(nomatch_eq, BF_VERDICT_ACCEPT, pkt_remote_ip6_tcp);
    bft_e2e_test(match_ne, BF_VERDICT_DROP, pkt_remote_ip6_tcp);
    bft_e2e_test(nomatch_ne, BF_VERDICT_ACCEPT, pkt_remote_ip6_tcp);
}

Test(ip6, daddr)
{
    _free_bf_chain_ struct bf_chain *match_eq = bf_test_chain_get(
        BF_HOOK_XDP,
        BF_VERDICT_ACCEPT,
        NULL,
        (struct bf_rule *[]) {
            bf_rule_get(
                0,
                false,
                BF_VERDICT_DROP,
                (struct bf_matcher *[]) {
                    bf_matcher_get(BF_MATCHER_IP6_DADDR, BF_MATCHER_EQ,
                        (uint8_t[]) {
                            0x52, 0x32, 0x18, 0x5a, 0x52, 0xf9, 0x0a, 0xb4,
                            0x80, 0x25, 0x79, 0x74, 0x22, 0x99, 0xeb, 0x04,
                        },
                        16
                    ),
                    NULL,
                }
            ),
            NULL,
        }
    );
    _free_bf_chain_ struct bf_chain *nomatch_eq = bf_test_chain_get(
        BF_HOOK_XDP,
        BF_VERDICT_ACCEPT,
        NULL,
        (struct bf_rule *[]) {
            bf_rule_get(
                0,
                false,
                BF_VERDICT_DROP,
                (struct bf_matcher *[]) {
                    bf_matcher_get(BF_MATCHER_IP6_DADDR, BF_MATCHER_EQ,
                        (uint8_t[]) {
                            0x52, 0x32, 0x18, 0x5a, 0x52, 0xf9, 0x0a, 0xb4,
                            0x80, 0x25, 0x79, 0x74, 0x22, 0x99, 0xeb, 0x05 /* Changed */,
                        },
                        16
                    ),
                    NULL,
                }
            ),
            NULL,
        }
    );
    _free_bf_chain_ struct bf_chain *match_ne = bf_test_chain_get(
        BF_HOOK_XDP,
        BF_VERDICT_ACCEPT,
        NULL,
        (struct bf_rule *[]) {
            bf_rule_get(
                0,
                false,
                BF_VERDICT_DROP,
                (struct bf_matcher *[]) {
                    bf_matcher_get(BF_MATCHER_IP6_DADDR, BF_MATCHER_NE,
                        (uint8_t[]) {
                            0x52, 0x32, 0x18, 0x5a, 0x52, 0xf9, 0x0a, 0xb4,
                            0x80, 0x25, 0x79, 0x74, 0x22, 0x99, 0xeb, 0x05 /* Changed */,
                        },
                        16
                    ),
                    NULL,
                }
            ),
            NULL,
        }
    );
    _free_bf_chain_ struct bf_chain *nomatch_ne = bf_test_chain_get(
        BF_HOOK_XDP,
        BF_VERDICT_ACCEPT,
        NULL,
        (struct bf_rule *[]) {
            bf_rule_get(
                0,
                false,
                BF_VERDICT_DROP,
                (struct bf_matcher *[]) {
                    bf_matcher_get(BF_MATCHER_IP6_DADDR, BF_MATCHER_NE,
                        (uint8_t[]) {
                            0x52, 0x32, 0x18, 0x5a, 0x52, 0xf9, 0x0a, 0xb4,
                            0x80, 0x25, 0x79, 0x74, 0x22, 0x99, 0xeb, 0x04,
                        },
                        16
                    ),
                    NULL,
                }
            ),
            NULL,
        }
    );

    bft_e2e_test(match_eq, BF_VERDICT_DROP, pkt_remote_ip6_tcp);
    bft_e2e_test(nomatch_eq, BF_VERDICT_ACCEPT, pkt_remote_ip6_tcp);
    bft_e2e_test(match_ne, BF_VERDICT_DROP, pkt_remote_ip6_tcp);
    bft_e2e_test(nomatch_ne, BF_VERDICT_ACCEPT, pkt_remote_ip6_tcp);
}

Test(ip6, snet)
{
    _free_bf_chain_ struct bf_chain *match_eq = bf_test_chain_get(
        BF_HOOK_XDP, BF_VERDICT_ACCEPT,
        NULL,
        (struct bf_rule *[]) {
            bf_rule_get(0, false, BF_VERDICT_DROP,
                        (struct bf_matcher *[]) {
                            bf_matcher_get(BF_MATCHER_IP6_SNET, BF_MATCHER_EQ,
                                (struct bf_ip6_lpm_key[]) {{
                                    .prefixlen = 64,
                                    .data = {
                                        0x54, 0x2c, 0x1a, 0x31, 0xf9, 0x64, 0x94, 0x6c,
                                        0x5a, 0x24, 0xe7, 0x1e, 0x4d, 0x26, 0xb8, 0x7e,
                                    }
                                }},
                                sizeof(struct bf_ip6_lpm_key)
                            ),
                            NULL,
                        }),
            NULL,
        });
    _free_bf_chain_ struct bf_chain *nomatch_eq = bf_test_chain_get(
        BF_HOOK_XDP, BF_VERDICT_ACCEPT,
        NULL,
        (struct bf_rule *[]) {
            bf_rule_get(0, false, BF_VERDICT_DROP,
                        (struct bf_matcher *[]) {
                            bf_matcher_get(BF_MATCHER_IP6_SNET, BF_MATCHER_EQ,
                                (struct bf_ip6_lpm_key[]) {{
                                    .prefixlen = 72,
                                    .data = {
                                        0x54, 0x2c, 0x1a, 0x31, 0xf9, 0x64, 0x94, 0x6c,
                                        0x5b /* Changed */, 0x24, 0xe7, 0x1e, 0x4d, 0x26, 0xb8, 0x7e,
                                    }
                                }},
                                sizeof(struct bf_ip6_lpm_key)
                            ),
                            NULL,
                        }),
            NULL,
        });
    _free_bf_chain_ struct bf_chain *match_ne = bf_test_chain_get(
        BF_HOOK_XDP, BF_VERDICT_ACCEPT,
        NULL,
        (struct bf_rule *[]) {
            bf_rule_get(0, false, BF_VERDICT_DROP,
                        (struct bf_matcher *[]) {
                            bf_matcher_get(BF_MATCHER_IP6_SNET, BF_MATCHER_NE,
                                (struct bf_ip6_lpm_key[]) {{
                                    .prefixlen = 72,
                                    .data = {
                                        0x54, 0x2c, 0x1a, 0x31, 0xf9, 0x64, 0x94, 0x6c,
                                        0x5b /* Changed */, 0x24, 0xe7, 0x1e, 0x4d, 0x26, 0xb8, 0x7e,
                                    }
                                }},
                                sizeof(struct bf_ip6_lpm_key)
                            ),
                            NULL,
                        }),
            NULL,
        });
    _free_bf_chain_ struct bf_chain *nomatch_ne = bf_test_chain_get(
        BF_HOOK_XDP, BF_VERDICT_ACCEPT,
        NULL,
        (struct bf_rule *[]) {
            bf_rule_get(0, false, BF_VERDICT_DROP,
                        (struct bf_matcher *[]) {
                            bf_matcher_get(BF_MATCHER_IP6_SNET, BF_MATCHER_NE,
                                (struct bf_ip6_lpm_key[]) {{
                                    .prefixlen = 72,
                                    .data = {
                                        0x54, 0x2c, 0x1a, 0x31, 0xf9, 0x64, 0x94, 0x6c,
                                        0x5a, 0x24, 0xe7, 0x1e, 0x4d, 0x26, 0xb8, 0x7e,
                                    }
                                }},
                                sizeof(struct bf_ip6_lpm_key)
                            ),
                            NULL,
                        }),
            NULL,
        });

    bft_e2e_test(match_eq, BF_VERDICT_DROP, pkt_remote_ip6_tcp);
    bft_e2e_test(nomatch_eq, BF_VERDICT_ACCEPT, pkt_remote_ip6_tcp);
    bft_e2e_test(match_ne, BF_VERDICT_DROP, pkt_remote_ip6_tcp);
    bft_e2e_test(nomatch_ne, BF_VERDICT_ACCEPT, pkt_remote_ip6_tcp);
}


Test(ip6, dnet)
{
    _free_bf_chain_ struct bf_chain *match_eq = bf_test_chain_get(
        BF_HOOK_XDP, BF_VERDICT_ACCEPT,
        NULL,
        (struct bf_rule *[]) {
            bf_rule_get(0, false, BF_VERDICT_DROP,
                        (struct bf_matcher *[]) {
                            bf_matcher_get(BF_MATCHER_IP6_DNET, BF_MATCHER_EQ,
                                (struct bf_ip6_lpm_key[]) {{
                                    .prefixlen = 64,
                                    .data = {
                                        0x52, 0x32, 0x18, 0x5a, 0x52, 0xf9, 0x0a, 0xb4,
                                        0x80, 0x25, 0x79, 0x74, 0x22, 0x99, 0xeb, 0x04,
                                    }
                                }},
                                sizeof(struct bf_ip6_lpm_key)
                            ),
                            NULL,
                        }),
            NULL,
        });
    _free_bf_chain_ struct bf_chain *nomatch_eq = bf_test_chain_get(
        BF_HOOK_XDP, BF_VERDICT_ACCEPT,
        NULL,
        (struct bf_rule *[]) {
            bf_rule_get(0, false, BF_VERDICT_DROP,
                        (struct bf_matcher *[]) {
                            bf_matcher_get(BF_MATCHER_IP6_DNET, BF_MATCHER_EQ,
                                (struct bf_ip6_lpm_key[]) {{
                                    .prefixlen = 72,
                                    .data = {
                                        0x52, 0x32, 0x18, 0x5a, 0x52, 0xf9, 0x0a, 0xb4,
                                        0x81 /* Changed */, 0x25, 0x79, 0x74, 0x22, 0x99, 0xeb, 0x04,
                                    }
                                }},
                                sizeof(struct bf_ip6_lpm_key)
                            ),
                            NULL,
                        }),
            NULL,
        });
    _free_bf_chain_ struct bf_chain *match_ne = bf_test_chain_get(
        BF_HOOK_XDP, BF_VERDICT_ACCEPT,
        NULL,
        (struct bf_rule *[]) {
            bf_rule_get(0, false, BF_VERDICT_DROP,
                        (struct bf_matcher *[]) {
                            bf_matcher_get(BF_MATCHER_IP6_DNET, BF_MATCHER_NE,
                                (struct bf_ip6_lpm_key[]) {{
                                    .prefixlen = 72,
                                    .data = {
                                        0x52, 0x32, 0x18, 0x5a, 0x52, 0xf9, 0x0a, 0xb4,
                                        0x81 /* Changed */, 0x25, 0x79, 0x74, 0x22, 0x99, 0xeb, 0x04,
                                    }
                                }},
                                sizeof(struct bf_ip6_lpm_key)
                            ),
                            NULL,
                        }),
            NULL,
        });
    _free_bf_chain_ struct bf_chain *nomatch_ne = bf_test_chain_get(
        BF_HOOK_XDP, BF_VERDICT_ACCEPT,
        NULL,
        (struct bf_rule *[]) {
            bf_rule_get(0, false, BF_VERDICT_DROP,
                        (struct bf_matcher *[]) {
                            bf_matcher_get(BF_MATCHER_IP6_DNET, BF_MATCHER_NE,
                                (struct bf_ip6_lpm_key[]) {{
                                    .prefixlen = 72,
                                    .data = {
                                        0x52, 0x32, 0x18, 0x5a, 0x52, 0xf9, 0x0a, 0xb4,
                                        0x80, 0x25, 0x79, 0x74, 0x22, 0x99, 0xeb, 0x04,
                                    }
                                }},
                                sizeof(struct bf_ip6_lpm_key)
                            ),
                            NULL,
                        }),
            NULL,
        });

    bft_e2e_test(match_eq, BF_VERDICT_DROP, pkt_remote_ip6_tcp);
    bft_e2e_test(nomatch_eq, BF_VERDICT_ACCEPT, pkt_remote_ip6_tcp);
    bft_e2e_test(match_ne, BF_VERDICT_DROP, pkt_remote_ip6_tcp);
    bft_e2e_test(nomatch_ne, BF_VERDICT_ACCEPT, pkt_remote_ip6_tcp);
}

Test(ip6, snet_in)
{
    _free_bf_chain_ struct bf_chain *not_in = bf_test_chain_get(
        BF_HOOK_XDP,
        BF_VERDICT_ACCEPT,
        (struct bf_set *[]) {
            bft_set_get(
                (enum bf_matcher_type[]) {
                    BF_MATCHER_IP6_SNET
                },
                1,
                (struct bf_ip6_lpm_key []){
                    (struct bf_ip6_lpm_key) {
                        .prefixlen = 64,
                        .data = {
                            0x54, 0x2b /* Changed */, 0x1a, 0x31, 0xf9, 0x64, 0x94, 0x6c,
                            0x5a, 0x24, 0xe7, 0x1e, 0x4d, 0x26, 0xb8, 0x7e
                        },
                    },
                },
                1
            ),
            NULL,
        },
        (struct bf_rule *[]) {
            bf_rule_get(
                0,
                false,
                BF_VERDICT_DROP,
                (struct bf_matcher *[]) {
                    bf_matcher_get(BF_MATCHER_SET, BF_MATCHER_IN,
                        (uint32_t[]) {0}, 4
                    ),
                    NULL,
                }
            ),
            NULL,
        }
    );

    bft_e2e_test(not_in, BF_VERDICT_ACCEPT, pkt_remote_ip6_tcp);

    _free_bf_chain_ struct bf_chain *in = bf_test_chain_get(
        BF_HOOK_XDP,
        BF_VERDICT_ACCEPT,
        (struct bf_set *[]) {
            bft_set_get(
                (enum bf_matcher_type[]) {
                    BF_MATCHER_IP6_SNET
                },
                1,
                (struct bf_ip6_lpm_key []){
                    (struct bf_ip6_lpm_key) {
                        .prefixlen = 64,
                        .data = {
                            0x54, 0x2c, 0x1a, 0x31, 0xf9, 0x64, 0x94, 0x6c,
                            0x5a, 0x24, 0xe7, 0x1e, 0x4d, 0x26, 0xb8, 0x7e
                        },
                    },
                },
                1
            ),
            NULL,
        },
        (struct bf_rule *[]) {
            bf_rule_get(
                0,
                false,
                BF_VERDICT_DROP,
                (struct bf_matcher *[]) {
                    bf_matcher_get(BF_MATCHER_SET, BF_MATCHER_IN,
                        (uint32_t[]) {0}, 4
                    ),
                    NULL,
                }
            ),
            NULL,
        }
    );

    bft_e2e_test(in, BF_VERDICT_DROP, pkt_remote_ip6_tcp);
}

Test(ip6, dnet_in)
{
    _free_bf_chain_ struct bf_chain *not_in = bf_test_chain_get(
        BF_HOOK_XDP,
        BF_VERDICT_ACCEPT,
        (struct bf_set *[]) {
            bft_set_get(
                (enum bf_matcher_type[]) {
                    BF_MATCHER_IP6_DNET
                },
                1,
                (struct bf_ip6_lpm_key []){
                    (struct bf_ip6_lpm_key) {
                        .prefixlen = 64,
                        .data = {
                            0x52, 0x31 /* Changed */, 0x18, 0x5a, 0x52, 0xf9, 0x0a, 0xb4,
                            0x80, 0x25, 0x79, 0x74, 0x22, 0x99, 0xeb, 0x04
                        },
                    },
                },
                1
            ),
            NULL,
        },
        (struct bf_rule *[]) {
            bf_rule_get(
                0,
                false,
                BF_VERDICT_DROP,
                (struct bf_matcher *[]) {
                    bf_matcher_get(BF_MATCHER_SET, BF_MATCHER_IN,
                        (uint32_t[]) {0}, 4
                    ),
                    NULL,
                }
            ),
            NULL,
        }
    );

    bft_e2e_test(not_in, BF_VERDICT_ACCEPT, pkt_remote_ip6_tcp);

    _free_bf_chain_ struct bf_chain *in = bf_test_chain_get(
        BF_HOOK_XDP,
        BF_VERDICT_ACCEPT,
        (struct bf_set *[]) {
            bft_set_get(
                (enum bf_matcher_type[]) {
                    BF_MATCHER_IP6_DNET
                },
                1,
                (struct bf_ip6_lpm_key []){
                    (struct bf_ip6_lpm_key) {
                        .prefixlen = 64,
                        .data = {
                            0x52, 0x32, 0x18, 0x5a, 0x52, 0xf9, 0x0a, 0xb4,
                            0x80, 0x25, 0x79, 0x74, /* Changed */ 0x23, 0x99, 0xeb, 0x04
                        },
                    },
                },
                1
            ),
            NULL,
        },
        (struct bf_rule *[]) {
            bf_rule_get(
                0,
                false,
                BF_VERDICT_DROP,
                (struct bf_matcher *[]) {
                    bf_matcher_get(BF_MATCHER_SET, BF_MATCHER_IN,
                        (uint32_t[]) {0}, 4
                    ),
                    NULL,
                }
            ),
            NULL,
        }
    );

    bft_e2e_test(in, BF_VERDICT_DROP, pkt_remote_ip6_tcp);
}

Test(tcp, dport_range)
{
    _free_bf_chain_ struct bf_chain *in_range = bf_test_chain_get(
        BF_HOOK_XDP,
        BF_VERDICT_ACCEPT,
        NULL,
        (struct bf_rule *[]) {
            bf_rule_get(
                0,
                false,
                BF_VERDICT_DROP,
                (struct bf_matcher *[]) {
                    bf_matcher_get(BF_MATCHER_TCP_DPORT, BF_MATCHER_RANGE,
                        (uint8_t[]) {
                            // 31000 to 32000
                            0x18, 0x79, 0x00, 0xd7,
                        },
                        4
                    ),
                    NULL,
                }
            ),
            NULL,
        }
    );
    bft_e2e_test(in_range, BF_VERDICT_DROP, pkt_local_ip6_tcp);

    _free_bf_chain_ struct bf_chain *under_range = bf_test_chain_get(
        BF_HOOK_XDP,
        BF_VERDICT_ACCEPT,
        NULL,
        (struct bf_rule *[]) {
            bf_rule_get(
                0,
                false,
                BF_VERDICT_DROP,
                (struct bf_matcher *[]) {
                    bf_matcher_get(BF_MATCHER_TCP_DPORT, BF_MATCHER_RANGE,
                        (uint8_t[]) {
                            // 1 to 31000
                            0x01, 0x00, 0x18, 0x79,
                        },
                        4
                    ),
                    NULL,
                }
            ),
            NULL,
        }
    );
    bft_e2e_test(under_range, BF_VERDICT_ACCEPT, pkt_local_ip6_tcp);

    _free_bf_chain_ struct bf_chain *over_range = bf_test_chain_get(
        BF_HOOK_XDP,
        BF_VERDICT_ACCEPT,
        NULL,
        (struct bf_rule *[]) {
            bf_rule_get(
                0,
                false,
                BF_VERDICT_DROP,
                (struct bf_matcher *[]) {
                    bf_matcher_get(BF_MATCHER_TCP_DPORT, BF_MATCHER_RANGE,
                        (uint8_t[]) {
                            // 32000 to 65535
                            0x00, 0xd7, 0xff, 0xff,
                        },
                        4
                    ),
                    NULL,
                }
            ),
            NULL,
        }
    );
    bft_e2e_test(over_range, BF_VERDICT_ACCEPT, pkt_local_ip6_tcp);
}

Test(udp, dport_range)
{
    _free_bf_chain_ struct bf_chain *in_range = bf_test_chain_get(
        BF_HOOK_XDP,
        BF_VERDICT_ACCEPT,
        NULL,
        (struct bf_rule *[]) {
            bf_rule_get(
                0,
                false,
                BF_VERDICT_DROP,
                (struct bf_matcher *[]) {
                    bf_matcher_get(BF_MATCHER_UDP_DPORT, BF_MATCHER_RANGE,
                        (uint8_t[]) {
                            // 31000 to 32000
                            0x18, 0x79, 0x00, 0xd7,
                        },
                        4
                    ),
                    NULL,
                }
            ),
            NULL,
        }
    );
    bft_e2e_test(in_range, BF_VERDICT_DROP, pkt_local_ip6_udp);

    _free_bf_chain_ struct bf_chain *under_range = bf_test_chain_get(
        BF_HOOK_XDP,
        BF_VERDICT_ACCEPT,
        NULL,
        (struct bf_rule *[]) {
            bf_rule_get(
                0,
                false,
                BF_VERDICT_DROP,
                (struct bf_matcher *[]) {
                    bf_matcher_get(BF_MATCHER_UDP_DPORT, BF_MATCHER_RANGE,
                        (uint8_t[]) {
                            // 1 to 31000
                            0x01, 0x00, 0x18, 0x79,
                        },
                        4
                    ),
                    NULL,
                }
            ),
            NULL,
        }
    );
    bft_e2e_test(under_range, BF_VERDICT_ACCEPT, pkt_local_ip6_udp);

    _free_bf_chain_ struct bf_chain *over_range = bf_test_chain_get(
        BF_HOOK_XDP,
        BF_VERDICT_ACCEPT,
        NULL,
        (struct bf_rule *[]) {
            bf_rule_get(
                0,
                false,
                BF_VERDICT_DROP,
                (struct bf_matcher *[]) {
                    bf_matcher_get(BF_MATCHER_UDP_DPORT, BF_MATCHER_RANGE,
                        (uint8_t[]) {
                            // 32000 to 65535
                            0x00, 0xd7, 0xff, 0xff,
                        },
                        4
                    ),
                    NULL,
                }
            ),
            NULL,
        }
    );
    bft_e2e_test(over_range, BF_VERDICT_ACCEPT, pkt_local_ip6_udp);
}

Test(meta, dport_range)
{
    _free_bf_chain_ struct bf_chain *in_range = bf_test_chain_get(
        BF_HOOK_XDP,
        BF_VERDICT_ACCEPT,
        NULL,
        (struct bf_rule *[]) {
            bf_rule_get(
                0,
                false,
                BF_VERDICT_DROP,
                (struct bf_matcher *[]) {
                    bf_matcher_get(BF_MATCHER_META_DPORT, BF_MATCHER_RANGE,
                        (uint8_t[]) {
                            // 31000 to 32000
                            0x18, 0x79, 0x00, 0xd7,
                        },
                        4
                    ),
                    NULL,
                }
            ),
            NULL,
        }
    );
    bft_e2e_test(in_range, BF_VERDICT_DROP, pkt_local_ip6_tcp);
    bft_e2e_test(in_range, BF_VERDICT_DROP, pkt_local_ip6_udp);

    _free_bf_chain_ struct bf_chain *under_range = bf_test_chain_get(
        BF_HOOK_XDP,
        BF_VERDICT_ACCEPT,
        NULL,
        (struct bf_rule *[]) {
            bf_rule_get(
                0,
                false,
                BF_VERDICT_DROP,
                (struct bf_matcher *[]) {
                    bf_matcher_get(BF_MATCHER_META_DPORT, BF_MATCHER_RANGE,
                        (uint8_t[]) {
                            // 1 to 31000
                            0x01, 0x00, 0x18, 0x79,
                        },
                        4
                    ),
                    NULL,
                }
            ),
            NULL,
        }
    );
    bft_e2e_test(under_range, BF_VERDICT_ACCEPT, pkt_local_ip6_tcp);
    bft_e2e_test(under_range, BF_VERDICT_ACCEPT, pkt_local_ip6_udp);

    _free_bf_chain_ struct bf_chain *over_range = bf_test_chain_get(
        BF_HOOK_XDP,
        BF_VERDICT_ACCEPT,
        NULL,
        (struct bf_rule *[]) {
            bf_rule_get(
                0,
                false,
                BF_VERDICT_DROP,
                (struct bf_matcher *[]) {
                    bf_matcher_get(BF_MATCHER_META_DPORT, BF_MATCHER_RANGE,
                        (uint8_t[]) {
                            // 32000 to 65535
                            0x00, 0xd7, 0xff, 0xff,
                        },
                        4
                    ),
                    NULL,
                }
            ),
            NULL,
        }
    );
    bft_e2e_test(over_range, BF_VERDICT_ACCEPT, pkt_local_ip6_tcp);
    bft_e2e_test(over_range, BF_VERDICT_ACCEPT, pkt_local_ip6_udp);
}

Test(icmp, type)
{
    _free_bf_chain_ struct bf_chain *match_eq = bf_test_chain_get(
        BF_HOOK_XDP,
        BF_VERDICT_ACCEPT,
        NULL,
        (struct bf_rule *[]) {
            bf_rule_get(
                0,
                false,
                BF_VERDICT_DROP,
                (struct bf_matcher *[]) {
                    bf_matcher_get(BF_MATCHER_ICMP_TYPE, BF_MATCHER_EQ,
                        (uint8_t[]) {
                            0x08,
                        },
                        1
                    ),
                    NULL,
                }
            ),
            NULL,
        }
    );
    _free_bf_chain_ struct bf_chain *nomatch_eq = bf_test_chain_get(
        BF_HOOK_XDP,
        BF_VERDICT_ACCEPT,
        NULL,
        (struct bf_rule *[]) {
            bf_rule_get(
                0,
                false,
                BF_VERDICT_DROP,
                (struct bf_matcher *[]) {
                    bf_matcher_get(BF_MATCHER_ICMP_TYPE, BF_MATCHER_EQ,
                        (uint8_t[]) {
                            0x01,
                        },
                        1
                    ),
                    NULL,
                }
            ),
            NULL,
        }
    );
    _free_bf_chain_ struct bf_chain *match_ne = bf_test_chain_get(
        BF_HOOK_XDP,
        BF_VERDICT_ACCEPT,
        NULL,
        (struct bf_rule *[]) {
            bf_rule_get(
                0,
                false,
                BF_VERDICT_DROP,
                (struct bf_matcher *[]) {
                    bf_matcher_get(BF_MATCHER_ICMP_TYPE, BF_MATCHER_NE,
                        (uint8_t[]) {
                            0x01,
                        },
                        1
                    ),
                    NULL,
                }
            ),
            NULL,
        }
    );
    _free_bf_chain_ struct bf_chain *nomatch_ne = bf_test_chain_get(
        BF_HOOK_XDP,
        BF_VERDICT_ACCEPT,
        NULL,
        (struct bf_rule *[]) {
            bf_rule_get(
                0,
                false,
                BF_VERDICT_DROP,
                (struct bf_matcher *[]) {
                    bf_matcher_get(BF_MATCHER_ICMP_TYPE, BF_MATCHER_NE,
                        (uint8_t[]) {
                            0x08,
                        },
                        1
                    ),
                    NULL,
                }
            ),
            NULL,
        }
    );

    bft_e2e_test(match_eq, BF_VERDICT_DROP, pkt_local_ip4_icmp);
    bft_e2e_test(nomatch_eq, BF_VERDICT_ACCEPT, pkt_local_ip4_icmp);
    bft_e2e_test(match_ne, BF_VERDICT_DROP, pkt_local_ip4_icmp);
    bft_e2e_test(nomatch_ne, BF_VERDICT_ACCEPT, pkt_local_ip4_icmp);
}

Test(icmp, code)
{
    _free_bf_chain_ struct bf_chain *match_eq = bf_test_chain_get(
        BF_HOOK_XDP,
        BF_VERDICT_ACCEPT,
        NULL,
        (struct bf_rule *[]) {
            bf_rule_get(
                0,
                false,
                BF_VERDICT_DROP,
                (struct bf_matcher *[]) {
                    bf_matcher_get(BF_MATCHER_ICMP_CODE, BF_MATCHER_EQ,
                        (uint8_t[]) {
                            0x02,
                        },
                        1
                    ),
                    NULL,
                }
            ),
            NULL,
        }
    );
    _free_bf_chain_ struct bf_chain *nomatch_eq = bf_test_chain_get(
        BF_HOOK_XDP,
        BF_VERDICT_ACCEPT,
        NULL,
        (struct bf_rule *[]) {
            bf_rule_get(
                0,
                false,
                BF_VERDICT_DROP,
                (struct bf_matcher *[]) {
                    bf_matcher_get(BF_MATCHER_ICMP_CODE, BF_MATCHER_EQ,
                        (uint8_t[]) {
                            0x03,
                        },
                        1
                    ),
                    NULL,
                }
            ),
            NULL,
        }
    );
    _free_bf_chain_ struct bf_chain *match_ne = bf_test_chain_get(
        BF_HOOK_XDP,
        BF_VERDICT_ACCEPT,
        NULL,
        (struct bf_rule *[]) {
            bf_rule_get(
                0,
                false,
                BF_VERDICT_DROP,
                (struct bf_matcher *[]) {
                    bf_matcher_get(BF_MATCHER_ICMP_CODE, BF_MATCHER_NE,
                        (uint8_t[]) {
                            0x03,
                        },
                        1
                    ),
                    NULL,
                }
            ),
            NULL,
        }
    );
    _free_bf_chain_ struct bf_chain *nomatch_ne = bf_test_chain_get(
        BF_HOOK_XDP,
        BF_VERDICT_ACCEPT,
        NULL,
        (struct bf_rule *[]) {
            bf_rule_get(
                0,
                false,
                BF_VERDICT_DROP,
                (struct bf_matcher *[]) {
                    bf_matcher_get(BF_MATCHER_ICMP_CODE, BF_MATCHER_NE,
                        (uint8_t[]) {
                            0x02,
                        },
                        1
                    ),
                    NULL,
                }
            ),
            NULL,
        }
    );

    bft_e2e_test(match_eq, BF_VERDICT_DROP, pkt_local_ip4_icmp);
    bft_e2e_test(nomatch_eq, BF_VERDICT_ACCEPT, pkt_local_ip4_icmp);
    bft_e2e_test(match_ne, BF_VERDICT_DROP, pkt_local_ip4_icmp);
    bft_e2e_test(nomatch_ne, BF_VERDICT_ACCEPT, pkt_local_ip4_icmp);
}

Test(icmpv6, type)
{
    _free_bf_chain_ struct bf_chain *match_eq = bf_test_chain_get(
        BF_HOOK_XDP,
        BF_VERDICT_ACCEPT,
        NULL,
        (struct bf_rule *[]) {
            bf_rule_get(
                0,
                false,
                BF_VERDICT_DROP,
                (struct bf_matcher *[]) {
                    bf_matcher_get(BF_MATCHER_ICMPV6_TYPE, BF_MATCHER_EQ,
                        (uint8_t[]) {
                            0x80,
                        },
                        1
                    ),
                    NULL,
                }
            ),
            NULL,
        }
    );
    _free_bf_chain_ struct bf_chain *nomatch_eq = bf_test_chain_get(
        BF_HOOK_XDP,
        BF_VERDICT_ACCEPT,
        NULL,
        (struct bf_rule *[]) {
            bf_rule_get(
                0,
                false,
                BF_VERDICT_DROP,
                (struct bf_matcher *[]) {
                    bf_matcher_get(BF_MATCHER_ICMPV6_TYPE, BF_MATCHER_EQ,
                        (uint8_t[]) {
                            0x81,
                        },
                        1
                    ),
                    NULL,
                }
            ),
            NULL,
        }
    );
    _free_bf_chain_ struct bf_chain *match_ne = bf_test_chain_get(
        BF_HOOK_XDP,
        BF_VERDICT_ACCEPT,
        NULL,
        (struct bf_rule *[]) {
            bf_rule_get(
                0,
                false,
                BF_VERDICT_DROP,
                (struct bf_matcher *[]) {
                    bf_matcher_get(BF_MATCHER_ICMPV6_TYPE, BF_MATCHER_NE,
                        (uint8_t[]) {
                            0x81,
                        },
                        1
                    ),
                    NULL,
                }
            ),
            NULL,
        }
    );
    _free_bf_chain_ struct bf_chain *nomatch_ne = bf_test_chain_get(
        BF_HOOK_XDP,
        BF_VERDICT_ACCEPT,
        NULL,
        (struct bf_rule *[]) {
            bf_rule_get(
                0,
                false,
                BF_VERDICT_DROP,
                (struct bf_matcher *[]) {
                    bf_matcher_get(BF_MATCHER_ICMPV6_TYPE, BF_MATCHER_NE,
                        (uint8_t[]) {
                            0x80,
                        },
                        1
                    ),
                    NULL,
                }
            ),
            NULL,
        }
    );

    bft_e2e_test(match_eq, BF_VERDICT_DROP, pkt_local_ip6_icmp);
    bft_e2e_test(nomatch_eq, BF_VERDICT_ACCEPT, pkt_local_ip6_icmp);
    bft_e2e_test(match_ne, BF_VERDICT_DROP, pkt_local_ip6_icmp);
    bft_e2e_test(nomatch_ne, BF_VERDICT_ACCEPT, pkt_local_ip6_icmp);
}

Test(icmpv6, code)
{
    _free_bf_chain_ struct bf_chain *match_eq = bf_test_chain_get(
        BF_HOOK_XDP,
        BF_VERDICT_ACCEPT,
        NULL,
        (struct bf_rule *[]) {
            bf_rule_get(
                0,
                false,
                BF_VERDICT_DROP,
                (struct bf_matcher *[]) {
                    bf_matcher_get(BF_MATCHER_ICMPV6_CODE, BF_MATCHER_EQ,
                        (uint8_t[]) {
                            0x02,
                        },
                        1
                    ),
                    NULL,
                }
            ),
            NULL,
        }
    );
    _free_bf_chain_ struct bf_chain *nomatch_eq = bf_test_chain_get(
        BF_HOOK_XDP,
        BF_VERDICT_ACCEPT,
        NULL,
        (struct bf_rule *[]) {
            bf_rule_get(
                0,
                false,
                BF_VERDICT_DROP,
                (struct bf_matcher *[]) {
                    bf_matcher_get(BF_MATCHER_ICMPV6_CODE, BF_MATCHER_EQ,
                        (uint8_t[]) {
                            0x03,
                        },
                        1
                    ),
                    NULL,
                }
            ),
            NULL,
        }
    );
    _free_bf_chain_ struct bf_chain *match_ne = bf_test_chain_get(
        BF_HOOK_XDP,
        BF_VERDICT_ACCEPT,
        NULL,
        (struct bf_rule *[]) {
            bf_rule_get(
                0,
                false,
                BF_VERDICT_DROP,
                (struct bf_matcher *[]) {
                    bf_matcher_get(BF_MATCHER_ICMPV6_CODE, BF_MATCHER_NE,
                        (uint8_t[]) {
                            0x03,
                        },
                        1
                    ),
                    NULL,
                }
            ),
            NULL,
        }
    );
    _free_bf_chain_ struct bf_chain *nomatch_ne = bf_test_chain_get(
        BF_HOOK_XDP,
        BF_VERDICT_ACCEPT,
        NULL,
        (struct bf_rule *[]) {
            bf_rule_get(
                0,
                false,
                BF_VERDICT_DROP,
                (struct bf_matcher *[]) {
                    bf_matcher_get(BF_MATCHER_ICMPV6_CODE, BF_MATCHER_NE,
                        (uint8_t[]) {
                            0x02,
                        },
                        1
                    ),
                    NULL,
                }
            ),
            NULL,
        }
    );

    bft_e2e_test(match_eq, BF_VERDICT_DROP, pkt_local_ip6_icmp);
    bft_e2e_test(nomatch_eq, BF_VERDICT_ACCEPT, pkt_local_ip6_icmp);
    bft_e2e_test(match_ne, BF_VERDICT_DROP, pkt_local_ip6_icmp);
    bft_e2e_test(nomatch_ne, BF_VERDICT_ACCEPT, pkt_local_ip6_icmp);
}

Test(ipv6, extension_headers)
{
    _free_bf_chain_ struct bf_chain *chain = bf_test_chain_get(
        BF_HOOK_XDP,
        BF_VERDICT_ACCEPT,
        NULL,
        (struct bf_rule *[]) {
            bf_rule_get(
                0,
                false,
                BF_VERDICT_DROP,
                (struct bf_matcher *[]) {
                    bf_matcher_get(BF_MATCHER_TCP_DPORT, BF_MATCHER_EQ,
                        (uint8_t[]) { 0x7a, 0xb7 },
                        2
                    ),
                    NULL,
                }
            ),
            NULL,
        }
    );

    bft_e2e_test(chain, BF_VERDICT_ACCEPT, pkt_remote_ip6_eh);
    bft_e2e_test(chain, BF_VERDICT_DROP, pkt_remote_ip6_eh_tcp);
}

Test(tcp, flags)
{
    _free_bf_chain_ struct bf_chain *match_eq = bf_test_chain_get(
        BF_HOOK_XDP,
        BF_VERDICT_ACCEPT,
        NULL,
        (struct bf_rule *[]) {
            bf_rule_get(
                0,
                false,
                BF_VERDICT_DROP,
                (struct bf_matcher *[]) {
                    bf_matcher_get(BF_MATCHER_TCP_FLAGS, BF_MATCHER_EQ,
                        (uint8_t[]) {
                            0b00010010, /* SYN */
                        },
                        1
                    ),
                    NULL,
                }
            ),
            NULL,
        }
    );
    _free_bf_chain_ struct bf_chain *nomatch_eq = bf_test_chain_get(
        BF_HOOK_XDP,
        BF_VERDICT_ACCEPT,
        NULL,
        (struct bf_rule *[]) {
            bf_rule_get(
                0,
                false,
                BF_VERDICT_DROP,
                (struct bf_matcher *[]) {
                    bf_matcher_get(BF_MATCHER_TCP_FLAGS, BF_MATCHER_EQ,
                        (uint8_t[]) {
                            0b00000010, /* SYN */
                        },
                        1
                    ),
                    NULL,
                }
            ),
            NULL,
        }
    );
    _free_bf_chain_ struct bf_chain *match_ne = bf_test_chain_get(
        BF_HOOK_XDP,
        BF_VERDICT_ACCEPT,
        NULL,
        (struct bf_rule *[]) {
            bf_rule_get(
                0,
                false,
                BF_VERDICT_DROP,
                (struct bf_matcher *[]) {
                    bf_matcher_get(BF_MATCHER_TCP_FLAGS, BF_MATCHER_NE,
                        (uint8_t[]) {
                            0b00000010, /* SYN */
                        },
                        1
                    ),
                    NULL,
                }
            ),
            NULL,
        }
    );
    _free_bf_chain_ struct bf_chain *nomatch_ne = bf_test_chain_get(
        BF_HOOK_XDP,
        BF_VERDICT_ACCEPT,
        NULL,
        (struct bf_rule *[]) {
            bf_rule_get(
                0,
                false,
                BF_VERDICT_DROP,
                (struct bf_matcher *[]) {
                    bf_matcher_get(BF_MATCHER_TCP_FLAGS, BF_MATCHER_NE,
                        (uint8_t[]) {
                            0b00010010, /* SYN | ACK */
                        },
                        1
                    ),
                    NULL,
                }
            ),
            NULL,
        }
    );
    _free_bf_chain_ struct bf_chain *match_any = bf_test_chain_get(
        BF_HOOK_XDP,
        BF_VERDICT_ACCEPT,
        NULL,
        (struct bf_rule *[]) {
            bf_rule_get(
                0,
                false,
                BF_VERDICT_DROP,
                (struct bf_matcher *[]) {
                    bf_matcher_get(BF_MATCHER_TCP_FLAGS, BF_MATCHER_ANY,
                        (uint8_t[]) {
                            0b00011100, /* ACK | PSH | RST */
                        },
                        1
                    ),
                    NULL,
                }
            ),
            NULL,
        }
    );
    _free_bf_chain_ struct bf_chain *nomatch_any = bf_test_chain_get(
        BF_HOOK_XDP,
        BF_VERDICT_ACCEPT,
        NULL,
        (struct bf_rule *[]) {
            bf_rule_get(
                0,
                false,
                BF_VERDICT_DROP,
                (struct bf_matcher *[]) {
                    bf_matcher_get(BF_MATCHER_TCP_FLAGS, BF_MATCHER_ANY,
                        (uint8_t[]) {
                            0b11100000, /* CWR, ECE, URG */
                        },
                        1
                    ),
                    NULL,
                }
            ),
            NULL,
        }
    );
    _free_bf_chain_ struct bf_chain *match_all = bf_test_chain_get(
        BF_HOOK_XDP,
        BF_VERDICT_ACCEPT,
        NULL,
        (struct bf_rule *[]) {
            bf_rule_get(
                0,
                false,
                BF_VERDICT_DROP,
                (struct bf_matcher *[]) {
                    bf_matcher_get(BF_MATCHER_TCP_FLAGS, BF_MATCHER_ALL,
                        (uint8_t[]) {
                            0b00010000, /* ACK */
                        },
                        1
                    ),
                    NULL,
                }
            ),
            NULL,
        }
    );
    _free_bf_chain_ struct bf_chain *nomatch_all = bf_test_chain_get(
        BF_HOOK_XDP,
        BF_VERDICT_ACCEPT,
        NULL,
        (struct bf_rule *[]) {
            bf_rule_get(
                0,
                false,
                BF_VERDICT_DROP,
                (struct bf_matcher *[]) {
                    bf_matcher_get(BF_MATCHER_TCP_FLAGS, BF_MATCHER_ALL,
                        (uint8_t[]) {
                            0b00010001, /* ACK | FIN */
                        },
                        1
                    ),
                    NULL,
                }
            ),
            NULL,
        }
    );

    bft_e2e_test(match_eq, BF_VERDICT_DROP, pkt_remote_ip6_eh_tcp);
    bft_e2e_test(nomatch_eq, BF_VERDICT_ACCEPT, pkt_remote_ip6_eh_tcp);
    bft_e2e_test(match_ne, BF_VERDICT_DROP, pkt_remote_ip6_eh_tcp);
    bft_e2e_test(nomatch_ne, BF_VERDICT_ACCEPT, pkt_remote_ip6_eh_tcp);
    bft_e2e_test(match_any, BF_VERDICT_DROP, pkt_remote_ip6_eh_tcp);
    bft_e2e_test(nomatch_any, BF_VERDICT_ACCEPT, pkt_remote_ip6_eh_tcp);
    bft_e2e_test(match_all, BF_VERDICT_DROP, pkt_remote_ip6_eh_tcp);
    bft_e2e_test(nomatch_all, BF_VERDICT_ACCEPT, pkt_remote_ip6_eh_tcp);
}

Test(ip6, nexthdr)
{
    _free_bf_chain_ struct bf_chain *next_accept = bf_test_chain_get(
        BF_HOOK_XDP, BF_VERDICT_ACCEPT, NULL,
        (struct bf_rule *[]) {
            bf_rule_get(
                0, false, BF_VERDICT_DROP,
                (struct bf_matcher *[]) {
                    bf_matcher_get(BF_MATCHER_IP6_NEXTHDR, BF_MATCHER_EQ,
                                   (uint8_t[]) {
                                       // Destination options
                                       0x3c,
                                   },
                                   1),
                    NULL,
                }),
            NULL,
        });
    bft_e2e_test(next_accept, BF_VERDICT_ACCEPT, pkt_local_ip6_hop);

    _free_bf_chain_ struct bf_chain *next_drop = bf_test_chain_get(
        BF_HOOK_XDP, BF_VERDICT_ACCEPT, NULL,
        (struct bf_rule *[]) {
            bf_rule_get(
                0, false, BF_VERDICT_DROP,
                (struct bf_matcher *[]) {
                    bf_matcher_get(BF_MATCHER_IP6_NEXTHDR, BF_MATCHER_EQ,
                                   (uint8_t[]) {
                                       // Routing
                                       0x2b,
                                   },
                                   1),
                    NULL,
                }),
            NULL,
        });
    bft_e2e_test(next_drop, BF_VERDICT_ACCEPT, pkt_local_ip6_tcp);
    bft_e2e_test(next_drop, BF_VERDICT_DROP, pkt_local_ip6_hop);
}

int main(int argc, char *argv[])
{
    _free_bf_test_suite_ bf_test_suite *suite = NULL;
    extern bf_test __start_bf_test;
    extern bf_test __stop_bf_test;
    int failed = 0;
    int r;

    r = bft_e2e_parse_args(argc, argv);
    if (r)
        return r;

    r = bf_test_discover_test_suite(&suite, &__start_bf_test, &__stop_bf_test);
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
