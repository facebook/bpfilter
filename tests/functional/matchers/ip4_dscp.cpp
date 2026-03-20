/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#include "Chain.hpp"
#include "Matcher.hpp"
#include "Rule.hpp"
#include "test.hpp"

extern "C" {
#include <bpfilter/bpfilter.h>
}

/**
 * Verify ip4.dscp eq matches the configured TOS byte value and rejects
 * others. The matcher compares the full TOS byte including the ECN bits, not
 * just the DSCP field, so a packet with the same DSCP but non-zero ECN must
 * not match.
 */
static void ip4_dscp_eq(void **state)
{
    auto *test = static_cast<MatcherTest *>(*state);

    // TOS byte 0x20 = DSCP 8 (CS1)
    BFT_CHAIN_SET(
        bf::Chain("test_ip4_dscp", test->hook(), BF_VERDICT_ACCEPT)
        << bf::Rule(BF_VERDICT_DROP, true, {},
                    {bf::Matcher(BF_MATCHER_IP4_DSCP, BF_MATCHER_EQ, {0x20})}));

    // tos=0x20 should match -> DROP
    bft_assert_prog_run("test_ip4_dscp", test->hook(),
                        bft::Ethernet() /
                            bft::IPv4 {.saddr = "192.0.2.1",
                                       .daddr = "192.0.2.2",
                                       .tos = 0x20} /
                            bft::TCP {.sport = 12345, .dport = 80},
                        test->verdictDrop());

    // tos=0 should not match -> ACCEPT
    bft_assert_prog_run(
        "test_ip4_dscp", test->hook(),
        bft::Ethernet() /
            bft::IPv4 {.saddr = "192.0.2.1", .daddr = "192.0.2.2", .tos = 0} /
            bft::TCP {.sport = 12345, .dport = 80},
        test->verdictAccept());

    // tos=0x23 has the same DSCP bits (8) as 0x20 but ECN=3; the matcher
    // compares the full TOS byte, so this must not match -> ACCEPT
    bft_assert_prog_run("test_ip4_dscp", test->hook(),
                        bft::Ethernet() /
                            bft::IPv4 {.saddr = "192.0.2.1",
                                       .daddr = "192.0.2.2",
                                       .tos = 0x23} /
                            bft::TCP {.sport = 12345, .dport = 80},
                        test->verdictAccept());

    bft_assert_counter_eq("test_ip4_dscp", 0, 1, -1);
}

/**
 * Verify ip4.dscp ne does not match the configured TOS byte value but matches
 * all other values. The matcher compares the full TOS byte including the ECN
 * bits, not just the DSCP field.
 */
static void ip4_dscp_ne(void **state)
{
    auto *test = static_cast<MatcherTest *>(*state);

    BFT_CHAIN_SET(
        bf::Chain("test_ip4_dscp", test->hook(), BF_VERDICT_ACCEPT)
        << bf::Rule(BF_VERDICT_DROP, true, {},
                    {bf::Matcher(BF_MATCHER_IP4_DSCP, BF_MATCHER_NE, {0x20})}));

    // tos=0x20 should not match NE -> ACCEPT
    bft_assert_prog_run("test_ip4_dscp", test->hook(),
                        bft::Ethernet() /
                            bft::IPv4 {.saddr = "192.0.2.1",
                                       .daddr = "192.0.2.2",
                                       .tos = 0x20} /
                            bft::TCP {.sport = 12345, .dport = 80},
                        test->verdictAccept());

    // tos=0 should match NE -> DROP
    bft_assert_prog_run(
        "test_ip4_dscp", test->hook(),
        bft::Ethernet() /
            bft::IPv4 {.saddr = "192.0.2.1", .daddr = "192.0.2.2", .tos = 0} /
            bft::TCP {.sport = 12345, .dport = 80},
        test->verdictDrop());

    bft_assert_counter_eq("test_ip4_dscp", 0, 1, -1);
}

int main()
{
    auto suite = MatcherTestsSuite(BF_MATCHER_IP4_DSCP);

    suite << MatcherTest(BF_MATCHER_IP4_DSCP, BF_MATCHER_EQ, ip4_dscp_eq);
    suite << MatcherTest(BF_MATCHER_IP4_DSCP, BF_MATCHER_NE, ip4_dscp_ne);

    return suite.run();
}
