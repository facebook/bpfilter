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
 * Verify ip6.dscp eq matches the configured traffic class byte value and
 * rejects others. The matcher compares the full traffic class byte including
 * the ECN bits, not just the DSCP field, so a packet with the same DSCP but
 * non-zero ECN must not match.
 */
static void ip6_dscp_eq(void **state)
{
    auto *test = static_cast<MatcherTest *>(*state);

    // traffic_class=0x20 (DSCP 8 / CS1)
    BFT_CHAIN_SET(
        bf::Chain("test_ip6_dscp", test->hook(), BF_VERDICT_ACCEPT)
        << bf::Rule(BF_VERDICT_DROP, true, {},
                    {bf::Matcher(BF_MATCHER_IP6_DSCP, BF_MATCHER_EQ, {0x20})}));

    bft_assert_prog_run("test_ip6_dscp", test->hook(),
                        bft::Ethernet() /
                            bft::IPv6 {.saddr = "2001:db8::1",
                                       .daddr = "2001:db8::2",
                                       .traffic_class = 0x20} /
                            bft::TCP {.sport = 12345, .dport = 80},
                        test->verdictDrop());

    bft_assert_prog_run("test_ip6_dscp", test->hook(),
                        bft::Ethernet() /
                            bft::IPv6 {.saddr = "2001:db8::1",
                                       .daddr = "2001:db8::2",
                                       .traffic_class = 0} /
                            bft::TCP {.sport = 12345, .dport = 80},
                        test->verdictAccept());

    // traffic_class=0x21 has the same DSCP bits (8) as 0x20 but ECN=1; the
    // matcher compares the full traffic class byte, so this must not match
    // -> ACCEPT
    bft_assert_prog_run("test_ip6_dscp", test->hook(),
                        bft::Ethernet() /
                            bft::IPv6 {.saddr = "2001:db8::1",
                                       .daddr = "2001:db8::2",
                                       .traffic_class = 0x21} /
                            bft::TCP {.sport = 12345, .dport = 80},
                        test->verdictAccept());

    bft_assert_counter_eq("test_ip6_dscp", 0, 1, -1);
}

/**
 * Verify ip6.dscp ne does not match the configured traffic class byte value
 * but matches all other values. The matcher compares the full traffic class
 * byte including the ECN bits, not just the DSCP field.
 */
static void ip6_dscp_ne(void **state)
{
    auto *test = static_cast<MatcherTest *>(*state);

    BFT_CHAIN_SET(
        bf::Chain("test_ip6_dscp", test->hook(), BF_VERDICT_ACCEPT)
        << bf::Rule(BF_VERDICT_DROP, true, {},
                    {bf::Matcher(BF_MATCHER_IP6_DSCP, BF_MATCHER_NE, {0x20})}));

    bft_assert_prog_run("test_ip6_dscp", test->hook(),
                        bft::Ethernet() /
                            bft::IPv6 {.saddr = "2001:db8::1",
                                       .daddr = "2001:db8::2",
                                       .traffic_class = 0x20} /
                            bft::TCP {.sport = 12345, .dport = 80},
                        test->verdictAccept());

    bft_assert_prog_run("test_ip6_dscp", test->hook(),
                        bft::Ethernet() /
                            bft::IPv6 {.saddr = "2001:db8::1",
                                       .daddr = "2001:db8::2",
                                       .traffic_class = 0} /
                            bft::TCP {.sport = 12345, .dport = 80},
                        test->verdictDrop());

    bft_assert_counter_eq("test_ip6_dscp", 0, 1, -1);
}

int main()
{
    auto suite = MatcherTestsSuite(BF_MATCHER_IP6_DSCP);

    suite << MatcherTest(BF_MATCHER_IP6_DSCP, BF_MATCHER_EQ, ip6_dscp_eq);
    suite << MatcherTest(BF_MATCHER_IP6_DSCP, BF_MATCHER_NE, ip6_dscp_ne);

    return suite.run();
}
