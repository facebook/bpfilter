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
 * Verify that icmp.code eq N matches a packet with ICMP code N and
 * does not match a packet with a different code. Counter must be
 * updated only for the matching packet.
 */
static void icmp_code_eq(void **state)
{
    auto *test = static_cast<MatcherTest *>(*state);

    BFT_CHAIN_SET(
        bf::Chain("test_icmp_code", test->hook(), BF_VERDICT_ACCEPT)
        << bf::Rule(BF_VERDICT_DROP, true, {},
                    {bf::Matcher(BF_MATCHER_ICMP_CODE, BF_MATCHER_EQ, {3})}));

    // ICMP code=3 should match the rule -> DROP
    bft_assert_prog_run(
        "test_icmp_code", test->hook(),
        bft::Ethernet() /
            bft::IPv4 {.saddr = "127.0.0.1", .daddr = "127.0.0.2"} /
            bft::ICMPv4 {.type = 8, .code = 3},
        test->verdictDrop());

    // ICMP code=0 should not match -> ACCEPT (policy)
    bft_assert_prog_run(
        "test_icmp_code", test->hook(),
        bft::Ethernet() /
            bft::IPv4 {.saddr = "127.0.0.1", .daddr = "127.0.0.2"} /
            bft::ICMPv4 {.type = 8, .code = 0},
        test->verdictAccept());

    bft_assert_counter_eq("test_icmp_code", 0, 1, -1);
}

/**
 * Verify that icmp.code ne N does not match a packet with code N
 * but matches packets with different codes.
 */
static void icmp_code_ne(void **state)
{
    auto *test = static_cast<MatcherTest *>(*state);

    BFT_CHAIN_SET(
        bf::Chain("test_icmp_code", test->hook(), BF_VERDICT_ACCEPT)
        << bf::Rule(BF_VERDICT_DROP, true, {},
                    {bf::Matcher(BF_MATCHER_ICMP_CODE, BF_MATCHER_NE, {3})}));

    // ICMP code=3 should not match -> ACCEPT (policy)
    bft_assert_prog_run(
        "test_icmp_code", test->hook(),
        bft::Ethernet() /
            bft::IPv4 {.saddr = "127.0.0.1", .daddr = "127.0.0.2"} /
            bft::ICMPv4 {.type = 8, .code = 3},
        test->verdictAccept());

    // ICMP code=0 should match -> DROP
    bft_assert_prog_run(
        "test_icmp_code", test->hook(),
        bft::Ethernet() /
            bft::IPv4 {.saddr = "127.0.0.1", .daddr = "127.0.0.2"} /
            bft::ICMPv4 {.type = 8, .code = 0},
        test->verdictDrop());

    bft_assert_counter_eq("test_icmp_code", 0, 1, -1);
}

int main()
{
    auto suite = MatcherTestsSuite(BF_MATCHER_ICMP_CODE);

    suite << MatcherTest(BF_MATCHER_ICMP_CODE, BF_MATCHER_EQ, icmp_code_eq);
    suite << MatcherTest(BF_MATCHER_ICMP_CODE, BF_MATCHER_NE, icmp_code_ne);

    return suite.run();
}
