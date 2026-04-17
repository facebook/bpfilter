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
 * Verify meta.sport eq matches packets from the configured source port across
 * both TCP and UDP (meta matcher is protocol-agnostic) and over IPv4 and IPv6.
 * ICMP packets must not match since the matcher skips non-TCP/UDP traffic.
 */
static void meta_sport_eq(void **state)
{
    auto *test = static_cast<MatcherTest *>(*state);

    BFT_CHAIN_SET(bf::Chain("test_meta_sport", test->hook(), BF_VERDICT_ACCEPT)
                  << bf::Rule(BF_VERDICT_DROP, true, BF_RULE_LOG_NONE, {},
                              {bf::Matcher(BF_MATCHER_META_SPORT, BF_MATCHER_EQ,
                                           bft_port_be(12345))}));

    // TCP sport=12345 should match -> DROP
    bft_assert_prog_run(
        "test_meta_sport", test->hook(),
        bft::Ethernet() /
            bft::IPv4 {.saddr = "192.0.2.1", .daddr = "192.0.2.2"} /
            bft::TCP {.sport = 12345, .dport = 80},
        test->verdictDrop());

    // UDP sport=12345 should also match -> DROP (meta matcher is protocol-agnostic)
    bft_assert_prog_run(
        "test_meta_sport", test->hook(),
        bft::Ethernet() /
            bft::IPv4 {.saddr = "192.0.2.1", .daddr = "192.0.2.2"} /
            bft::UDP {.sport = 12345, .dport = 53},
        test->verdictDrop());

    // TCP over IPv6 sport=12345 should also match -> DROP
    bft_assert_prog_run(
        "test_meta_sport", test->hook(),
        bft::Ethernet() /
            bft::IPv6 {.saddr = "2001:db8::1", .daddr = "2001:db8::2"} /
            bft::TCP {.sport = 12345, .dport = 80},
        test->verdictDrop());

    // TCP sport=54321 should not match -> ACCEPT
    bft_assert_prog_run(
        "test_meta_sport", test->hook(),
        bft::Ethernet() /
            bft::IPv4 {.saddr = "192.0.2.1", .daddr = "192.0.2.2"} /
            bft::TCP {.sport = 54321, .dport = 80},
        test->verdictAccept());

    // ICMP is neither TCP nor UDP: meta_sport sets R1=0 and jumps to the next
    // rule, so the drop rule must not fire regardless of the port value.
    bft_assert_prog_run(
        "test_meta_sport", test->hook(),
        bft::Ethernet() /
            bft::IPv4 {.saddr = "192.0.2.1", .daddr = "192.0.2.2"} /
            bft::ICMPv4 {.type = 8, .code = 0},
        test->verdictAccept());

    bft_assert_counter_eq("test_meta_sport", 0, 3, -1);
}

/**
 * Verify meta.sport ne does not match the configured source port but matches
 * packets from any other port across both TCP and UDP.
 */
static void meta_sport_ne(void **state)
{
    auto *test = static_cast<MatcherTest *>(*state);

    BFT_CHAIN_SET(bf::Chain("test_meta_sport", test->hook(), BF_VERDICT_ACCEPT)
                  << bf::Rule(BF_VERDICT_DROP, true, BF_RULE_LOG_NONE, {},
                              {bf::Matcher(BF_MATCHER_META_SPORT, BF_MATCHER_NE,
                                           bft_port_be(12345))}));

    bft_assert_prog_run(
        "test_meta_sport", test->hook(),
        bft::Ethernet() /
            bft::IPv4 {.saddr = "192.0.2.1", .daddr = "192.0.2.2"} /
            bft::TCP {.sport = 12345, .dport = 80},
        test->verdictAccept());

    bft_assert_prog_run(
        "test_meta_sport", test->hook(),
        bft::Ethernet() /
            bft::IPv4 {.saddr = "192.0.2.1", .daddr = "192.0.2.2"} /
            bft::TCP {.sport = 54321, .dport = 80},
        test->verdictDrop());

    // UDP sport=54321 also matches -> DROP (meta matcher is protocol-agnostic)
    bft_assert_prog_run(
        "test_meta_sport", test->hook(),
        bft::Ethernet() /
            bft::IPv4 {.saddr = "192.0.2.1", .daddr = "192.0.2.2"} /
            bft::UDP {.sport = 54321, .dport = 53},
        test->verdictDrop());

    bft_assert_counter_eq("test_meta_sport", 0, 2, -1);
}

/**
 * Verify meta.sport range [min, max] matches packets within the inclusive
 * bounds across both TCP and UDP (meta matcher is protocol-agnostic) and
 * rejects those outside the range.
 */
static void meta_sport_range(void **state)
{
    auto *test = static_cast<MatcherTest *>(*state);

    BFT_CHAIN_SET(
        bf::Chain("test_meta_sport", test->hook(), BF_VERDICT_ACCEPT)
        << bf::Rule(BF_VERDICT_DROP, true, BF_RULE_LOG_NONE, {},
                    {bf::Matcher(BF_MATCHER_META_SPORT, BF_MATCHER_RANGE,
                                 bft_port_range(1000, 2000))}));

    // TCP sport=1000 is at range minimum -> DROP
    bft_assert_prog_run(
        "test_meta_sport", test->hook(),
        bft::Ethernet() /
            bft::IPv4 {.saddr = "192.0.2.1", .daddr = "192.0.2.2"} /
            bft::TCP {.sport = 1000, .dport = 80},
        test->verdictDrop());

    // TCP sport=1500 is in range -> DROP
    bft_assert_prog_run(
        "test_meta_sport", test->hook(),
        bft::Ethernet() /
            bft::IPv4 {.saddr = "192.0.2.1", .daddr = "192.0.2.2"} /
            bft::TCP {.sport = 1500, .dport = 80},
        test->verdictDrop());

    // UDP sport=1500 is also in range -> DROP (meta matcher is protocol-agnostic)
    bft_assert_prog_run(
        "test_meta_sport", test->hook(),
        bft::Ethernet() /
            bft::IPv4 {.saddr = "192.0.2.1", .daddr = "192.0.2.2"} /
            bft::UDP {.sport = 1500, .dport = 53},
        test->verdictDrop());

    // TCP sport=2000 is at range maximum -> DROP
    bft_assert_prog_run(
        "test_meta_sport", test->hook(),
        bft::Ethernet() /
            bft::IPv4 {.saddr = "192.0.2.1", .daddr = "192.0.2.2"} /
            bft::TCP {.sport = 2000, .dport = 80},
        test->verdictDrop());

    // TCP sport=999 is below range -> ACCEPT
    bft_assert_prog_run(
        "test_meta_sport", test->hook(),
        bft::Ethernet() /
            bft::IPv4 {.saddr = "192.0.2.1", .daddr = "192.0.2.2"} /
            bft::TCP {.sport = 999, .dport = 80},
        test->verdictAccept());

    // TCP sport=2001 is above range -> ACCEPT
    bft_assert_prog_run(
        "test_meta_sport", test->hook(),
        bft::Ethernet() /
            bft::IPv4 {.saddr = "192.0.2.1", .daddr = "192.0.2.2"} /
            bft::TCP {.sport = 2001, .dport = 80},
        test->verdictAccept());

    bft_assert_counter_eq("test_meta_sport", 0, 4, -1);
}

int main()
{
    auto suite = MatcherTestsSuite(BF_MATCHER_META_SPORT);

    suite << MatcherTest(BF_MATCHER_META_SPORT, BF_MATCHER_EQ, meta_sport_eq);
    suite << MatcherTest(BF_MATCHER_META_SPORT, BF_MATCHER_NE, meta_sport_ne);
    suite << MatcherTest(BF_MATCHER_META_SPORT, BF_MATCHER_RANGE,
                         meta_sport_range);

    return suite.run();
}
