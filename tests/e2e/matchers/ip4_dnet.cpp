/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#include "Chain.hpp"
#include "Matcher.hpp"
#include "Rule.hpp"
#include "Set.hpp"
#include "test.hpp"

extern "C" {
#include <bpfilter/bpfilter.h>
}

/**
 * Verify ip4.dnet eq matches packets whose destination address falls within
 * the configured subnet and rejects those outside. Exercises the /24, /32
 * (no-masking code path), and /0 (match-all) prefix lengths.
 */
static void ip4_dnet_eq(void **state)
{
    auto *test = static_cast<MatcherTest *>(*state);

    BFT_CHAIN_SET(
        bf::Chain("test_ip4_dnet", test->hook(), BF_VERDICT_ACCEPT)
        << bf::Rule(BF_VERDICT_DROP, true, {},
                    {bf::Matcher(BF_MATCHER_IP4_DNET, BF_MATCHER_EQ,
                                 bft_ip4_lpm_key(24, 192, 0, 2, 0))}));

    // daddr=192.0.2.100 is in 192.0.2.0/24 -> DROP
    bft_assert_prog_run(
        "test_ip4_dnet", test->hook(),
        bft::Ethernet() /
            bft::IPv4 {.saddr = "192.0.2.1", .daddr = "192.0.2.100"} /
            bft::TCP {.sport = 12345, .dport = 80},
        test->verdictDrop());

    // daddr=192.0.2.0 (network address) is in 192.0.2.0/24 -> DROP
    bft_assert_prog_run(
        "test_ip4_dnet", test->hook(),
        bft::Ethernet() /
            bft::IPv4 {.saddr = "192.0.2.1", .daddr = "192.0.2.0"} /
            bft::TCP {.sport = 12345, .dport = 80},
        test->verdictDrop());

    // daddr=192.0.2.255 (broadcast address) is in 192.0.2.0/24 -> DROP
    bft_assert_prog_run(
        "test_ip4_dnet", test->hook(),
        bft::Ethernet() /
            bft::IPv4 {.saddr = "192.0.2.1", .daddr = "192.0.2.255"} /
            bft::TCP {.sport = 12345, .dport = 80},
        test->verdictDrop());

    // daddr=192.0.3.1 is not in 192.0.2.0/24 -> ACCEPT
    bft_assert_prog_run(
        "test_ip4_dnet", test->hook(),
        bft::Ethernet() /
            bft::IPv4 {.saddr = "192.0.2.1", .daddr = "192.0.3.1"} /
            bft::TCP {.sport = 12345, .dport = 80},
        test->verdictAccept());

    bft_assert_counter_eq("test_ip4_dnet", 0, 3, -1);

    // /32 (single host): exercises the no-masking code path.
    BFT_CHAIN_SET(
        bf::Chain("test_ip4_dnet", test->hook(), BF_VERDICT_ACCEPT)
        << bf::Rule(BF_VERDICT_DROP, true, {},
                    {bf::Matcher(BF_MATCHER_IP4_DNET, BF_MATCHER_EQ,
                                 bft_ip4_lpm_key(32, 192, 0, 2, 2))}));

    // daddr=192.0.2.2 exactly matches the /32 -> DROP
    bft_assert_prog_run(
        "test_ip4_dnet", test->hook(),
        bft::Ethernet() /
            bft::IPv4 {.saddr = "192.0.2.1", .daddr = "192.0.2.2"} /
            bft::TCP {.sport = 12345, .dport = 80},
        test->verdictDrop());

    // daddr=192.0.2.1 does not match the /32 -> ACCEPT
    bft_assert_prog_run(
        "test_ip4_dnet", test->hook(),
        bft::Ethernet() /
            bft::IPv4 {.saddr = "192.0.2.1", .daddr = "192.0.2.1"} /
            bft::TCP {.sport = 12345, .dport = 80},
        test->verdictAccept());

    bft_assert_counter_eq("test_ip4_dnet", 0, 1, -1);

    // /0 (match all): mask=0 causes all addresses to AND to 0, matching any
    // destination address.
    BFT_CHAIN_SET(bf::Chain("test_ip4_dnet", test->hook(), BF_VERDICT_ACCEPT)
                  << bf::Rule(BF_VERDICT_DROP, true, {},
                              {bf::Matcher(BF_MATCHER_IP4_DNET, BF_MATCHER_EQ,
                                           bft_ip4_lpm_key(0, 0, 0, 0, 0))}));

    // any daddr matches /0 -> DROP
    bft_assert_prog_run(
        "test_ip4_dnet", test->hook(),
        bft::Ethernet() /
            bft::IPv4 {.saddr = "192.0.2.1", .daddr = "10.0.0.1"} /
            bft::TCP {.sport = 12345, .dport = 80},
        test->verdictDrop());

    bft_assert_counter_eq("test_ip4_dnet", 0, 1, -1);
}

/**
 * Verify ip4.dnet ne does not match when the destination address is within
 * the configured subnet but matches addresses outside it. Exercises /24, /32
 * (no-masking code path), and /0 (which covers all addresses, so NE /0 never
 * matches).
 */
static void ip4_dnet_ne(void **state)
{
    auto *test = static_cast<MatcherTest *>(*state);

    BFT_CHAIN_SET(
        bf::Chain("test_ip4_dnet", test->hook(), BF_VERDICT_ACCEPT)
        << bf::Rule(BF_VERDICT_DROP, true, {},
                    {bf::Matcher(BF_MATCHER_IP4_DNET, BF_MATCHER_NE,
                                 bft_ip4_lpm_key(24, 192, 0, 2, 0))}));

    // daddr=192.0.2.100 is in subnet -> NE does not match -> ACCEPT
    bft_assert_prog_run(
        "test_ip4_dnet", test->hook(),
        bft::Ethernet() /
            bft::IPv4 {.saddr = "192.0.2.1", .daddr = "192.0.2.100"} /
            bft::TCP {.sport = 12345, .dport = 80},
        test->verdictAccept());

    // daddr=192.0.3.1 is not in subnet -> NE matches -> DROP
    bft_assert_prog_run(
        "test_ip4_dnet", test->hook(),
        bft::Ethernet() /
            bft::IPv4 {.saddr = "192.0.2.1", .daddr = "192.0.3.1"} /
            bft::TCP {.sport = 12345, .dport = 80},
        test->verdictDrop());

    bft_assert_counter_eq("test_ip4_dnet", 0, 1, -1);

    // /32 ne: daddr exactly matching the host -> NE does not match -> ACCEPT
    BFT_CHAIN_SET(
        bf::Chain("test_ip4_dnet", test->hook(), BF_VERDICT_ACCEPT)
        << bf::Rule(BF_VERDICT_DROP, true, {},
                    {bf::Matcher(BF_MATCHER_IP4_DNET, BF_MATCHER_NE,
                                 bft_ip4_lpm_key(32, 192, 0, 2, 2))}));

    bft_assert_prog_run(
        "test_ip4_dnet", test->hook(),
        bft::Ethernet() /
            bft::IPv4 {.saddr = "192.0.2.1", .daddr = "192.0.2.2"} /
            bft::TCP {.sport = 12345, .dport = 80},
        test->verdictAccept());

    // daddr differs from the /32 host -> NE matches -> DROP
    bft_assert_prog_run(
        "test_ip4_dnet", test->hook(),
        bft::Ethernet() /
            bft::IPv4 {.saddr = "192.0.2.1", .daddr = "192.0.2.1"} /
            bft::TCP {.sport = 12345, .dport = 80},
        test->verdictDrop());

    bft_assert_counter_eq("test_ip4_dnet", 0, 1, -1);

    // /0 ne: /0 covers the entire address space; NE /0 never matches.
    BFT_CHAIN_SET(bf::Chain("test_ip4_dnet", test->hook(), BF_VERDICT_ACCEPT)
                  << bf::Rule(BF_VERDICT_DROP, true, {},
                              {bf::Matcher(BF_MATCHER_IP4_DNET, BF_MATCHER_NE,
                                           bft_ip4_lpm_key(0, 0, 0, 0, 0))}));

    bft_assert_prog_run(
        "test_ip4_dnet", test->hook(),
        bft::Ethernet() /
            bft::IPv4 {.saddr = "192.0.2.1", .daddr = "10.0.0.1"} /
            bft::TCP {.sport = 12345, .dport = 80},
        test->verdictAccept());

    bft_assert_counter_eq("test_ip4_dnet", 0, 0, -1);
}

/**
 * Verify ip4.dnet in {set} matches packets whose destination address falls
 * within any subnet in the set and rejects those outside all set members.
 */
static void ip4_dnet_in(void **state)
{
    auto *test = static_cast<MatcherTest *>(*state);

    auto set = bf::Set({BF_MATCHER_IP4_DNET});
    set << bft_ip4_lpm_key(24, 192, 0, 2, 0)
        << bft_ip4_lpm_key(16, 10, 0, 0, 0);

    BFT_CHAIN_SET(bf::Chain("test_ip4_dnet", test->hook(), BF_VERDICT_ACCEPT)
                  << std::move(set)
                  << bf::Rule(BF_VERDICT_DROP, true, {},
                              {bf::Matcher(BF_MATCHER_SET, BF_MATCHER_IN,
                                           {0, 0, 0, 0})}));

    // daddr=10.0.1.1 matches 10.0.0.0/16 in set -> DROP
    bft_assert_prog_run(
        "test_ip4_dnet", test->hook(),
        bft::Ethernet() /
            bft::IPv4 {.saddr = "192.0.2.1", .daddr = "10.0.1.1"} /
            bft::TCP {.sport = 12345, .dport = 80},
        test->verdictDrop());

    // daddr=192.0.2.100 matches 192.0.2.0/24 (first set element) -> DROP
    bft_assert_prog_run(
        "test_ip4_dnet", test->hook(),
        bft::Ethernet() /
            bft::IPv4 {.saddr = "192.0.2.1", .daddr = "192.0.2.100"} /
            bft::TCP {.sport = 12345, .dport = 80},
        test->verdictDrop());

    // daddr=172.16.0.1 not in any set subnet -> ACCEPT
    bft_assert_prog_run(
        "test_ip4_dnet", test->hook(),
        bft::Ethernet() /
            bft::IPv4 {.saddr = "192.0.2.1", .daddr = "172.16.0.1"} /
            bft::TCP {.sport = 12345, .dport = 80},
        test->verdictAccept());

    bft_assert_counter_eq("test_ip4_dnet", 0, 2, -1);
}

int main()
{
    auto suite = MatcherTestsSuite(BF_MATCHER_IP4_DNET);

    suite << MatcherTest(BF_MATCHER_IP4_DNET, BF_MATCHER_EQ, ip4_dnet_eq);
    suite << MatcherTest(BF_MATCHER_IP4_DNET, BF_MATCHER_NE, ip4_dnet_ne);
    suite << MatcherTest(BF_MATCHER_IP4_DNET, BF_MATCHER_IN, ip4_dnet_in);

    return suite.run();
}
