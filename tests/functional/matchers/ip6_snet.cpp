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
 * Verify ip6.snet eq matches packets whose IPv6 source address falls within
 * the configured prefix and rejects those outside. Exercises the /32, /128
 * (no-masking code path in bf_cmp_masked_value()), and /0 (match-all) prefix
 * lengths.
 */
static void ip6_snet_eq(void **state)
{
    auto *test = static_cast<MatcherTest *>(*state);

    // 2001:db8::/32
    BFT_CHAIN_SET(
        bf::Chain("test_ip6_snet", test->hook(), BF_VERDICT_ACCEPT)
        << bf::Rule(BF_VERDICT_DROP, true, {},
                    {bf::Matcher(BF_MATCHER_IP6_SNET, BF_MATCHER_EQ,
                                 bft_ip6_lpm_key(32, "2001:db8::"))}));

    // saddr=2001:db8::1 is in 2001:db8::/32 -> DROP
    bft_assert_prog_run(
        "test_ip6_snet", test->hook(),
        bft::Ethernet() /
            bft::IPv6 {.saddr = "2001:db8::1", .daddr = "2001:db8::2"} /
            bft::TCP {.sport = 12345, .dport = 80},
        test->verdictDrop());

    // saddr=2001:db8:: (network base address) is in 2001:db8::/32 -> DROP
    bft_assert_prog_run(
        "test_ip6_snet", test->hook(),
        bft::Ethernet() /
            bft::IPv6 {.saddr = "2001:db8::", .daddr = "2001:db8::2"} /
            bft::TCP {.sport = 12345, .dport = 80},
        test->verdictDrop());

    // saddr=2001:db9::1 is not in 2001:db8::/32 -> ACCEPT
    bft_assert_prog_run(
        "test_ip6_snet", test->hook(),
        bft::Ethernet() /
            bft::IPv6 {.saddr = "2001:db9::1", .daddr = "2001:db8::2"} /
            bft::TCP {.sport = 12345, .dport = 80},
        test->verdictAccept());

    bft_assert_counter_eq("test_ip6_snet", 0, 2, -1);

    // /128 (single host): mask[15]=0xff triggers the no-masking code path in
    // bf_cmp_masked_value(), comparing both 64-bit halves directly without AND.
    BFT_CHAIN_SET(
        bf::Chain("test_ip6_snet", test->hook(), BF_VERDICT_ACCEPT)
        << bf::Rule(BF_VERDICT_DROP, true, {},
                    {bf::Matcher(BF_MATCHER_IP6_SNET, BF_MATCHER_EQ,
                                 bft_ip6_lpm_key(128, "2001:db8::1"))}));

    // saddr=2001:db8::1 exactly matches the /128 -> DROP
    bft_assert_prog_run(
        "test_ip6_snet", test->hook(),
        bft::Ethernet() /
            bft::IPv6 {.saddr = "2001:db8::1", .daddr = "2001:db8::2"} /
            bft::TCP {.sport = 12345, .dport = 80},
        test->verdictDrop());

    // saddr=2001:db8::2 does not match the /128 -> ACCEPT
    bft_assert_prog_run(
        "test_ip6_snet", test->hook(),
        bft::Ethernet() /
            bft::IPv6 {.saddr = "2001:db8::2", .daddr = "2001:db8::2"} /
            bft::TCP {.sport = 12345, .dport = 80},
        test->verdictAccept());

    bft_assert_counter_eq("test_ip6_snet", 0, 1, -1);

    // /0 (match all): mask=0 causes all addresses to AND to 0, matching any
    // source address.
    BFT_CHAIN_SET(bf::Chain("test_ip6_snet", test->hook(), BF_VERDICT_ACCEPT)
                  << bf::Rule(BF_VERDICT_DROP, true, {},
                              {bf::Matcher(BF_MATCHER_IP6_SNET, BF_MATCHER_EQ,
                                           bft_ip6_lpm_key(0, "::"))}));

    // any saddr matches /0 -> DROP
    bft_assert_prog_run(
        "test_ip6_snet", test->hook(),
        bft::Ethernet() /
            bft::IPv6 {.saddr = "fe80::1", .daddr = "2001:db8::2"} /
            bft::TCP {.sport = 12345, .dport = 80},
        test->verdictDrop());

    bft_assert_counter_eq("test_ip6_snet", 0, 1, -1);
}

/**
 * Verify ip6.snet ne does not match when the IPv6 source address is within
 * the configured prefix but matches addresses outside it. Exercises /32, /128
 * (no-masking code path), and /0 (which covers all addresses, so NE /0 never
 * matches).
 */
static void ip6_snet_ne(void **state)
{
    auto *test = static_cast<MatcherTest *>(*state);

    BFT_CHAIN_SET(
        bf::Chain("test_ip6_snet", test->hook(), BF_VERDICT_ACCEPT)
        << bf::Rule(BF_VERDICT_DROP, true, {},
                    {bf::Matcher(BF_MATCHER_IP6_SNET, BF_MATCHER_NE,
                                 bft_ip6_lpm_key(32, "2001:db8::"))}));

    // saddr in subnet -> NE does not match -> ACCEPT
    bft_assert_prog_run(
        "test_ip6_snet", test->hook(),
        bft::Ethernet() /
            bft::IPv6 {.saddr = "2001:db8::1", .daddr = "2001:db8::2"} /
            bft::TCP {.sport = 12345, .dport = 80},
        test->verdictAccept());

    // saddr outside subnet -> NE matches -> DROP
    bft_assert_prog_run(
        "test_ip6_snet", test->hook(),
        bft::Ethernet() /
            bft::IPv6 {.saddr = "2001:db9::1", .daddr = "2001:db8::2"} /
            bft::TCP {.sport = 12345, .dport = 80},
        test->verdictDrop());

    bft_assert_counter_eq("test_ip6_snet", 0, 1, -1);

    // /128 ne: saddr matching the exact host -> NE does not match -> ACCEPT;
    // saddr differing by one bit -> NE matches -> DROP. Exercises the
    // no-masking code path.
    BFT_CHAIN_SET(
        bf::Chain("test_ip6_snet", test->hook(), BF_VERDICT_ACCEPT)
        << bf::Rule(BF_VERDICT_DROP, true, {},
                    {bf::Matcher(BF_MATCHER_IP6_SNET, BF_MATCHER_NE,
                                 bft_ip6_lpm_key(128, "2001:db8::1"))}));

    bft_assert_prog_run(
        "test_ip6_snet", test->hook(),
        bft::Ethernet() /
            bft::IPv6 {.saddr = "2001:db8::1", .daddr = "2001:db8::2"} /
            bft::TCP {.sport = 12345, .dport = 80},
        test->verdictAccept());

    bft_assert_prog_run(
        "test_ip6_snet", test->hook(),
        bft::Ethernet() /
            bft::IPv6 {.saddr = "2001:db8::2", .daddr = "2001:db8::2"} /
            bft::TCP {.sport = 12345, .dport = 80},
        test->verdictDrop());

    bft_assert_counter_eq("test_ip6_snet", 0, 1, -1);

    // /0 ne: /0 covers the entire address space; NE /0 never matches.
    BFT_CHAIN_SET(bf::Chain("test_ip6_snet", test->hook(), BF_VERDICT_ACCEPT)
                  << bf::Rule(BF_VERDICT_DROP, true, {},
                              {bf::Matcher(BF_MATCHER_IP6_SNET, BF_MATCHER_NE,
                                           bft_ip6_lpm_key(0, "::"))}));

    bft_assert_prog_run(
        "test_ip6_snet", test->hook(),
        bft::Ethernet() /
            bft::IPv6 {.saddr = "fe80::1", .daddr = "2001:db8::2"} /
            bft::TCP {.sport = 12345, .dport = 80},
        test->verdictAccept());

    bft_assert_counter_eq("test_ip6_snet", 0, 0, -1);
}

/**
 * Verify ip6.snet in {set} matches packets whose IPv6 source address falls
 * within any prefix in the set and rejects those outside all set members.
 */
static void ip6_snet_in(void **state)
{
    auto *test = static_cast<MatcherTest *>(*state);

    auto set = bf::Set({BF_MATCHER_IP6_SNET});
    set << bft_ip6_lpm_key(32, "2001:db8::") << bft_ip6_lpm_key(64, "fd00::");

    BFT_CHAIN_SET(bf::Chain("test_ip6_snet", test->hook(), BF_VERDICT_ACCEPT)
                  << std::move(set)
                  << bf::Rule(BF_VERDICT_DROP, true, {},
                              {bf::Matcher(BF_MATCHER_SET, BF_MATCHER_IN,
                                           {0, 0, 0, 0})}));

    // saddr=2001:db8::1 matches 2001:db8::/32 in set -> DROP
    bft_assert_prog_run(
        "test_ip6_snet", test->hook(),
        bft::Ethernet() /
            bft::IPv6 {.saddr = "2001:db8::1", .daddr = "2001:db8::2"} /
            bft::TCP {.sport = 12345, .dport = 80},
        test->verdictDrop());

    // saddr=fd00::1 matches fd00::/64 (second set element) -> DROP
    bft_assert_prog_run(
        "test_ip6_snet", test->hook(),
        bft::Ethernet() /
            bft::IPv6 {.saddr = "fd00::1", .daddr = "2001:db8::2"} /
            bft::TCP {.sport = 12345, .dport = 80},
        test->verdictDrop());

    // saddr=fe80::1 not in any set subnet -> ACCEPT
    bft_assert_prog_run(
        "test_ip6_snet", test->hook(),
        bft::Ethernet() /
            bft::IPv6 {.saddr = "fe80::1", .daddr = "2001:db8::2"} /
            bft::TCP {.sport = 12345, .dport = 80},
        test->verdictAccept());

    bft_assert_counter_eq("test_ip6_snet", 0, 2, -1);
}

int main()
{
    auto suite = MatcherTestsSuite(BF_MATCHER_IP6_SNET);

    suite << MatcherTest(BF_MATCHER_IP6_SNET, BF_MATCHER_EQ, ip6_snet_eq);
    suite << MatcherTest(BF_MATCHER_IP6_SNET, BF_MATCHER_NE, ip6_snet_ne);
    suite << MatcherTest(BF_MATCHER_IP6_SNET, BF_MATCHER_IN, ip6_snet_in);

    return suite.run();
}
