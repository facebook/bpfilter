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
 * Verify meta.probability eq at 100% always matches and at 0% never matches.
 * These boundary values give deterministic outcomes without relying on random
 * number distribution.
 */
static void meta_probability_eq(void **state)
{
    auto *test = static_cast<MatcherTest *>(*state);

    // 100.0f always matches
    BFT_CHAIN_SET(
        bf::Chain("test_meta_prob", test->hook(), BF_VERDICT_ACCEPT)
        << bf::Rule(BF_VERDICT_DROP, bf_counter(), {},
                    {bf::Matcher(BF_MATCHER_META_PROBABILITY, BF_MATCHER_EQ,
                                 bft_float_payload(100.0f))}));

    bft_assert_prog_run(
        "test_meta_prob", test->hook(),
        bft::Ethernet() /
            bft::IPv4 {.saddr = "192.0.2.1", .daddr = "192.0.2.2"} /
            bft::TCP {.sport = 12345, .dport = 80},
        test->verdictDrop());

    bft_assert_counter_eq("test_meta_prob", 0, 1, -1);

    // 0.0f should never match
    BFT_CHAIN_SET(
        bf::Chain("test_meta_prob", test->hook(), BF_VERDICT_ACCEPT)
        << bf::Rule(BF_VERDICT_DROP, bf_counter(), {},
                    {bf::Matcher(BF_MATCHER_META_PROBABILITY, BF_MATCHER_EQ,
                                 bft_float_payload(0.0f))}));

    bft_assert_prog_run(
        "test_meta_prob", test->hook(),
        bft::Ethernet() /
            bft::IPv4 {.saddr = "192.0.2.1", .daddr = "192.0.2.2"} /
            bft::TCP {.sport = 12345, .dport = 80},
        test->verdictAccept());

    bft_assert_counter_eq("test_meta_prob", 0, 0, -1);

    // Negated 100.0f should never match
    BFT_CHAIN_SET(
        bf::Chain("test_meta_prob", test->hook(), BF_VERDICT_ACCEPT)
        << bf::Rule(BF_VERDICT_DROP, bf_counter(), {},
                    {bf::Matcher(BF_MATCHER_META_PROBABILITY, BF_MATCHER_EQ,
                                 bft_float_payload(100.0f), true)}));

    bft_assert_prog_run(
        "test_meta_prob", test->hook(),
        bft::Ethernet() /
            bft::IPv4 {.saddr = "192.0.2.1", .daddr = "192.0.2.2"} /
            bft::TCP {.sport = 12345, .dport = 80},
        test->verdictAccept());

    bft_assert_counter_eq("test_meta_prob", 0, 0, -1);

    // Negated 0.0f should always match
    BFT_CHAIN_SET(
        bf::Chain("test_meta_prob", test->hook(), BF_VERDICT_ACCEPT)
        << bf::Rule(BF_VERDICT_DROP, bf_counter(), {},
                    {bf::Matcher(BF_MATCHER_META_PROBABILITY, BF_MATCHER_EQ,
                                 bft_float_payload(0.0f), true)}));

    bft_assert_prog_run(
        "test_meta_prob", test->hook(),
        bft::Ethernet() /
            bft::IPv4 {.saddr = "192.0.2.1", .daddr = "192.0.2.2"} /
            bft::TCP {.sport = 12345, .dport = 80},
        test->verdictDrop());

    bft_assert_counter_eq("test_meta_prob", 0, 1, -1);
}

int main()
{
    auto suite = MatcherTestsSuite(BF_MATCHER_META_PROBABILITY);

    suite << MatcherTest(BF_MATCHER_META_PROBABILITY, BF_MATCHER_EQ,
                         meta_probability_eq);

    return suite.run();
}
