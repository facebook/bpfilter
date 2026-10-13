/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 */

#include <vector>

#include "Chain.hpp"
#include "Matcher.hpp"
#include "Rule.hpp"
#include "test.hpp"

extern "C" {
#include <bpfilter/bpfilter.h>
#include <bpfilter/runtime.h>
}

namespace
{

struct FragCase
{
    bft::Packet pkt;
    enum bf_frag frag;
};

/**
 * Packets in each fragmentation state, for both IPv4 and IPv6. A fragment
 * offset of 181 is 1448 bytes, where Linux splits datagrams on a 1500 bytes
 * MTU link.
 */
std::vector<FragCase> fragCases()
{
    return {
        {bft::Ethernet() / bft::IPv4 {} / bft::UDP {}, BF_FRAG_NONE},
        {bft::Ethernet() / bft::IPv4 {.more = true} / bft::UDP {},
         BF_FRAG_FIRST},
        {bft::Ethernet() / bft::IPv4 {.frag_offset = 181, .more = true} /
             bft::UDP {},
         BF_FRAG_LATER},
        {bft::Ethernet() / bft::IPv4 {.frag_offset = 181} / bft::UDP {},
         BF_FRAG_LATER},
        {bft::Ethernet() / bft::IPv6 {} / bft::UDP {}, BF_FRAG_NONE},
        // Atomic fragment: offset 0 and no more fragments
        {bft::Ethernet() / bft::IPv6 {} / bft::IPv6Fragment {} / bft::UDP {},
         BF_FRAG_NONE},
        {bft::Ethernet() / bft::IPv6 {} / bft::IPv6Fragment {.more = true} /
             bft::UDP {},
         BF_FRAG_FIRST},
        {bft::Ethernet() / bft::IPv6 {} / bft::IPv6HopByHop {} /
             bft::IPv6Fragment {.more = true} / bft::TCP {},
         BF_FRAG_FIRST},
        {bft::Ethernet() / bft::IPv6 {} /
             bft::IPv6Fragment {.offset = 181, .more = true} / bft::UDP {},
         BF_FRAG_LATER},
        {bft::Ethernet() / bft::IPv6 {} / bft::IPv6DstOpts {} /
             bft::IPv6Fragment {.offset = 181} / bft::UDP {},
         BF_FRAG_LATER},
    };
}

} // namespace

/**
 * Verify meta.frag eq matches the packets in the configured fragmentation
 * state only, for both IPv4 and IPv6, with and without negation.
 */
static void meta_frag_eq(void **state)
{
    auto *test = static_cast<MatcherTest *>(*state);
    const auto cases = fragCases();

    for (const enum bf_frag frag:
         {BF_FRAG_NONE, BF_FRAG_FIRST, BF_FRAG_LATER}) {
        for (const bool negate: {false, true}) {
            bft_with_ipv6_parsers(
                bf::Chain("test_meta_frag", test->hook(), BF_VERDICT_ACCEPT)
                    << bf::Rule(
                           BF_VERDICT_DROP, bf_counter(), {},
                           {bf::Matcher(BF_MATCHER_META_FRAG, BF_MATCHER_EQ,
                                        {static_cast<uint8_t>(frag)}, negate)}),
                [&]() {
                    uint64_t matched = 0;

                    for (const auto &c: cases) {
                        const bool match = (c.frag == frag) != negate;

                        bft_assert_prog_run("test_meta_frag", test->hook(),
                                            c.pkt,
                                            match ? test->verdictDrop() :
                                                    test->verdictAccept());
                        matched += match ? 1 : 0;
                    }

                    bft_assert_counter_eq("test_meta_frag", 0, matched, -1);
                });
        }
    }
}

int main()
{
    auto suite = MatcherTestsSuite(BF_MATCHER_META_FRAG);

    suite << MatcherTest(BF_MATCHER_META_FRAG, BF_MATCHER_EQ, meta_frag_eq);

    return suite.run();
}
