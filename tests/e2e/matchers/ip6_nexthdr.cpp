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
 * Verify ip6.nexthdr eq matches packets whose IPv6 next header field equals
 * the configured value and rejects packets with a different next header.
 */
static void ip6_nexthdr_eq(void **state)
{
    auto *test = static_cast<MatcherTest *>(*state);

    // IPPROTO_TCP = 6
    BFT_CHAIN_SET(
        bf::Chain("test_ip6_nexthdr", test->hook(), BF_VERDICT_ACCEPT)
        << bf::Rule(BF_VERDICT_DROP, bf_counter(), {},
                    {bf::Matcher(BF_MATCHER_IP6_NEXTHDR, BF_MATCHER_EQ, {6})}));

    // TCP over IPv6 -> nexthdr=6 -> DROP
    bft_assert_prog_run(
        "test_ip6_nexthdr", test->hook(),
        bft::Ethernet() /
            bft::IPv6 {.saddr = "2001:db8::1", .daddr = "2001:db8::2"} /
            bft::TCP {.sport = 12345, .dport = 80},
        test->verdictDrop());

    // TCP after a Fragment header with reserved=8 -> nexthdr=6 -> DROP
    bft_assert_prog_run("test_ip6_nexthdr", test->hook(),
                        bft::Ethernet() / bft::IPv6 {} / bft::IPv6HopByHop {} /
                            bft::IPv6Fragment {.reserved = 8} / bft::TCP {},
                        test->verdictDrop());

    // UDP over IPv6 -> nexthdr=17 -> ACCEPT
    bft_assert_prog_run(
        "test_ip6_nexthdr", test->hook(),
        bft::Ethernet() /
            bft::IPv6 {.saddr = "2001:db8::1", .daddr = "2001:db8::2"} /
            bft::UDP {.sport = 12345, .dport = 53},
        test->verdictAccept());

    // TCP after a Fragment header right after the IPv6 header -> DROP
    bft_assert_prog_run("test_ip6_nexthdr", test->hook(),
                        bft::Ethernet() / bft::IPv6 {} /
                            bft::IPv6Fragment {.more = true} / bft::TCP {},
                        test->verdictDrop());

    // TCP after an Authentication Header -> DROP
    bft_assert_prog_run("test_ip6_nexthdr", test->hook(),
                        bft::Ethernet() / bft::IPv6 {} / bft::IPv6AH {} /
                            bft::TCP {},
                        test->verdictDrop());

    // Truncated TCP header -> nexthdr=6 -> DROP
    auto pkt = bft::Ethernet() / bft::IPv6 {} / bft::TCP {};
    pkt.len -= 1;
    bft_assert_prog_run("test_ip6_nexthdr", test->hook(), pkt,
                        test->verdictDrop());

    // Non-first fragment of a TCP segment -> nexthdr=6 -> DROP
    bft_assert_prog_run("test_ip6_nexthdr", test->hook(),
                        bft::Ethernet() / bft::IPv6 {} /
                            bft::IPv6Fragment {.offset = 181} / bft::TCP {},
                        test->verdictDrop());

    bft_assert_counter_eq("test_ip6_nexthdr", 0, 6, -1);

    // L4 protocol bpfilter doesn't parse: IPPROTO_GRE = 47
    BFT_CHAIN_SET(bf::Chain("test_ip6_nexthdr", test->hook(), BF_VERDICT_ACCEPT)
                  << bf::Rule(BF_VERDICT_DROP, bf_counter(), {},
                              {bf::Matcher(BF_MATCHER_IP6_NEXTHDR,
                                           BF_MATCHER_EQ, {47})}));

    bft_assert_prog_run("test_ip6_nexthdr", test->hook(),
                        bft::Ethernet() / bft::IPv6 {} / bft::GRE {},
                        test->verdictDrop());

    bft_assert_prog_run("test_ip6_nexthdr", test->hook(),
                        bft::Ethernet() / bft::IPv6 {} / bft::IPv6DstOpts {} /
                            bft::GRE {},
                        test->verdictDrop());

    bft_assert_counter_eq("test_ip6_nexthdr", 0, 2, -1);

    // IPPROTO_FRAGMENT = 44: matches the extension header, wherever it is
    BFT_CHAIN_SET(bf::Chain("test_ip6_nexthdr", test->hook(), BF_VERDICT_ACCEPT)
                  << bf::Rule(BF_VERDICT_DROP, bf_counter(), {},
                              {bf::Matcher(BF_MATCHER_IP6_NEXTHDR,
                                           BF_MATCHER_EQ, {44})}));

    // Fragment header right after the IPv6 header -> DROP
    bft_assert_prog_run("test_ip6_nexthdr", test->hook(),
                        bft::Ethernet() / bft::IPv6 {} /
                            bft::IPv6Fragment {.more = true} / bft::UDP {},
                        test->verdictDrop());

    // Fragment header after a Hop-by-Hop Options header -> DROP
    bft_assert_prog_run("test_ip6_nexthdr", test->hook(),
                        bft::Ethernet() / bft::IPv6 {} / bft::IPv6HopByHop {} /
                            bft::IPv6Fragment {.more = true} / bft::UDP {},
                        test->verdictDrop());

    // Non-first fragment -> DROP
    bft_assert_prog_run("test_ip6_nexthdr", test->hook(),
                        bft::Ethernet() / bft::IPv6 {} /
                            bft::IPv6Fragment {.offset = 181} / bft::UDP {},
                        test->verdictDrop());

    // No Fragment header -> ACCEPT
    bft_assert_prog_run("test_ip6_nexthdr", test->hook(),
                        bft::Ethernet() / bft::IPv6 {} / bft::IPv6DstOpts {} /
                            bft::UDP {},
                        test->verdictAccept());

    bft_assert_counter_eq("test_ip6_nexthdr", 0, 3, -1);

    // Negation
    BFT_CHAIN_SET(bf::Chain("test_ip6_nexthdr", test->hook(), BF_VERDICT_ACCEPT)
                  << bf::Rule(BF_VERDICT_DROP, bf_counter(), {},
                              {bf::Matcher(BF_MATCHER_IP6_NEXTHDR,
                                           BF_MATCHER_EQ, {6}, true)}));

    // TCP -> nexthdr=6 -> not eq does not match -> ACCEPT
    bft_assert_prog_run(
        "test_ip6_nexthdr", test->hook(),
        bft::Ethernet() /
            bft::IPv6 {.saddr = "2001:db8::1", .daddr = "2001:db8::2"} /
            bft::TCP {.sport = 12345, .dport = 80},
        test->verdictAccept());

    // UDP -> nexthdr=17 -> not eq matches -> DROP
    bft_assert_prog_run(
        "test_ip6_nexthdr", test->hook(),
        bft::Ethernet() /
            bft::IPv6 {.saddr = "2001:db8::1", .daddr = "2001:db8::2"} /
            bft::UDP {.sport = 12345, .dport = 53},
        test->verdictDrop());

    bft_assert_counter_eq("test_ip6_nexthdr", 0, 1, -1);
}

/**
 * Verify ip6.nexthdr in {set} matches packets whose L4 protocol, after the
 * extension headers, is a member of the set and rejects packets with other L4
 * protocols.
 */
static void ip6_nexthdr_in(void **state)
{
    auto *test = static_cast<MatcherTest *>(*state);

    auto set = bf::Set({BF_MATCHER_IP6_NEXTHDR});
    set << std::vector<uint8_t> {6} // TCP
        << std::vector<uint8_t> {17}; // UDP

    BFT_CHAIN_SET(bf::Chain("test_ip6_nexthdr", test->hook(), BF_VERDICT_ACCEPT)
                  << std::move(set)
                  << bf::Rule(BF_VERDICT_DROP, bf_counter(), {},
                              {bf::Matcher(BF_MATCHER_SET, BF_MATCHER_IN,
                                           {0, 0, 0, 0})}));

    // TCP -> nexthdr=6 in set -> DROP
    bft_assert_prog_run(
        "test_ip6_nexthdr", test->hook(),
        bft::Ethernet() /
            bft::IPv6 {.saddr = "2001:db8::1", .daddr = "2001:db8::2"} /
            bft::TCP {.sport = 12345, .dport = 80},
        test->verdictDrop());

    // UDP -> nexthdr=17 is also in set -> DROP
    bft_assert_prog_run(
        "test_ip6_nexthdr", test->hook(),
        bft::Ethernet() /
            bft::IPv6 {.saddr = "2001:db8::1", .daddr = "2001:db8::2"} /
            bft::UDP {.sport = 12345, .dport = 53},
        test->verdictDrop());

    // ICMPv6 -> nexthdr=58 not in set -> ACCEPT
    bft_assert_prog_run(
        "test_ip6_nexthdr", test->hook(),
        bft::Ethernet() /
            bft::IPv6 {.saddr = "2001:db8::1", .daddr = "2001:db8::2"} /
            bft::ICMPv6 {.type = 128, .code = 0},
        test->verdictAccept());

    bft_assert_counter_eq("test_ip6_nexthdr", 0, 2, -1);

    /* As with eq, the set is checked against the L4 protocol after the
     * extension headers, with both IPv6 parsers. */
    auto ehSet = bf::Set({BF_MATCHER_IP6_NEXTHDR});
    ehSet << std::vector<uint8_t> {6} // TCP
          << std::vector<uint8_t> {17}; // UDP

    bft_with_ipv6_parsers(
        bf::Chain("test_ip6_nexthdr", test->hook(), BF_VERDICT_ACCEPT)
            << std::move(ehSet)
            << bf::Rule(
                   BF_VERDICT_DROP, bf_counter(), {},
                   {bf::Matcher(BF_MATCHER_SET, BF_MATCHER_IN, {0, 0, 0, 0})}),
        [test]() {
            // TCP after a Destination Options header -> DROP
            bft_assert_prog_run("test_ip6_nexthdr", test->hook(),
                                bft::Ethernet() / bft::IPv6 {} /
                                    bft::IPv6DstOpts {} / bft::TCP {},
                                test->verdictDrop());

            // First fragment of a UDP datagram -> DROP
            bft_assert_prog_run(
                "test_ip6_nexthdr", test->hook(),
                bft::Ethernet() / bft::IPv6 {} / bft::IPv6HopByHop {} /
                    bft::IPv6Fragment {.more = true} / bft::UDP {},
                test->verdictDrop());

            // Non-first fragment of a TCP segment -> DROP
            bft_assert_prog_run("test_ip6_nexthdr", test->hook(),
                                bft::Ethernet() / bft::IPv6 {} /
                                    bft::IPv6Fragment {.offset = 181} /
                                    bft::TCP {},
                                test->verdictDrop());

            // ICMPv6 after a Routing header -> ACCEPT
            bft_assert_prog_run("test_ip6_nexthdr", test->hook(),
                                bft::Ethernet() / bft::IPv6 {} /
                                    bft::IPv6Routing {} / bft::ICMPv6 {},
                                test->verdictAccept());

            bft_assert_counter_eq("test_ip6_nexthdr", 0, 3, -1);
        });

    // Multiple components: the L4 protocol is stored after the address
    auto multiSet = bf::Set({BF_MATCHER_IP6_SADDR, BF_MATCHER_IP6_NEXTHDR});
    auto elem = bft_ipv6_addr("2001:db8::1");
    elem.push_back(6); // TCP
    multiSet << elem;

    BFT_CHAIN_SET(bf::Chain("test_ip6_nexthdr", test->hook(), BF_VERDICT_ACCEPT)
                  << std::move(multiSet)
                  << bf::Rule(BF_VERDICT_DROP, bf_counter(), {},
                              {bf::Matcher(BF_MATCHER_SET, BF_MATCHER_IN,
                                           {0, 0, 0, 0})}));

    // saddr=2001:db8::1, TCP after a Destination Options header -> DROP
    bft_assert_prog_run("test_ip6_nexthdr", test->hook(),
                        bft::Ethernet() / bft::IPv6 {.saddr = "2001:db8::1"} /
                            bft::IPv6DstOpts {} / bft::TCP {},
                        test->verdictDrop());

    // saddr=2001:db8::1, UDP -> ACCEPT
    bft_assert_prog_run("test_ip6_nexthdr", test->hook(),
                        bft::Ethernet() / bft::IPv6 {.saddr = "2001:db8::1"} /
                            bft::UDP {},
                        test->verdictAccept());

    // saddr=2001:db8::3, TCP -> ACCEPT
    bft_assert_prog_run("test_ip6_nexthdr", test->hook(),
                        bft::Ethernet() / bft::IPv6 {.saddr = "2001:db8::3"} /
                            bft::TCP {},
                        test->verdictAccept());

    bft_assert_counter_eq("test_ip6_nexthdr", 0, 1, -1);
}

int main()
{
    auto suite = MatcherTestsSuite(BF_MATCHER_IP6_NEXTHDR);

    suite << MatcherTest(BF_MATCHER_IP6_NEXTHDR, BF_MATCHER_EQ, ip6_nexthdr_eq);
    suite << MatcherTest(BF_MATCHER_IP6_NEXTHDR, BF_MATCHER_IN, ip6_nexthdr_in);

    return suite.run();
}
