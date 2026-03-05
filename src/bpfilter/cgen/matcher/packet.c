/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 */

#include "cgen/matcher/packet.h"

#include <errno.h>

#include <bpfilter/helper.h>
#include <bpfilter/logger.h>
#include <bpfilter/matcher.h>

#include "cgen/matcher/icmp.h"
#include "cgen/matcher/ip4.h"
#include "cgen/matcher/ip6.h"
#include "cgen/matcher/meta.h"
#include "cgen/matcher/set.h"
#include "cgen/matcher/tcp.h"
#include "cgen/matcher/udp.h"
#include "cgen/program.h"

int bf_matcher_generate_packet(struct bf_program *program,
                               const struct bf_matcher *matcher)
{
    assert(program);
    assert(matcher);

    switch (bf_matcher_get_type(matcher)) {
    case BF_MATCHER_META_IFACE:
    case BF_MATCHER_META_L3_PROTO:
    case BF_MATCHER_META_L4_PROTO:
    case BF_MATCHER_META_PROBABILITY:
    case BF_MATCHER_META_SPORT:
    case BF_MATCHER_META_DPORT:
    case BF_MATCHER_META_FLOW_PROBABILITY:
        return bf_matcher_generate_meta(program, matcher);
    case BF_MATCHER_META_MARK:
    case BF_MATCHER_META_FLOW_HASH:
        return bf_err_r(-ENOTSUP,
                        "matcher '%s' is not supported by this flavor",
                        bf_matcher_type_to_str(bf_matcher_get_type(matcher)));
    case BF_MATCHER_IP4_SADDR:
    case BF_MATCHER_IP4_SNET:
    case BF_MATCHER_IP4_DADDR:
    case BF_MATCHER_IP4_DNET:
    case BF_MATCHER_IP4_PROTO:
    case BF_MATCHER_IP4_DSCP:
        return bf_matcher_generate_ip4(program, matcher);
    case BF_MATCHER_IP6_SADDR:
    case BF_MATCHER_IP6_SNET:
    case BF_MATCHER_IP6_DADDR:
    case BF_MATCHER_IP6_DNET:
    case BF_MATCHER_IP6_NEXTHDR:
    case BF_MATCHER_IP6_DSCP:
        return bf_matcher_generate_ip6(program, matcher);
    case BF_MATCHER_TCP_SPORT:
    case BF_MATCHER_TCP_DPORT:
    case BF_MATCHER_TCP_FLAGS:
        return bf_matcher_generate_tcp(program, matcher);
    case BF_MATCHER_UDP_SPORT:
    case BF_MATCHER_UDP_DPORT:
        return bf_matcher_generate_udp(program, matcher);
    case BF_MATCHER_ICMP_TYPE:
    case BF_MATCHER_ICMP_CODE:
    case BF_MATCHER_ICMPV6_TYPE:
    case BF_MATCHER_ICMPV6_CODE:
        return bf_matcher_generate_icmp(program, matcher);
    case BF_MATCHER_SET:
        return bf_matcher_generate_set(program, matcher);
    default:
        return bf_err_r(-EINVAL, "unknown matcher type %d",
                        bf_matcher_get_type(matcher));
    }
}
