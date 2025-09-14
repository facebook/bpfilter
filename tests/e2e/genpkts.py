#!/usr/bin/env python3

import argparse
import pathlib

from scapy.layers.l2 import Ether
from scapy.layers.inet import IP as IPv4
from scapy.layers.inet import TCP, UDP, ICMP
from scapy.layers.inet6 import (
    IPv6,
    ICMPv6EchoRequest,
    IPv6ExtHdrHopByHop,
    IPv6ExtHdrRouting,
)

packets = [
    {
        "name": "pkt_local_ip6_tcp",
        "family": "NFPROTO_IPV6",
        "packet": Ether(src=0x01, dst=0x02)
        / IPv6(src="::1", dst="::2")
        / TCP(sport=31337, dport=31415),
    },
    {
        "name": "pkt_local_ip6_udp",
        "family": "NFPROTO_IPV6",
        "packet": Ether(src=0x01, dst=0x02)
        / IPv6(src="::1", dst="::2")
        / UDP(sport=31337, dport=31415),
    },
    {
        "name": "pkt_local_ip6_icmp",
        "family": "NFPROTO_IPV6",
        "packet": Ether(src=0x01, dst=0x02)
        / IPv6(src="::1", dst="::2")
        / ICMPv6EchoRequest(code=2),
    },
    {
        "name": "pkt_local_ip6_hop",
        "family": "NFPROTO_IPV6",
        "packet": Ether(src=0x01, dst=0x02)
        / IPv6(src="::1", dst="::2")
        / IPv6ExtHdrHopByHop()
        / IPv6ExtHdrRouting()
        / IPv6ExtHdrHopByHop(),
    },
    {
        "name": "pkt_remote_ip6_tcp",
        "family": "NFPROTO_IPV6",
        "packet": Ether(src=0x01, dst=0x02)
        / IPv6(
            src="542c:1a31:f964:946c:5a24:e71e:4d26:b87e",
            dst="5232:185a:52f9:0ab4:8025:7974:2299:eb04",
        )
        / TCP(sport=31337, dport=31415),
    },
    {
        "name": "pkt_remote_ip6_eh",
        "family": "NFPROTO_IPV6",
        "packet": Ether(src=0x01, dst=0x02)
        / IPv6(
            src="542c:1a31:f964:946c:5a24:e71e:4d26:b87e",
            dst="5232:185a:52f9:0ab4:8025:7974:2299:eb04",
        )
        / IPv6ExtHdrHopByHop()
        / IPv6ExtHdrRouting()
        / IPv6ExtHdrHopByHop(),
    },
    {
        "name": "pkt_remote_ip6_eh_tcp",
        "family": "NFPROTO_IPV6",
        "packet": Ether(src=0x01, dst=0x02)
        / IPv6(
            src="542c:1a31:f964:946c:5a24:e71e:4d26:b87e",
            dst="5232:185a:52f9:0ab4:8025:7974:2299:eb04",
        )
        / IPv6ExtHdrHopByHop()
        / IPv6ExtHdrRouting()
        / TCP(sport=31337, dport=31415, flags="SA"),
    },
    {
        "name": "pkt_local_ip4",
        "family": "NFPROTO_IPV4",
        "packet": Ether(src=0x01, dst=0x02)
        / IPv4(src="127.2.10.10", dst="127.2.10.11"),
    },
    {
        "name": "pkt_local_ip4_icmp",
        "family": "NFPROTO_IPV4",
        "packet": Ether(src=0x01, dst=0x02)
        / IPv4(src="127.2.10.10", dst="127.2.10.11")
        / ICMP(type=8, code=2),
    },
]

template = """#pragma once

#include "bpfilter/flavor.h"
#include "harness/prog.h"

#include <linux/netfilter.h>

struct sk_buff;
struct sock;
struct net;
struct net_device;

struct bft_prog_run_args {{
    size_t pkt_len;
    const void *pkt;
    size_t ctx_len;
    union {{
        struct nf_hook_state {{
            uint8_t hook;
            uint8_t pf;
            struct net_device *in;
            struct net_device *out;
            struct sock *sk;
            struct net *net;
            int (*okfn)(struct net *, struct sock *, struct sk_buff *);
        }} nf_ctx;
    }} ctx;
}};

{}
"""

packet_template = """__attribute__((unused)) static const uint8_t _{pkt_name}_raw[] = {{ {pkt_raw} }};
__attribute__((unused)) static const struct bft_prog_run_args {pkt_name}[_BF_FLAVOR_MAX] = {{
    [BF_FLAVOR_TC] = {{
        .pkt_len = {len},
        .pkt = &_{pkt_name}_raw,
    }},
    [BF_FLAVOR_NF] = {{
        .pkt_len = {len},
        .pkt = &_{pkt_name}_raw,
        .ctx_len = sizeof(struct nf_hook_state),
        .ctx = {{
            .nf_ctx = {{
                .hook = NF_INET_FORWARD,
                .pf = {pkt_family},
            }},
        }}
    }},
    [BF_FLAVOR_XDP] = {{
        .pkt_len = {len},
        .pkt = &_{pkt_name}_raw,
    }},
    [BF_FLAVOR_CGROUP] = {{
        .pkt_len = {len},
        .pkt = &_{pkt_name}_raw,
    }},
}};
"""


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--output",
        "-o",
        type=pathlib.Path,
        help="Output file path",
        default="packets.h",
    )
    args = parser.parse_args()

    strs = []
    for packet in packets:
        raw = [f"0x{byte:02x}" for byte in bytes(packet["packet"])]

        strs.append(
            packet_template.format(
                pkt_raw=", ".join(raw),
                pkt_name=packet["name"],
                len=len(raw),
                pkt_family=packet["family"],
            )
        )

    with open(args.output, "w") as output:
        output.write(template.format("\n\n".join(strs)))


if __name__ == "__main__":
    main()
