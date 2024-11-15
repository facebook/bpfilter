#!/usr/bin/env python3

import argparse
import pathlib

from scapy.layers.l2 import Ether
from scapy.layers.inet6 import IPv6, TCP

packets = [
    {
        "name": "pkt_local_ip6_tcp",
        "packet": Ether(src=0x01, dst=0x02)
        / IPv6(src="::1", dst="::2")
        / TCP(sport=31337, dport=31415),
    },
    {
        "name": "pkt_remote_ip6_tcp",
        "packet": Ether(src=0x01, dst=0x02)
        / IPv6(
            src="542c:1a31:f964:946c:5a24:e71e:4d26:b87e",
            dst="5232:185a:52f9:0ab4:8025:7974:2299:eb04",
        )
        / TCP(sport=31337, dport=31415),
    },
]

template = """#pragma once

#include "harness/prog.h"

{}
"""

packet_template = """__attribute__((unused)) static const uint8_t _{}_data[] = {{ {} }};
__attribute__((unused)) static const struct bf_test_packet _{} = {{
    .len = {},
    .data = &_{}_data,
}};
__attribute__((unused)) static const struct bf_test_packet *{} = &_{};
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
        name = packet["name"]

        strs.append(
            packet_template.format(
                name, ", ".join(raw), name, len(raw), name, name, name
            )
        )

    with open(args.output, "w") as output:
        output.write(template.format("\n\n".join(strs)))


if __name__ == "__main__":
    main()
