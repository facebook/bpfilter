# SPDX-License-Identifier: GPL-2.0
# Copyright (c) 2023 Meta Platforms, Inc. and affiliates.

"""End-to-end tests for bpfilter.

This test suite is in very early stages of development. It is not meant to be
run as part of the CI pipeline, but rather as a manual test suite.
"""

from bpftest import BpfilterEndToEndTest
import unittest


class IptablesTests(BpfilterEndToEndTest):
    def test_icmpBlock(self) -> None:
        icmp = self.network.get_icmp(self.dev1, self.dev2)

        # Drop ICMP packets coming to dev2
        self.iptables.run(f"-A INPUT -p icmp -i {self.dev2.name} -j DROP")

        # Send ICMP packet from dev1 to dev2
        self.assertIsNone(self.send(icmp))

        stats = self.iptables.stats()
        self.assertEqual(stats[0]["rules"][0]["pkts"], 1)
        self.assertEqual(stats[0]["rules"][0]["bytes"], len(icmp))


if __name__ == "__main__":
    unittest.main()
