# SPDX-License-Identifier: GPL-2.0
# Copyright (c) 2023 Meta Platforms, Inc. and affiliates.

"""End-to-end tests for bpfilter.

This test suite is in very early stages of development. It is not meant to be
run as part of the CI pipeline, but rather as a manual test suite.
"""

import json
import os
import pathlib
import shlex
import shutil
import signal
import subprocess
import time
import unittest
from typing import Any
from scapy.all import srp1, Ether, IP, ICMP


bpfilter_path: pathlib.Path | None = None
iptables_path: pathlib.Path | None = None


def find_bpfilter() -> None:
    global bpfilter_path

    path = shutil.which("bpfilter")
    if path is None:
        raise ValueError("bpfilter not found in $PATH!")

    bpfilter_path = pathlib.Path(path)


def find_iptables() -> None:
    global iptables_path

    path = shutil.which("iptables")
    if path is None:
        raise ValueError("iptables not found in $PATH!")

    iptables_path = pathlib.Path(path)


def run(cmd: str, echo: bool = False, **kwargs) -> None:
    """Run a command.

    Supports all the key-value arguments of `subprocess.run`, except for
    `stdout` and `stderr` which are always set to `subprocess.PIPE`, and `check`
    which is always set to `True`.

    Args:
        cmd (str): The command to run.
        echo (bool, optional): Whether to echo the command. Defaults to False.
    """

    if echo:
        print(f"[.] Running: {cmd}")

    subprocess.run(
        shlex.split(cmd),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=True,
        **kwargs
    )


class Bpfilter:
    def __init__(self) -> None:
        self._process: Any = None

    def run(self) -> None:
        """Run bpfilter.
        """

        self._process = subprocess.Popen(
            [
                str(bpfilter_path),
                "--transient",
                "--verbose",
            ]
        )

        time.sleep(.25)

    def stop(self) -> None:
        self._process.send_signal(signal.SIGTERM)
        self._process.wait()
        self._process = None


class Iptables:
    def run(self, opts: str) -> None:
        run(f"{iptables_path} {opts} --bpf")

    def stats(self) -> dict:
        iptables = subprocess.Popen(
            [
                str(iptables_path),
                "-L",
                "-nv",
                "--bpf"
            ],
            stdout=subprocess.PIPE
        )

        jc = subprocess.check_output(
            [
                "jc",
                "--iptables"
            ],
            stdin=iptables.stdout
        )

        iptables.wait()
        iptables.stdout.close()

        return json.loads(jc.decode('UTF-8'))


class Device:
    """A network device.
    """

    @staticmethod
    def exists(name: str) -> bool:
        """Check if a network device exists.

        Args:
            name (str): The name of the network device.

        Returns:
            bool: True if the network device exists, False otherwise.
        """

        try:
            os.stat(f"/sys/class/net/{name}")
            return True
        except Exception as _:
            return False

    def __init__(self, name: str, addr: str, ip: str) -> None:
        """Initialize a network device.

        Args:
            name (str): The name of the network device.
            addr (str): The MAC address of the network device.
            ip (str): The IP address of the network device.
        """

        self._name = name
        self._addr = addr
        self._ip = ip

    def setup(self) -> None:
        """Setup the network device.
        """

        cmds = [
            f"ip link set dev {self.name} address {self.addr}",
            f"ip addr add {self.ip}/24 dev {self.name}",
            f"ip link set {self.name} up",
            f"sysctl -w net.ipv4.conf.{self.name}.accept_local=1",
            f"sysctl -w net.ipv4.conf.{self.name}.rp_filter=0",
        ]

        for cmd in cmds:
            run(cmd)

    @property
    def name(self) -> str:
        """The name of the network device.

        Returns:
            str: The name of the network device.
        """

        return self._name

    @property
    def addr(self) -> str:
        """The MAC address of the network device.

        Returns:
            str: The MAC address of the network device.
        """

        return self._addr

    @property
    def ip(self) -> str:
        """The IP address of the network device.

        Returns:
            str: The IP address of the network device.
        """

        return self._ip


class Network:
    @staticmethod
    def send(pkt: Any, iface: Device) -> Any:
        """Send a packet.

        Args:
            pkt (Any): The packet to send.

        Returns:
            Any: The response packet.
        """

        return srp1(pkt, iface=iface.name, timeout=1, verbose=False)

    def __init__(self) -> None:
        self._dev1 = Device("bf-veth1", "b6:01:7d:e0:ac:07", "10.0.0.1")
        self._dev2 = Device("bf-veth2", "22:f5:b1:35:9f:b1", "10.0.0.2")

        if Device.exists(self.dev1.name) or Device.exists(self.dev2.name):
            raise ValueError(
                f"Device '{self.dev1.name}' or '{self.dev2.name}' already exists!")

    def setup(self) -> None:
        """Setup the network.
        """

        run("ip link add bf-veth1 type veth peer name bf-veth2")

        self._dev1.setup()
        self._dev2.setup()

        run("sysctl -w net.ipv4.conf.all.rp_filter=0")

    def teardown(self) -> None:
        """Teardown the network.
        """

        run(f"ip link set {self.dev1.name} down")
        run(f"ip link del {self.dev1.name}")

    def get_ether(self, src: Device, dst: Device):
        return Ether(src=src.addr, dst=dst.addr)

    def get_ip(self, src: Device, dst: Device):
        return self.get_ether(src, dst) / IP(src=src.ip, dst=dst.ip)

    def get_icmp(self, src: Device, dst: Device):
        return self.get_ip(src, dst) / ICMP()

    @property
    def dev1(self) -> Device:
        """The first network device.

        Returns:
            Device: The first network device.
        """

        return self._dev1

    @property
    def dev2(self) -> Device:
        """The second network device.

        Returns:
            Device: The second network device.
        """

        return self._dev2


class BpfilterEndToEndTest(unittest.TestCase):
    def __init__(self, *args, **kwargs):
        super(BpfilterEndToEndTest, self).__init__(*args, **kwargs)

        self._network = Network()
        self._bpfilter = Bpfilter()
        self._iptables = Iptables()
        self._dev1 = self.network.dev1
        self._dev2 = self.network.dev2

    def setUp(self) -> None:
        self.network.setup()
        self.bpfilter.run()

    def tearDown(self) -> None:
        self.bpfilter.stop()
        self.network.teardown()

    @property
    def network(self) -> Network:
        """The network.

        Returns:
            Network: The network.
        """

        return self._network

    @property
    def bpfilter(self) -> Bpfilter:
        """The bpfilter.

        Returns:
            Bpfilter: The bpfilter.
        """

        return self._bpfilter

    @property
    def iptables(self) -> Iptables:
        """The iptables.

        Returns:
            Iptables: The iptables.
        """

        return self._iptables

    @property
    def dev1(self) -> Device:
        """The first network device.

        Returns:
            Device: The first network device.
        """

        return self._dev1

    @property
    def dev2(self) -> Device:
        """The second network device.

        Returns:
            Device: The second network device.
        """

        return self._dev2


class IptablesTests(BpfilterEndToEndTest):
    def test_icmpBlock(self) -> None:
        icmp = self.network.get_icmp(self.dev1, self.dev2)

        # Drop ICMP packets coming to dev2
        self.iptables.run(f"-A INPUT -p icmp -i {self.dev2.name} -j DROP")

        # Send ICMP packet from dev1 to dev2
        self.assertIsNone(Network.send(icmp, iface=self.dev1))

        stats = self.iptables.stats()
        self.assertEqual(stats[0]['rules'][0]['pkts'], 1)
        self.assertEqual(stats[0]['rules'][0]['bytes'], len(icmp))


if __name__ == "__main__":
    find_bpfilter()
    find_iptables()

    print(f"Using bpfilter: {bpfilter_path}")
    print(f"Using iptables: {iptables_path}")

    unittest.main()
