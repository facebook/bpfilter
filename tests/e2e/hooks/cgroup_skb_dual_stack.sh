#!/usr/bin/env bash
# Copyright (c) Meta Platforms, Inc. and affiliates.

. "$(dirname "$0")"/../e2e_test_util.sh

make_sandbox

CGROUP_PATH=/sys/fs/cgroup/bftest_${_TEST_NAME}
mkdir -p ${CGROUP_PATH}
trap 'ret=$?; set +e; rmdir ${CGROUP_PATH} 2>/dev/null; cleanup; exit ${ret}' EXIT

# Join the test cgroup, then send one UDP packet to address $2 from a new
# socket of family $1. An AF_INET6 socket has IPV6_V6ONLY turned off, so it
# sends IPv4 packets to ::ffff:a.b.c.d addresses. The 64-byte payload makes the
# packet longer than an IPv6 header, so a program that wrongly reads it as IPv6
# still reaches the rule instead of accepting it early as too short.
udp_send() {
    ${FROM_NS} python3 -c "
import os, socket
with open('${CGROUP_PATH}/cgroup.procs', 'w') as f:
    f.write(str(os.getpid()))
s = socket.socket(socket.$1, socket.SOCK_DGRAM)
if s.family == socket.AF_INET6:
    s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
s.sendto(b'x' * 64, ('$2', 9990))
s.close()
"
}

# Drop and count every IPv4 packet sent to 127.0.0.1
${FROM_NS} ${BFCLI} chain set --from-str "chain c BF_HOOK_CGROUP_SKB_EGRESS{cgpath=${CGROUP_PATH}} ACCEPT rule ip4.daddr eq 127.0.0.1 counter DROP"

# Control: an IPv4 socket sends an IPv4 packet to 127.0.0.1. The rule drops it,
# so sendto() fails with EPERM.
(! udp_send AF_INET 127.0.0.1)
test "$(get_counter c 0)" = "1"

# An IPv6 socket sending to ::ffff:127.0.0.1 also sends an IPv4 packet to
# 127.0.0.1, so the same rule must drop it.
(! udp_send AF_INET6 ::ffff:127.0.0.1)
test "$(get_counter c 0)" = "2"
