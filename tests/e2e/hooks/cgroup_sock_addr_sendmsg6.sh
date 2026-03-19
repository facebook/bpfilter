#!/usr/bin/env bash

. "$(dirname "$0")"/../e2e_test_util.sh

# Supported matchers
bfcli ruleset set --dry-run --from-str "chain test BF_HOOK_CGROUP_SOCK_ADDR_SENDMSG6 ACCEPT rule meta.l3_proto eq ipv6 counter DROP"
bfcli ruleset set --dry-run --from-str "chain test BF_HOOK_CGROUP_SOCK_ADDR_SENDMSG6 ACCEPT rule meta.l4_proto eq udp counter DROP"
bfcli ruleset set --dry-run --from-str "chain test BF_HOOK_CGROUP_SOCK_ADDR_SENDMSG6 ACCEPT rule meta.probability eq 100% counter DROP"
bfcli ruleset set --dry-run --from-str "chain test BF_HOOK_CGROUP_SOCK_ADDR_SENDMSG6 ACCEPT rule meta.dport eq 443 counter DROP"
bfcli ruleset set --dry-run --from-str "chain test BF_HOOK_CGROUP_SOCK_ADDR_SENDMSG6 ACCEPT rule meta.dport range 0-65535 counter DROP"
bfcli ruleset set --dry-run --from-str "chain test BF_HOOK_CGROUP_SOCK_ADDR_SENDMSG6 ACCEPT rule ip6.saddr eq fd00::2 counter DROP"
bfcli ruleset set --dry-run --from-str "chain test BF_HOOK_CGROUP_SOCK_ADDR_SENDMSG6 ACCEPT rule ip6.snet eq fd00::/64 counter DROP"
bfcli ruleset set --dry-run --from-str "chain test BF_HOOK_CGROUP_SOCK_ADDR_SENDMSG6 ACCEPT rule ip6.daddr eq 2001:db8::1 counter DROP"
bfcli ruleset set --dry-run --from-str "chain test BF_HOOK_CGROUP_SOCK_ADDR_SENDMSG6 ACCEPT rule ip6.dnet eq 2001:db8::/32 counter DROP"
bfcli ruleset set --dry-run --from-str "chain test BF_HOOK_CGROUP_SOCK_ADDR_SENDMSG6 ACCEPT rule udp.dport eq 53 counter DROP"

# Unsupported matchers
(! bfcli ruleset set --dry-run --from-str "chain test BF_HOOK_CGROUP_SOCK_ADDR_SENDMSG6 ACCEPT rule meta.iface eq lo counter DROP")
(! bfcli ruleset set --dry-run --from-str "chain test BF_HOOK_CGROUP_SOCK_ADDR_SENDMSG6 ACCEPT rule meta.sport eq 1234 counter DROP")
(! bfcli ruleset set --dry-run --from-str "chain test BF_HOOK_CGROUP_SOCK_ADDR_SENDMSG6 ACCEPT rule meta.mark eq 0xff counter DROP")
(! bfcli ruleset set --dry-run --from-str "chain test BF_HOOK_CGROUP_SOCK_ADDR_SENDMSG6 ACCEPT rule ip6.nexthdr eq tcp counter DROP")
(! bfcli ruleset set --dry-run --from-str "chain test BF_HOOK_CGROUP_SOCK_ADDR_SENDMSG6 ACCEPT rule ip6.dscp eq 46 counter DROP")
(! bfcli ruleset set --dry-run --from-str "chain test BF_HOOK_CGROUP_SOCK_ADDR_SENDMSG6 ACCEPT rule icmpv6.type eq echo-reply counter DROP")
(! bfcli ruleset set --dry-run --from-str "chain test BF_HOOK_CGROUP_SOCK_ADDR_SENDMSG6 ACCEPT rule icmpv6.code eq 0 counter DROP")
(! bfcli ruleset set --dry-run --from-str "chain test BF_HOOK_CGROUP_SOCK_ADDR_SENDMSG6 ACCEPT rule tcp.sport eq 1234 counter DROP")
(! bfcli ruleset set --dry-run --from-str "chain test BF_HOOK_CGROUP_SOCK_ADDR_SENDMSG6 ACCEPT rule tcp.dport eq 80 counter DROP")
(! bfcli ruleset set --dry-run --from-str "chain test BF_HOOK_CGROUP_SOCK_ADDR_SENDMSG6 ACCEPT rule tcp.flags eq SYN counter DROP")
(! bfcli ruleset set --dry-run --from-str "chain test BF_HOOK_CGROUP_SOCK_ADDR_SENDMSG6 ACCEPT rule udp.sport eq 1234 counter DROP")
(! bfcli ruleset set --dry-run --from-str "chain test BF_HOOK_CGROUP_SOCK_ADDR_SENDMSG6 ACCEPT rule ip4.daddr eq 1.1.1.1 counter DROP")
(! bfcli ruleset set --dry-run --from-str "chain test BF_HOOK_CGROUP_SOCK_ADDR_SENDMSG6 ACCEPT rule ip4.dnet eq 10.0.0.0/8 counter DROP")
(! bfcli ruleset set --dry-run --from-str "chain test BF_HOOK_CGROUP_SOCK_ADDR_SENDMSG6 ACCEPT rule ip4.proto eq tcp counter DROP")
(! bfcli ruleset set --dry-run --from-str "chain test BF_HOOK_CGROUP_SOCK_ADDR_SENDMSG6 ACCEPT rule ip4.saddr eq 10.0.0.1 counter DROP")
(! bfcli ruleset set --dry-run --from-str "chain test BF_HOOK_CGROUP_SOCK_ADDR_SENDMSG6 ACCEPT rule ip4.snet eq 10.0.0.0/8 counter DROP")

make_sandbox

# Add IPv6 addresses on the veth pair
HOST_IP6_ADDR="fd00::1"
NS_IP6_ADDR="fd00::2"
ip addr add ${HOST_IP6_ADDR}/64 dev ${VETH_HOST} nodad
ip netns exec ${NETNS_NAME} ip addr add ${NS_IP6_ADDR}/64 dev ${VETH_NS} nodad

start_bpfilter

CGROUP_PATH=/sys/fs/cgroup/bftest_${_TEST_NAME}
mkdir -p ${CGROUP_PATH}
trap 'ret=$?; rmdir ${CGROUP_PATH} 2>/dev/null; cleanup; exit ${ret}' EXIT

udp6_sendmsg() {
    ${FROM_NS} python3 -c "
import os, socket
with open('${CGROUP_PATH}/cgroup.procs', 'w') as f:
    f.write(str(os.getpid()))
s = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
s.bind(('${NS_IP6_ADDR}', 0))
s.sendto(b'x', ('$1', $2))
s.close()
"
}

# meta.l3_proto
${FROM_NS} bfcli chain set --from-str "chain c BF_HOOK_CGROUP_SOCK_ADDR_SENDMSG6{cgpath=${CGROUP_PATH}} ACCEPT rule meta.l3_proto eq ipv6 DROP"
(! udp6_sendmsg ${HOST_IP6_ADDR} 9990)
${FROM_NS} bfcli ruleset flush

# meta.l4_proto
${FROM_NS} bfcli chain set --from-str "chain c BF_HOOK_CGROUP_SOCK_ADDR_SENDMSG6{cgpath=${CGROUP_PATH}} ACCEPT rule meta.l4_proto eq udp DROP"
(! udp6_sendmsg ${HOST_IP6_ADDR} 9990)
${FROM_NS} bfcli ruleset flush

# meta.probability
${FROM_NS} bfcli chain set --from-str "chain c BF_HOOK_CGROUP_SOCK_ADDR_SENDMSG6{cgpath=${CGROUP_PATH}} ACCEPT rule meta.probability eq 100% DROP"
(! udp6_sendmsg ${HOST_IP6_ADDR} 9990)
${FROM_NS} bfcli ruleset flush

# meta.dport eq
${FROM_NS} bfcli chain set --from-str "chain c BF_HOOK_CGROUP_SOCK_ADDR_SENDMSG6{cgpath=${CGROUP_PATH}} ACCEPT rule meta.dport eq 9990 DROP"
(! udp6_sendmsg ${HOST_IP6_ADDR} 9990)
udp6_sendmsg ${HOST_IP6_ADDR} 9991
${FROM_NS} bfcli ruleset flush

# meta.dport range
${FROM_NS} bfcli chain set --from-str "chain c BF_HOOK_CGROUP_SOCK_ADDR_SENDMSG6{cgpath=${CGROUP_PATH}} ACCEPT rule meta.dport range 9990-9995 DROP"
(! udp6_sendmsg ${HOST_IP6_ADDR} 9990)
(! udp6_sendmsg ${HOST_IP6_ADDR} 9995)
udp6_sendmsg ${HOST_IP6_ADDR} 9996
${FROM_NS} bfcli ruleset flush

# ip6.daddr
${FROM_NS} bfcli chain set --from-str "chain c BF_HOOK_CGROUP_SOCK_ADDR_SENDMSG6{cgpath=${CGROUP_PATH}} ACCEPT rule ip6.daddr eq ${HOST_IP6_ADDR} DROP"
(! udp6_sendmsg ${HOST_IP6_ADDR} 9990)
${FROM_NS} bfcli ruleset flush

# ip6.dnet
${FROM_NS} bfcli chain set --from-str "chain c BF_HOOK_CGROUP_SOCK_ADDR_SENDMSG6{cgpath=${CGROUP_PATH}} ACCEPT rule ip6.dnet eq fd00::/64 DROP"
(! udp6_sendmsg ${HOST_IP6_ADDR} 9990)
${FROM_NS} bfcli ruleset flush

# ip6.saddr
${FROM_NS} bfcli chain set --from-str "chain c BF_HOOK_CGROUP_SOCK_ADDR_SENDMSG6{cgpath=${CGROUP_PATH}} ACCEPT rule ip6.saddr eq ${NS_IP6_ADDR} DROP"
(! udp6_sendmsg ${HOST_IP6_ADDR} 9990)
${FROM_NS} bfcli ruleset flush

# ip6.snet
${FROM_NS} bfcli chain set --from-str "chain c BF_HOOK_CGROUP_SOCK_ADDR_SENDMSG6{cgpath=${CGROUP_PATH}} ACCEPT rule ip6.snet eq fd00::/64 DROP"
(! udp6_sendmsg ${HOST_IP6_ADDR} 9990)
${FROM_NS} bfcli ruleset flush

# udp.dport
${FROM_NS} bfcli chain set --from-str "chain c BF_HOOK_CGROUP_SOCK_ADDR_SENDMSG6{cgpath=${CGROUP_PATH}} ACCEPT rule udp.dport eq 9990 DROP"
(! udp6_sendmsg ${HOST_IP6_ADDR} 9990)
udp6_sendmsg ${HOST_IP6_ADDR} 9991
${FROM_NS} bfcli ruleset flush

# Default policy DROP with explicit ACCEPT rule
${FROM_NS} bfcli chain set --from-str "chain c BF_HOOK_CGROUP_SOCK_ADDR_SENDMSG6{cgpath=${CGROUP_PATH}} DROP rule meta.dport eq 9990 ACCEPT"
udp6_sendmsg ${HOST_IP6_ADDR} 9990
(! udp6_sendmsg ${HOST_IP6_ADDR} 9991)
${FROM_NS} bfcli ruleset flush
