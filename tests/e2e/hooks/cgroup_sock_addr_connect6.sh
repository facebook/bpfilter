#!/usr/bin/env bash

. "$(dirname "$0")"/../e2e_test_util.sh

# Supported matchers
${BFCLI} ruleset set --dry-run --from-str "chain test BF_HOOK_CGROUP_SOCK_ADDR_CONNECT6 ACCEPT rule meta.l3_proto eq ipv6 counter DROP"
${BFCLI} ruleset set --dry-run --from-str "chain test BF_HOOK_CGROUP_SOCK_ADDR_CONNECT6 ACCEPT rule meta.l4_proto eq tcp counter DROP"
${BFCLI} ruleset set --dry-run --from-str "chain test BF_HOOK_CGROUP_SOCK_ADDR_CONNECT6 ACCEPT rule meta.probability eq 100% counter DROP"
${BFCLI} ruleset set --dry-run --from-str "chain test BF_HOOK_CGROUP_SOCK_ADDR_CONNECT6 ACCEPT rule meta.dport eq 443 counter DROP"
${BFCLI} ruleset set --dry-run --from-str "chain test BF_HOOK_CGROUP_SOCK_ADDR_CONNECT6 ACCEPT rule meta.dport range 0-65535 counter DROP"
${BFCLI} ruleset set --dry-run --from-str "chain test BF_HOOK_CGROUP_SOCK_ADDR_CONNECT6 ACCEPT rule ip6.daddr eq 2001:db8::1 counter DROP"
${BFCLI} ruleset set --dry-run --from-str "chain test BF_HOOK_CGROUP_SOCK_ADDR_CONNECT6 ACCEPT rule ip6.daddr not ::1 counter DROP"
${BFCLI} ruleset set --dry-run --from-str "chain test BF_HOOK_CGROUP_SOCK_ADDR_CONNECT6 ACCEPT rule ip6.dnet eq 2001:db8::/32 counter DROP"
${BFCLI} ruleset set --dry-run --from-str "chain test BF_HOOK_CGROUP_SOCK_ADDR_CONNECT6 ACCEPT rule ip6.dnet not fd00::/8 counter DROP"
${BFCLI} ruleset set --dry-run --from-str "chain test BF_HOOK_CGROUP_SOCK_ADDR_CONNECT6 ACCEPT rule tcp.dport eq 80 counter DROP"
${BFCLI} ruleset set --dry-run --from-str "chain test BF_HOOK_CGROUP_SOCK_ADDR_CONNECT6 ACCEPT rule udp.dport eq 53 counter DROP"

# Unsupported matchers
(! ${BFCLI} ruleset set --dry-run --from-str "chain test BF_HOOK_CGROUP_SOCK_ADDR_CONNECT6 ACCEPT rule meta.iface eq lo counter DROP")
(! ${BFCLI} ruleset set --dry-run --from-str "chain test BF_HOOK_CGROUP_SOCK_ADDR_CONNECT6 ACCEPT rule meta.sport eq 1234 counter DROP")
(! ${BFCLI} ruleset set --dry-run --from-str "chain test BF_HOOK_CGROUP_SOCK_ADDR_CONNECT6 ACCEPT rule meta.mark eq 0xff counter DROP")
(! ${BFCLI} ruleset set --dry-run --from-str "chain test BF_HOOK_CGROUP_SOCK_ADDR_CONNECT6 ACCEPT rule ip6.saddr eq ::1 counter DROP")
(! ${BFCLI} ruleset set --dry-run --from-str "chain test BF_HOOK_CGROUP_SOCK_ADDR_CONNECT6 ACCEPT rule ip6.snet eq 2001:db8::/32 counter DROP")
(! ${BFCLI} ruleset set --dry-run --from-str "chain test BF_HOOK_CGROUP_SOCK_ADDR_CONNECT6 ACCEPT rule ip6.nexthdr eq tcp counter DROP")
(! ${BFCLI} ruleset set --dry-run --from-str "chain test BF_HOOK_CGROUP_SOCK_ADDR_CONNECT6 ACCEPT rule ip6.dscp eq 46 counter DROP")
(! ${BFCLI} ruleset set --dry-run --from-str "chain test BF_HOOK_CGROUP_SOCK_ADDR_CONNECT6 ACCEPT rule icmpv6.type eq echo-reply counter DROP")
(! ${BFCLI} ruleset set --dry-run --from-str "chain test BF_HOOK_CGROUP_SOCK_ADDR_CONNECT6 ACCEPT rule icmpv6.code eq 0 counter DROP")
(! ${BFCLI} ruleset set --dry-run --from-str "chain test BF_HOOK_CGROUP_SOCK_ADDR_CONNECT6 ACCEPT rule tcp.sport eq 1234 counter DROP")
(! ${BFCLI} ruleset set --dry-run --from-str "chain test BF_HOOK_CGROUP_SOCK_ADDR_CONNECT6 ACCEPT rule tcp.flags eq SYN counter DROP")
(! ${BFCLI} ruleset set --dry-run --from-str "chain test BF_HOOK_CGROUP_SOCK_ADDR_CONNECT6 ACCEPT rule udp.sport eq 1234 counter DROP")
(! ${BFCLI} ruleset set --dry-run --from-str "chain test BF_HOOK_CGROUP_SOCK_ADDR_CONNECT6 ACCEPT rule ip4.daddr eq 1.1.1.1 counter DROP")
(! ${BFCLI} ruleset set --dry-run --from-str "chain test BF_HOOK_CGROUP_SOCK_ADDR_CONNECT6 ACCEPT rule ip4.dnet eq 10.0.0.0/8 counter DROP")
(! ${BFCLI} ruleset set --dry-run --from-str "chain test BF_HOOK_CGROUP_SOCK_ADDR_CONNECT6 ACCEPT rule ip4.proto eq tcp counter DROP")

# Supported sets
${BFCLI} ruleset set --dry-run --from-str "chain test BF_HOOK_CGROUP_SOCK_ADDR_CONNECT6 ACCEPT rule (ip6.daddr) in { ::1; ::2 } counter DROP"
${BFCLI} ruleset set --dry-run --from-str "chain test BF_HOOK_CGROUP_SOCK_ADDR_CONNECT6 ACCEPT rule (ip6.dnet) in { 2001:db8::/32; fd00::/8 } counter DROP"
${BFCLI} ruleset set --dry-run --from-str "chain test BF_HOOK_CGROUP_SOCK_ADDR_CONNECT6 ACCEPT rule (tcp.dport) in { 80; 443 } counter DROP"

# Unsupported set components
(! ${BFCLI} ruleset set --dry-run --from-str "chain test BF_HOOK_CGROUP_SOCK_ADDR_CONNECT6 ACCEPT rule (ip6.saddr) in { ::1 } counter DROP")
(! ${BFCLI} ruleset set --dry-run --from-str "chain test BF_HOOK_CGROUP_SOCK_ADDR_CONNECT6 ACCEPT rule (tcp.sport) in { 80 } counter DROP")

make_sandbox

# Add IPv6 addresses on the veth pair
HOST_IP6_ADDR="fd00::1"
NS_IP6_ADDR="fd00::2"
ip addr add ${HOST_IP6_ADDR}/64 dev ${VETH_HOST} nodad
ip netns exec ${NETNS_NAME} ip addr add ${NS_IP6_ADDR}/64 dev ${VETH_NS} nodad

CGROUP_PATH=/sys/fs/cgroup/bftest_${_TEST_NAME}
mkdir -p ${CGROUP_PATH}
trap 'ret=$?; rmdir ${CGROUP_PATH} 2>/dev/null; cleanup; exit ${ret}' EXIT

tcp6_connect() {
    ${FROM_NS} python3 -c "
import os, socket
with open('${CGROUP_PATH}/cgroup.procs', 'w') as f:
    f.write(str(os.getpid()))
s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
s.settimeout(1)
s.connect(('$1', $2))
s.close()
"
}

udp6_connect() {
    ${FROM_NS} python3 -c "
import os, socket
with open('${CGROUP_PATH}/cgroup.procs', 'w') as f:
    f.write(str(os.getpid()))
s = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
s.settimeout(1)
s.connect(('$1', $2))
s.send(b'x')
s.close()
"
}

get_counter() {
    ${FROM_NS} bpftool map dump pinned ${WORKDIR}/bpf/bpfilter/$1/bf_cmap | jq ".[$2].value.count"
}

# meta.l3_proto
${FROM_NS} ${BFCLI} chain set --from-str "chain c BF_HOOK_CGROUP_SOCK_ADDR_CONNECT6{cgpath=${CGROUP_PATH}} ACCEPT rule meta.l3_proto eq ipv6 log counter DROP"
(! tcp6_connect ${HOST_IP6_ADDR} 9990)
test "$(get_counter c 0)" = "1"

# meta.l4_proto
${FROM_NS} ${BFCLI} chain set --from-str "chain c BF_HOOK_CGROUP_SOCK_ADDR_CONNECT6{cgpath=${CGROUP_PATH}} ACCEPT rule meta.l4_proto eq tcp counter DROP"
(! tcp6_connect ${HOST_IP6_ADDR} 9990)
udp6_connect ${HOST_IP6_ADDR} 9990
test "$(get_counter c 0)" = "1"

# meta.probability
${FROM_NS} ${BFCLI} chain set --from-str "chain c BF_HOOK_CGROUP_SOCK_ADDR_CONNECT6{cgpath=${CGROUP_PATH}} ACCEPT rule meta.probability eq 100% counter DROP"
(! tcp6_connect ${HOST_IP6_ADDR} 9990)
test "$(get_counter c 0)" = "1"

# meta.dport eq
${FROM_NS} ${BFCLI} chain set --from-str "chain c BF_HOOK_CGROUP_SOCK_ADDR_CONNECT6{cgpath=${CGROUP_PATH}} ACCEPT rule meta.dport eq 9990 counter DROP"
(! udp6_connect ${HOST_IP6_ADDR} 9990)
udp6_connect ${HOST_IP6_ADDR} 9991
test "$(get_counter c 0)" = "1"

# meta.dport range
${FROM_NS} ${BFCLI} chain set --from-str "chain c BF_HOOK_CGROUP_SOCK_ADDR_CONNECT6{cgpath=${CGROUP_PATH}} ACCEPT rule meta.dport range 9990-9995 counter DROP"
(! udp6_connect ${HOST_IP6_ADDR} 9990)
(! udp6_connect ${HOST_IP6_ADDR} 9995)
udp6_connect ${HOST_IP6_ADDR} 9996
test "$(get_counter c 0)" = "2"

# ip6.daddr
${FROM_NS} ${BFCLI} chain set --from-str "chain c BF_HOOK_CGROUP_SOCK_ADDR_CONNECT6{cgpath=${CGROUP_PATH}} ACCEPT rule ip6.daddr eq ${HOST_IP6_ADDR} counter DROP"
(! tcp6_connect ${HOST_IP6_ADDR} 9990)
test "$(get_counter c 0)" = "1"

# ip6.dnet
${FROM_NS} ${BFCLI} chain set --from-str "chain c BF_HOOK_CGROUP_SOCK_ADDR_CONNECT6{cgpath=${CGROUP_PATH}} ACCEPT rule ip6.dnet eq fd00::/64 counter DROP"
(! tcp6_connect ${HOST_IP6_ADDR} 9990)
test "$(get_counter c 0)" = "1"

# tcp.dport
${FROM_NS} ${BFCLI} chain set --from-str "chain c BF_HOOK_CGROUP_SOCK_ADDR_CONNECT6{cgpath=${CGROUP_PATH}} ACCEPT rule tcp.dport eq 9990 counter DROP"
(! tcp6_connect ${HOST_IP6_ADDR} 9990)
udp6_connect ${HOST_IP6_ADDR} 9990
test "$(get_counter c 0)" = "1"

# udp.dport
${FROM_NS} ${BFCLI} chain set --from-str "chain c BF_HOOK_CGROUP_SOCK_ADDR_CONNECT6{cgpath=${CGROUP_PATH}} ACCEPT rule udp.dport eq 9990 counter DROP"
(! udp6_connect ${HOST_IP6_ADDR} 9990)
udp6_connect ${HOST_IP6_ADDR} 9991
test "$(get_counter c 0)" = "1"

# Default policy DROP with explicit ACCEPT rule
${FROM_NS} ${BFCLI} chain set --from-str "chain c BF_HOOK_CGROUP_SOCK_ADDR_CONNECT6{cgpath=${CGROUP_PATH}} DROP rule meta.dport eq 9990 counter ACCEPT"
udp6_connect ${HOST_IP6_ADDR} 9990
(! udp6_connect ${HOST_IP6_ADDR} 9991)
test "$(get_counter c 0)" = "1"

# (ip6.daddr, udp.dport) multi-component hash set
${FROM_NS} ${BFCLI} chain set --from-str "chain c BF_HOOK_CGROUP_SOCK_ADDR_CONNECT6{cgpath=${CGROUP_PATH}} ACCEPT rule (ip6.daddr, udp.dport) in { ${HOST_IP6_ADDR}, 9990 } counter DROP"
(! udp6_connect ${HOST_IP6_ADDR} 9990)
udp6_connect ${HOST_IP6_ADDR} 9991
test "$(get_counter c 0)" = "1"

# ip6.daddr hash set
${FROM_NS} ${BFCLI} chain set --from-str "chain c BF_HOOK_CGROUP_SOCK_ADDR_CONNECT6{cgpath=${CGROUP_PATH}} ACCEPT rule (ip6.daddr) in { ${HOST_IP6_ADDR} } counter DROP"
(! udp6_connect ${HOST_IP6_ADDR} 9990)
test "$(get_counter c 0)" = "1"

# ip6.dnet trie set
${FROM_NS} ${BFCLI} chain set --from-str "chain c BF_HOOK_CGROUP_SOCK_ADDR_CONNECT6{cgpath=${CGROUP_PATH}} ACCEPT rule (ip6.dnet) in { fd00::/64 } counter DROP"
(! udp6_connect ${HOST_IP6_ADDR} 9990)
test "$(get_counter c 0)" = "1"
