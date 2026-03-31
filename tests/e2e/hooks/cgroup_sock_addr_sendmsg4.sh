#!/usr/bin/env bash

. "$(dirname "$0")"/../e2e_test_util.sh

# Supported matchers
${BFCLI} ruleset set --dry-run --from-str "chain test BF_HOOK_CGROUP_SOCK_ADDR_SENDMSG4 ACCEPT rule meta.l3_proto eq ipv4 counter DROP"
${BFCLI} ruleset set --dry-run --from-str "chain test BF_HOOK_CGROUP_SOCK_ADDR_SENDMSG4 ACCEPT rule meta.l4_proto eq udp counter DROP"
${BFCLI} ruleset set --dry-run --from-str "chain test BF_HOOK_CGROUP_SOCK_ADDR_SENDMSG4 ACCEPT rule meta.probability eq 50% counter DROP"
${BFCLI} ruleset set --dry-run --from-str "chain test BF_HOOK_CGROUP_SOCK_ADDR_SENDMSG4 ACCEPT rule meta.dport eq 443 counter DROP"
${BFCLI} ruleset set --dry-run --from-str "chain test BF_HOOK_CGROUP_SOCK_ADDR_SENDMSG4 ACCEPT rule meta.dport range 8000-9000 counter DROP"
${BFCLI} ruleset set --dry-run --from-str "chain test BF_HOOK_CGROUP_SOCK_ADDR_SENDMSG4 ACCEPT rule ip4.saddr eq 10.0.0.1 counter DROP"
${BFCLI} ruleset set --dry-run --from-str "chain test BF_HOOK_CGROUP_SOCK_ADDR_SENDMSG4 ACCEPT rule ip4.snet eq 10.0.0.0/8 counter DROP"
${BFCLI} ruleset set --dry-run --from-str "chain test BF_HOOK_CGROUP_SOCK_ADDR_SENDMSG4 ACCEPT rule ip4.daddr eq 1.1.1.1 counter DROP"
${BFCLI} ruleset set --dry-run --from-str "chain test BF_HOOK_CGROUP_SOCK_ADDR_SENDMSG4 ACCEPT rule ip4.dnet eq 192.168.1.0/24 counter DROP"
${BFCLI} ruleset set --dry-run --from-str "chain test BF_HOOK_CGROUP_SOCK_ADDR_SENDMSG4 ACCEPT rule ip4.proto eq udp counter DROP"
${BFCLI} ruleset set --dry-run --from-str "chain test BF_HOOK_CGROUP_SOCK_ADDR_SENDMSG4 ACCEPT rule udp.dport eq 53 counter DROP"
${BFCLI} ruleset set --dry-run --from-str "chain test BF_HOOK_CGROUP_SOCK_ADDR_SENDMSG4 ACCEPT rule udp.dport range 1024-65535 counter DROP"

# Unsupported matchers
(! ${BFCLI} ruleset set --dry-run --from-str "chain test BF_HOOK_CGROUP_SOCK_ADDR_SENDMSG4 ACCEPT rule meta.iface eq lo counter DROP")
(! ${BFCLI} ruleset set --dry-run --from-str "chain test BF_HOOK_CGROUP_SOCK_ADDR_SENDMSG4 ACCEPT rule meta.sport eq 1234 counter DROP")
(! ${BFCLI} ruleset set --dry-run --from-str "chain test BF_HOOK_CGROUP_SOCK_ADDR_SENDMSG4 ACCEPT rule meta.mark eq 0xff counter DROP")
(! ${BFCLI} ruleset set --dry-run --from-str "chain test BF_HOOK_CGROUP_SOCK_ADDR_SENDMSG4 ACCEPT rule ip4.dscp eq 46 counter DROP")
(! ${BFCLI} ruleset set --dry-run --from-str "chain test BF_HOOK_CGROUP_SOCK_ADDR_SENDMSG4 ACCEPT rule tcp.sport eq 1234 counter DROP")
(! ${BFCLI} ruleset set --dry-run --from-str "chain test BF_HOOK_CGROUP_SOCK_ADDR_SENDMSG4 ACCEPT rule tcp.dport eq 80 counter DROP")
(! ${BFCLI} ruleset set --dry-run --from-str "chain test BF_HOOK_CGROUP_SOCK_ADDR_SENDMSG4 ACCEPT rule tcp.flags eq SYN counter DROP")
(! ${BFCLI} ruleset set --dry-run --from-str "chain test BF_HOOK_CGROUP_SOCK_ADDR_SENDMSG4 ACCEPT rule udp.sport eq 1234 counter DROP")
(! ${BFCLI} ruleset set --dry-run --from-str "chain test BF_HOOK_CGROUP_SOCK_ADDR_SENDMSG4 ACCEPT rule icmp.type eq echo-request counter DROP")
(! ${BFCLI} ruleset set --dry-run --from-str "chain test BF_HOOK_CGROUP_SOCK_ADDR_SENDMSG4 ACCEPT rule icmp.code eq 0 counter DROP")
(! ${BFCLI} ruleset set --dry-run --from-str "chain test BF_HOOK_CGROUP_SOCK_ADDR_SENDMSG4 ACCEPT rule ip6.daddr eq ::1 counter DROP")
(! ${BFCLI} ruleset set --dry-run --from-str "chain test BF_HOOK_CGROUP_SOCK_ADDR_SENDMSG4 ACCEPT rule ip6.dnet eq 2001:db8::/32 counter DROP")
(! ${BFCLI} ruleset set --dry-run --from-str "chain test BF_HOOK_CGROUP_SOCK_ADDR_SENDMSG4 ACCEPT rule ip6.saddr eq ::1 counter DROP")
(! ${BFCLI} ruleset set --dry-run --from-str "chain test BF_HOOK_CGROUP_SOCK_ADDR_SENDMSG4 ACCEPT rule ip6.snet eq 2001:db8::/32 counter DROP")

# Supported sets
${BFCLI} ruleset set --dry-run --from-str "chain test BF_HOOK_CGROUP_SOCK_ADDR_SENDMSG4 ACCEPT rule (ip4.daddr) in { 1.1.1.1; 2.2.2.2 } counter DROP"
${BFCLI} ruleset set --dry-run --from-str "chain test BF_HOOK_CGROUP_SOCK_ADDR_SENDMSG4 ACCEPT rule (ip4.dnet) in { 10.0.0.0/8 } counter DROP"
${BFCLI} ruleset set --dry-run --from-str "chain test BF_HOOK_CGROUP_SOCK_ADDR_SENDMSG4 ACCEPT rule (ip4.saddr) in { 10.0.0.1 } counter DROP"
${BFCLI} ruleset set --dry-run --from-str "chain test BF_HOOK_CGROUP_SOCK_ADDR_SENDMSG4 ACCEPT rule (ip4.snet) in { 10.0.0.0/8 } counter DROP"
${BFCLI} ruleset set --dry-run --from-str "chain test BF_HOOK_CGROUP_SOCK_ADDR_SENDMSG4 ACCEPT rule (udp.dport) in { 53; 443 } counter DROP"

# Unsupported set components
(! ${BFCLI} ruleset set --dry-run --from-str "chain test BF_HOOK_CGROUP_SOCK_ADDR_SENDMSG4 ACCEPT rule (tcp.dport) in { 80 } counter DROP")
(! ${BFCLI} ruleset set --dry-run --from-str "chain test BF_HOOK_CGROUP_SOCK_ADDR_SENDMSG4 ACCEPT rule (tcp.sport) in { 80 } counter DROP")

make_sandbox

CGROUP_PATH=/sys/fs/cgroup/bftest_${_TEST_NAME}
mkdir -p ${CGROUP_PATH}
trap 'ret=$?; rmdir ${CGROUP_PATH} 2>/dev/null; cleanup; exit ${ret}' EXIT

udp4_sendmsg() {
    ${FROM_NS} python3 -c "
import os, socket
with open('${CGROUP_PATH}/cgroup.procs', 'w') as f:
    f.write(str(os.getpid()))
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(('${NS_IP_ADDR}', 0))
s.sendto(b'x', ('$1', $2))
s.close()
"
}

get_counter() {
    ${FROM_NS} bpftool map dump pinned ${WORKDIR}/bpf/bpfilter/$1/bf_cmap | jq ".[$2].value.count"
}

# meta.l3_proto
${FROM_NS} ${BFCLI} chain set --from-str "chain c BF_HOOK_CGROUP_SOCK_ADDR_SENDMSG4{cgpath=${CGROUP_PATH}} ACCEPT rule meta.l3_proto eq ipv4 counter DROP"
(! udp4_sendmsg ${HOST_IP_ADDR} 9990)
test "$(get_counter c 0)" = "1"
${FROM_NS} ${BFCLI} ruleset flush

# meta.l4_proto
${FROM_NS} ${BFCLI} chain set --from-str "chain c BF_HOOK_CGROUP_SOCK_ADDR_SENDMSG4{cgpath=${CGROUP_PATH}} ACCEPT rule meta.l4_proto eq udp counter DROP"
(! udp4_sendmsg ${HOST_IP_ADDR} 9990)
test "$(get_counter c 0)" = "1"
${FROM_NS} ${BFCLI} ruleset flush

# meta.probability
${FROM_NS} ${BFCLI} chain set --from-str "chain c BF_HOOK_CGROUP_SOCK_ADDR_SENDMSG4{cgpath=${CGROUP_PATH}} ACCEPT rule meta.probability eq 100% counter DROP"
(! udp4_sendmsg ${HOST_IP_ADDR} 9990)
test "$(get_counter c 0)" = "1"
${FROM_NS} ${BFCLI} ruleset flush

# meta.dport eq
${FROM_NS} ${BFCLI} chain set --from-str "chain c BF_HOOK_CGROUP_SOCK_ADDR_SENDMSG4{cgpath=${CGROUP_PATH}} ACCEPT rule meta.dport eq 9990 counter DROP"
(! udp4_sendmsg ${HOST_IP_ADDR} 9990)
udp4_sendmsg ${HOST_IP_ADDR} 9991
test "$(get_counter c 0)" = "1"
${FROM_NS} ${BFCLI} ruleset flush

# meta.dport range
${FROM_NS} ${BFCLI} chain set --from-str "chain c BF_HOOK_CGROUP_SOCK_ADDR_SENDMSG4{cgpath=${CGROUP_PATH}} ACCEPT rule meta.dport range 9990-9995 counter DROP"
(! udp4_sendmsg ${HOST_IP_ADDR} 9990)
(! udp4_sendmsg ${HOST_IP_ADDR} 9995)
udp4_sendmsg ${HOST_IP_ADDR} 9996
test "$(get_counter c 0)" = "2"
${FROM_NS} ${BFCLI} ruleset flush

# ip4.daddr
${FROM_NS} ${BFCLI} chain set --from-str "chain c BF_HOOK_CGROUP_SOCK_ADDR_SENDMSG4{cgpath=${CGROUP_PATH}} ACCEPT rule ip4.daddr eq ${HOST_IP_ADDR} counter DROP"
(! udp4_sendmsg ${HOST_IP_ADDR} 9990)
test "$(get_counter c 0)" = "1"
${FROM_NS} ${BFCLI} ruleset flush

# ip4.dnet
${FROM_NS} ${BFCLI} chain set --from-str "chain c BF_HOOK_CGROUP_SOCK_ADDR_SENDMSG4{cgpath=${CGROUP_PATH}} ACCEPT rule ip4.dnet eq 10.0.0.0/8 counter DROP"
(! udp4_sendmsg ${HOST_IP_ADDR} 9990)
test "$(get_counter c 0)" = "1"
${FROM_NS} ${BFCLI} ruleset flush

# ip4.proto
${FROM_NS} ${BFCLI} chain set --from-str "chain c BF_HOOK_CGROUP_SOCK_ADDR_SENDMSG4{cgpath=${CGROUP_PATH}} ACCEPT rule ip4.proto eq udp counter DROP"
(! udp4_sendmsg ${HOST_IP_ADDR} 9990)
test "$(get_counter c 0)" = "1"
${FROM_NS} ${BFCLI} ruleset flush

# ip4.saddr
${FROM_NS} ${BFCLI} chain set --from-str "chain c BF_HOOK_CGROUP_SOCK_ADDR_SENDMSG4{cgpath=${CGROUP_PATH}} ACCEPT rule ip4.saddr eq ${NS_IP_ADDR} counter DROP"
(! udp4_sendmsg ${HOST_IP_ADDR} 9990)
test "$(get_counter c 0)" = "1"
${FROM_NS} ${BFCLI} ruleset flush

# ip4.snet
${FROM_NS} ${BFCLI} chain set --from-str "chain c BF_HOOK_CGROUP_SOCK_ADDR_SENDMSG4{cgpath=${CGROUP_PATH}} ACCEPT rule ip4.snet eq 10.0.0.0/8 counter DROP"
(! udp4_sendmsg ${HOST_IP_ADDR} 9990)
test "$(get_counter c 0)" = "1"
${FROM_NS} ${BFCLI} ruleset flush

# udp.dport
${FROM_NS} ${BFCLI} chain set --from-str "chain c BF_HOOK_CGROUP_SOCK_ADDR_SENDMSG4{cgpath=${CGROUP_PATH}} ACCEPT rule udp.dport eq 9990 counter DROP"
(! udp4_sendmsg ${HOST_IP_ADDR} 9990)
udp4_sendmsg ${HOST_IP_ADDR} 9991
test "$(get_counter c 0)" = "1"
${FROM_NS} ${BFCLI} ruleset flush

# Default policy DROP with explicit ACCEPT rule
${FROM_NS} ${BFCLI} chain set --from-str "chain c BF_HOOK_CGROUP_SOCK_ADDR_SENDMSG4{cgpath=${CGROUP_PATH}} DROP rule meta.dport eq 9990 counter ACCEPT"
udp4_sendmsg ${HOST_IP_ADDR} 9990
(! udp4_sendmsg ${HOST_IP_ADDR} 9991)
test "$(get_counter c 0)" = "1"
${FROM_NS} ${BFCLI} ruleset flush

# ip4.daddr hash set
${FROM_NS} ${BFCLI} chain set --from-str "chain c BF_HOOK_CGROUP_SOCK_ADDR_SENDMSG4{cgpath=${CGROUP_PATH}} ACCEPT rule (ip4.daddr) in { ${HOST_IP_ADDR} } counter DROP"
(! udp4_sendmsg ${HOST_IP_ADDR} 9990)
test "$(get_counter c 0)" = "1"
${FROM_NS} ${BFCLI} ruleset flush

# ip4.dnet trie set
${FROM_NS} ${BFCLI} chain set --from-str "chain c BF_HOOK_CGROUP_SOCK_ADDR_SENDMSG4{cgpath=${CGROUP_PATH}} ACCEPT rule (ip4.dnet) in { 10.0.0.0/8 } counter DROP"
(! udp4_sendmsg ${HOST_IP_ADDR} 9990)
test "$(get_counter c 0)" = "1"
${FROM_NS} ${BFCLI} ruleset flush

# (ip4.saddr, udp.dport) multi-component hash set
${FROM_NS} ${BFCLI} chain set --from-str "chain c BF_HOOK_CGROUP_SOCK_ADDR_SENDMSG4{cgpath=${CGROUP_PATH}} ACCEPT rule (ip4.saddr, udp.dport) in { ${NS_IP_ADDR}, 9990 } counter DROP"
(! udp4_sendmsg ${HOST_IP_ADDR} 9990)
udp4_sendmsg ${HOST_IP_ADDR} 9991
test "$(get_counter c 0)" = "1"
${FROM_NS} ${BFCLI} ruleset flush
