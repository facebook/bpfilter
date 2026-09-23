#!/usr/bin/env bash
# Copyright (c) Meta Platforms, Inc. and affiliates.

. "$(dirname "$0")"/../e2e_test_util.sh

# Bare log accepted for sock_addr hooks
${BFCLI} ruleset set --dry-run --from-str "chain test BF_HOOK_CGROUP_SOCK_ADDR_CONNECT4 ACCEPT rule meta.dport eq 9990 log counter DROP"

# Per-field log options rejected for sock_addr hooks
(! ${BFCLI} ruleset set --dry-run --from-str "chain test BF_HOOK_CGROUP_SOCK_ADDR_CONNECT4 ACCEPT rule meta.dport eq 9990 log internet,transport counter DROP")
(! ${BFCLI} ruleset set --dry-run --from-str "chain test BF_HOOK_CGROUP_SOCK_ADDR_CONNECT4 ACCEPT rule meta.dport eq 9990 log link counter DROP")
(! ${BFCLI} ruleset set --dry-run --from-str "chain test BF_HOOK_CGROUP_SOCK_ADDR_CONNECT4 ACCEPT rule meta.dport eq 9990 log link,internet,transport counter DROP")

# Supported matchers
${BFCLI} ruleset set --dry-run --from-str "chain test BF_HOOK_CGROUP_SOCK_ADDR_CONNECT4 ACCEPT rule meta.l3_proto eq ipv4 counter DROP"
${BFCLI} ruleset set --dry-run --from-str "chain test BF_HOOK_CGROUP_SOCK_ADDR_CONNECT4 ACCEPT rule meta.l4_proto eq tcp counter DROP"
${BFCLI} ruleset set --dry-run --from-str "chain test BF_HOOK_CGROUP_SOCK_ADDR_CONNECT4 ACCEPT rule meta.l4_proto not udp counter DROP"
${BFCLI} ruleset set --dry-run --from-str "chain test BF_HOOK_CGROUP_SOCK_ADDR_CONNECT4 ACCEPT rule meta.probability eq 50% counter DROP"
${BFCLI} ruleset set --dry-run --from-str "chain test BF_HOOK_CGROUP_SOCK_ADDR_CONNECT4 ACCEPT rule meta.dport eq 443 counter DROP"
${BFCLI} ruleset set --dry-run --from-str "chain test BF_HOOK_CGROUP_SOCK_ADDR_CONNECT4 ACCEPT rule meta.dport not 80 counter DROP"
${BFCLI} ruleset set --dry-run --from-str "chain test BF_HOOK_CGROUP_SOCK_ADDR_CONNECT4 ACCEPT rule meta.dport range 8000-9000 counter DROP"
${BFCLI} ruleset set --dry-run --from-str "chain test BF_HOOK_CGROUP_SOCK_ADDR_CONNECT4 ACCEPT rule meta.pid eq 1234 counter DROP"
${BFCLI} ruleset set --dry-run --from-str "chain test BF_HOOK_CGROUP_SOCK_ADDR_CONNECT4 ACCEPT rule meta.pid not 1234 counter DROP"
${BFCLI} ruleset set --dry-run --from-str "chain test BF_HOOK_CGROUP_SOCK_ADDR_CONNECT4 ACCEPT rule ip4.daddr eq 1.1.1.1 counter DROP"
${BFCLI} ruleset set --dry-run --from-str "chain test BF_HOOK_CGROUP_SOCK_ADDR_CONNECT4 ACCEPT rule ip4.daddr not 10.0.0.1 counter DROP"
${BFCLI} ruleset set --dry-run --from-str "chain test BF_HOOK_CGROUP_SOCK_ADDR_CONNECT4 ACCEPT rule ip4.dnet eq 192.168.1.0/24 counter DROP"
${BFCLI} ruleset set --dry-run --from-str "chain test BF_HOOK_CGROUP_SOCK_ADDR_CONNECT4 ACCEPT rule ip4.dnet not 10.0.0.0/8 counter DROP"
${BFCLI} ruleset set --dry-run --from-str "chain test BF_HOOK_CGROUP_SOCK_ADDR_CONNECT4 ACCEPT rule ip4.proto eq tcp counter DROP"
${BFCLI} ruleset set --dry-run --from-str "chain test BF_HOOK_CGROUP_SOCK_ADDR_CONNECT4 ACCEPT rule ip4.proto not udp counter DROP"
${BFCLI} ruleset set --dry-run --from-str "chain test BF_HOOK_CGROUP_SOCK_ADDR_CONNECT4 ACCEPT rule tcp.dport eq 443 counter DROP"
${BFCLI} ruleset set --dry-run --from-str "chain test BF_HOOK_CGROUP_SOCK_ADDR_CONNECT4 ACCEPT rule tcp.dport range 1024-65535 counter DROP"
${BFCLI} ruleset set --dry-run --from-str "chain test BF_HOOK_CGROUP_SOCK_ADDR_CONNECT4 ACCEPT rule udp.dport eq 53 counter DROP"
${BFCLI} ruleset set --dry-run --from-str "chain test BF_HOOK_CGROUP_SOCK_ADDR_CONNECT4 ACCEPT rule udp.dport range 1024-65535 counter DROP"

# Unsupported matchers
(! ${BFCLI} ruleset set --dry-run --from-str "chain test BF_HOOK_CGROUP_SOCK_ADDR_CONNECT4 ACCEPT rule meta.iface eq lo counter DROP")
(! ${BFCLI} ruleset set --dry-run --from-str "chain test BF_HOOK_CGROUP_SOCK_ADDR_CONNECT4 ACCEPT rule meta.sport eq 1234 counter DROP")
(! ${BFCLI} ruleset set --dry-run --from-str "chain test BF_HOOK_CGROUP_SOCK_ADDR_CONNECT4 ACCEPT rule meta.mark eq 0xff counter DROP")
(! ${BFCLI} ruleset set --dry-run --from-str "chain test BF_HOOK_CGROUP_SOCK_ADDR_CONNECT4 ACCEPT rule ip4.saddr eq 1.1.1.1 counter DROP")
(! ${BFCLI} ruleset set --dry-run --from-str "chain test BF_HOOK_CGROUP_SOCK_ADDR_CONNECT4 ACCEPT rule ip4.snet eq 10.0.0.0/8 counter DROP")
(! ${BFCLI} ruleset set --dry-run --from-str "chain test BF_HOOK_CGROUP_SOCK_ADDR_CONNECT4 ACCEPT rule ip4.dscp eq 46 counter DROP")
(! ${BFCLI} ruleset set --dry-run --from-str "chain test BF_HOOK_CGROUP_SOCK_ADDR_CONNECT4 ACCEPT rule tcp.sport eq 1234 counter DROP")
(! ${BFCLI} ruleset set --dry-run --from-str "chain test BF_HOOK_CGROUP_SOCK_ADDR_CONNECT4 ACCEPT rule tcp.flags eq SYN counter DROP")
(! ${BFCLI} ruleset set --dry-run --from-str "chain test BF_HOOK_CGROUP_SOCK_ADDR_CONNECT4 ACCEPT rule udp.sport eq 1234 counter DROP")
(! ${BFCLI} ruleset set --dry-run --from-str "chain test BF_HOOK_CGROUP_SOCK_ADDR_CONNECT4 ACCEPT rule icmp.type eq echo-request counter DROP")
(! ${BFCLI} ruleset set --dry-run --from-str "chain test BF_HOOK_CGROUP_SOCK_ADDR_CONNECT4 ACCEPT rule icmp.code eq 0 counter DROP")
(! ${BFCLI} ruleset set --dry-run --from-str "chain test BF_HOOK_CGROUP_SOCK_ADDR_CONNECT4 ACCEPT rule ip6.daddr eq ::1 counter DROP")
(! ${BFCLI} ruleset set --dry-run --from-str "chain test BF_HOOK_CGROUP_SOCK_ADDR_CONNECT4 ACCEPT rule ip6.dnet eq 2001:db8::/32 counter DROP")

# Supported sets
${BFCLI} ruleset set --dry-run --from-str "chain test BF_HOOK_CGROUP_SOCK_ADDR_CONNECT4 ACCEPT rule (ip4.daddr) in { 1.1.1.1; 2.2.2.2 } counter DROP"
${BFCLI} ruleset set --dry-run --from-str "chain test BF_HOOK_CGROUP_SOCK_ADDR_CONNECT4 ACCEPT rule (ip4.dnet) in { 192.168.1.0/24; 10.0.0.0/8 } counter DROP"
${BFCLI} ruleset set --dry-run --from-str "chain test BF_HOOK_CGROUP_SOCK_ADDR_CONNECT4 ACCEPT rule (tcp.dport) in { 80; 443 } counter DROP"
${BFCLI} ruleset set --dry-run --from-str "chain test BF_HOOK_CGROUP_SOCK_ADDR_CONNECT4 ACCEPT rule (ip4.daddr, tcp.dport) in { 1.1.1.1, 80; 2.2.2.2, 443 } counter DROP"
${BFCLI} ruleset set --dry-run --from-str "chain test BF_HOOK_CGROUP_SOCK_ADDR_CONNECT4 ACCEPT rule (meta.dport) in { 80; 443 } counter DROP"
${BFCLI} ruleset set --dry-run --from-str "chain test BF_HOOK_CGROUP_SOCK_ADDR_CONNECT4 ACCEPT rule (ip4.daddr, meta.dport) in { 1.1.1.1, 80; 2.2.2.2, 443 } counter DROP"
${BFCLI} ruleset set --dry-run --from-str "chain test BF_HOOK_CGROUP_SOCK_ADDR_CONNECT4 ACCEPT rule (meta.pid) in { 1; 1234 } counter DROP"
${BFCLI} ruleset set --dry-run --from-str "chain test BF_HOOK_CGROUP_SOCK_ADDR_CONNECT4 ACCEPT rule (ip4.daddr, meta.pid) in { 1.1.1.1, 1; 2.2.2.2, 1234 } counter DROP"

# Unsupported set components
(! ${BFCLI} ruleset set --dry-run --from-str "chain test BF_HOOK_CGROUP_SOCK_ADDR_CONNECT4 ACCEPT rule (ip4.saddr) in { 1.1.1.1 } counter DROP")
(! ${BFCLI} ruleset set --dry-run --from-str "chain test BF_HOOK_CGROUP_SOCK_ADDR_CONNECT4 ACCEPT rule (meta.sport) in { 80 } counter DROP")
(! ${BFCLI} ruleset set --dry-run --from-str "chain test BF_HOOK_CGROUP_SOCK_ADDR_CONNECT4 ACCEPT rule (tcp.sport) in { 80 } counter DROP")

make_sandbox

CGROUP_PATH=/sys/fs/cgroup/bftest_${_TEST_NAME}
mkdir -p ${CGROUP_PATH}
trap 'ret=$?; rmdir ${CGROUP_PATH} 2>/dev/null; cleanup; exit ${ret}' EXIT

tcp4_connect() {
    ${FROM_NS} bash -c "echo \$\$ > ${CGROUP_PATH}/cgroup.procs && echo > /dev/tcp/$1/$2" 2>/dev/null
}

udp4_connect() {
    ${FROM_NS} bash -c "echo \$\$ > ${CGROUP_PATH}/cgroup.procs && echo > /dev/udp/$1/$2" 2>/dev/null
}

# Load the chain $1 from the connecting process, with "$$" replaced by its PID
udp4_connect_self() {
    ${FROM_NS} bash -c "echo \$\$ > ${CGROUP_PATH}/cgroup.procs && ${BFCLI} chain set --from-str \"$1\" && echo 2>/dev/null > /dev/udp/$2/$3"
}

# meta.l3_proto
${FROM_NS} ${BFCLI} chain set --from-str "chain c BF_HOOK_CGROUP_SOCK_ADDR_CONNECT4{cgpath=${CGROUP_PATH}} ACCEPT rule meta.l3_proto eq ipv4 log counter DROP"
(! tcp4_connect ${HOST_IP_ADDR} 9990)
test "$(get_counter c 0)" = "1"

# meta.l4_proto
${FROM_NS} ${BFCLI} chain set --from-str "chain c BF_HOOK_CGROUP_SOCK_ADDR_CONNECT4{cgpath=${CGROUP_PATH}} ACCEPT rule meta.l4_proto eq tcp counter DROP"
(! tcp4_connect ${HOST_IP_ADDR} 9990)
udp4_connect ${HOST_IP_ADDR} 9990
test "$(get_counter c 0)" = "1"

# meta.probability
${FROM_NS} ${BFCLI} chain set --from-str "chain c BF_HOOK_CGROUP_SOCK_ADDR_CONNECT4{cgpath=${CGROUP_PATH}} ACCEPT rule meta.probability eq 100% counter DROP"
(! tcp4_connect ${HOST_IP_ADDR} 9990)
test "$(get_counter c 0)" = "1"

# meta.dport eq
${FROM_NS} ${BFCLI} chain set --from-str "chain c BF_HOOK_CGROUP_SOCK_ADDR_CONNECT4{cgpath=${CGROUP_PATH}} ACCEPT rule meta.dport eq 9990 counter DROP"
(! udp4_connect ${HOST_IP_ADDR} 9990)
udp4_connect ${HOST_IP_ADDR} 9991
test "$(get_counter c 0)" = "1"

# meta.dport range
${FROM_NS} ${BFCLI} chain set --from-str "chain c BF_HOOK_CGROUP_SOCK_ADDR_CONNECT4{cgpath=${CGROUP_PATH}} ACCEPT rule meta.dport range 9990-9995 counter DROP"
(! udp4_connect ${HOST_IP_ADDR} 9990)
(! udp4_connect ${HOST_IP_ADDR} 9995)
udp4_connect ${HOST_IP_ADDR} 9996
test "$(get_counter c 0)" = "2"

# meta.pid eq: PID 1 never runs in the test cgroup
${FROM_NS} ${BFCLI} chain set --from-str "chain c BF_HOOK_CGROUP_SOCK_ADDR_CONNECT4{cgpath=${CGROUP_PATH}} ACCEPT rule meta.pid eq 1 counter DROP"
udp4_connect ${HOST_IP_ADDR} 9990
test "$(get_counter c 0)" = "0"

# meta.pid not
${FROM_NS} ${BFCLI} chain set --from-str "chain c BF_HOOK_CGROUP_SOCK_ADDR_CONNECT4{cgpath=${CGROUP_PATH}} ACCEPT rule meta.pid not 1 counter DROP"
(! udp4_connect ${HOST_IP_ADDR} 9990)
test "$(get_counter c 0)" = "1"

# ip4.daddr
${FROM_NS} ${BFCLI} chain set --from-str "chain c BF_HOOK_CGROUP_SOCK_ADDR_CONNECT4{cgpath=${CGROUP_PATH}} ACCEPT rule ip4.daddr eq ${HOST_IP_ADDR} counter DROP"
(! tcp4_connect ${HOST_IP_ADDR} 9990)
test "$(get_counter c 0)" = "1"

# ip4.dnet
${FROM_NS} ${BFCLI} chain set --from-str "chain c BF_HOOK_CGROUP_SOCK_ADDR_CONNECT4{cgpath=${CGROUP_PATH}} ACCEPT rule ip4.dnet eq 10.0.0.0/8 counter DROP"
(! tcp4_connect ${HOST_IP_ADDR} 9990)
test "$(get_counter c 0)" = "1"

# ip4.proto
${FROM_NS} ${BFCLI} chain set --from-str "chain c BF_HOOK_CGROUP_SOCK_ADDR_CONNECT4{cgpath=${CGROUP_PATH}} ACCEPT rule ip4.proto eq tcp counter DROP"
(! tcp4_connect ${HOST_IP_ADDR} 9990)
udp4_connect ${HOST_IP_ADDR} 9990
test "$(get_counter c 0)" = "1"

# tcp.dport
${FROM_NS} ${BFCLI} chain set --from-str "chain c BF_HOOK_CGROUP_SOCK_ADDR_CONNECT4{cgpath=${CGROUP_PATH}} ACCEPT rule tcp.dport eq 9990 counter DROP"
(! tcp4_connect ${HOST_IP_ADDR} 9990)
udp4_connect ${HOST_IP_ADDR} 9990
test "$(get_counter c 0)" = "1"

# udp.dport
${FROM_NS} ${BFCLI} chain set --from-str "chain c BF_HOOK_CGROUP_SOCK_ADDR_CONNECT4{cgpath=${CGROUP_PATH}} ACCEPT rule udp.dport eq 9990 counter DROP"
(! udp4_connect ${HOST_IP_ADDR} 9990)
udp4_connect ${HOST_IP_ADDR} 9991
test "$(get_counter c 0)" = "1"

# Default policy DROP with explicit ACCEPT rule
${FROM_NS} ${BFCLI} chain set --from-str "chain c BF_HOOK_CGROUP_SOCK_ADDR_CONNECT4{cgpath=${CGROUP_PATH}} DROP rule meta.dport eq 9990 counter ACCEPT"
udp4_connect ${HOST_IP_ADDR} 9990
(! udp4_connect ${HOST_IP_ADDR} 9991)
test "$(get_counter c 0)" = "1"

# ip4.daddr hash set
${FROM_NS} ${BFCLI} chain set --from-str "chain c BF_HOOK_CGROUP_SOCK_ADDR_CONNECT4{cgpath=${CGROUP_PATH}} ACCEPT rule (ip4.daddr) in { ${HOST_IP_ADDR} } counter DROP"
(! udp4_connect ${HOST_IP_ADDR} 9990)
test "$(get_counter c 0)" = "1"

# ip4.dnet trie set
${FROM_NS} ${BFCLI} chain set --from-str "chain c BF_HOOK_CGROUP_SOCK_ADDR_CONNECT4{cgpath=${CGROUP_PATH}} ACCEPT rule (ip4.dnet) in { 10.0.0.0/8 } counter DROP"
(! udp4_connect ${HOST_IP_ADDR} 9990)
test "$(get_counter c 0)" = "1"

# ip4.proto hash set
${FROM_NS} ${BFCLI} chain set --from-str "chain c BF_HOOK_CGROUP_SOCK_ADDR_CONNECT4{cgpath=${CGROUP_PATH}} ACCEPT rule (ip4.proto) in { tcp } counter DROP"
(! tcp4_connect ${HOST_IP_ADDR} 9990)
udp4_connect ${HOST_IP_ADDR} 9990
test "$(get_counter c 0)" = "1"

# (ip4.daddr, udp.dport) multi-component hash set
${FROM_NS} ${BFCLI} chain set --from-str "chain c BF_HOOK_CGROUP_SOCK_ADDR_CONNECT4{cgpath=${CGROUP_PATH}} ACCEPT rule (ip4.daddr, udp.dport) in { ${HOST_IP_ADDR}, 9990 } counter DROP"
(! udp4_connect ${HOST_IP_ADDR} 9990)
udp4_connect ${HOST_IP_ADDR} 9991
test "$(get_counter c 0)" = "1"

# (ip4.daddr, meta.dport) multi-component hash set
${FROM_NS} ${BFCLI} chain set --from-str "chain c BF_HOOK_CGROUP_SOCK_ADDR_CONNECT4{cgpath=${CGROUP_PATH}} ACCEPT rule (ip4.daddr, meta.dport) in { ${HOST_IP_ADDR}, 9990 } counter DROP"
(! udp4_connect ${HOST_IP_ADDR} 9990)
udp4_connect ${HOST_IP_ADDR} 9991
test "$(get_counter c 0)" = "1"

# An explicit protocol matcher remains independent
${FROM_NS} ${BFCLI} chain set --from-str "chain c BF_HOOK_CGROUP_SOCK_ADDR_CONNECT4{cgpath=${CGROUP_PATH}} ACCEPT rule meta.l4_proto eq tcp (meta.dport) in { 9990 } counter DROP"
udp4_connect ${HOST_IP_ADDR} 9990
test "$(get_counter c 0)" = "0"

# (ip4.daddr, meta.pid) multi-component hash set
${FROM_NS} ${BFCLI} chain set --from-str "chain c BF_HOOK_CGROUP_SOCK_ADDR_CONNECT4{cgpath=${CGROUP_PATH}} ACCEPT rule (ip4.daddr, meta.pid) in { ${HOST_IP_ADDR}, 1 } counter DROP"
udp4_connect ${HOST_IP_ADDR} 9990
test "$(get_counter c 0)" = "0"

# (meta.dport, meta.pid): meta.pid at a 2-byte offset in the set key
${FROM_NS} ${BFCLI} chain set --from-str "chain c BF_HOOK_CGROUP_SOCK_ADDR_CONNECT4{cgpath=${CGROUP_PATH}} ACCEPT rule (meta.dport, meta.pid) in { 9990, 1 } counter DROP"
udp4_connect ${HOST_IP_ADDR} 9990
test "$(get_counter c 0)" = "0"

# (ip4.proto, meta.pid): meta.pid at a 1-byte offset in the set key
${FROM_NS} ${BFCLI} chain set --from-str "chain c BF_HOOK_CGROUP_SOCK_ADDR_CONNECT4{cgpath=${CGROUP_PATH}} ACCEPT rule (ip4.proto, meta.pid) in { udp, 1 } counter DROP"
udp4_connect ${HOST_IP_ADDR} 9990
test "$(get_counter c 0)" = "0"

# meta.pid matches the PID as seen from the initial PID namespace, a process can
# only match its own PID from there (4026531836 is PROC_PID_INIT_INO).
if [ "$(readlink /proc/self/ns/pid)" = "pid:[4026531836]" ]; then
    # meta.pid eq, with the PID of the connecting process
    (! udp4_connect_self "chain c BF_HOOK_CGROUP_SOCK_ADDR_CONNECT4{cgpath=${CGROUP_PATH}} ACCEPT rule meta.pid eq \$\$ counter DROP" ${HOST_IP_ADDR} 9990)
    udp4_connect ${HOST_IP_ADDR} 9990
    test "$(get_counter c 0)" = "1"

    # (ip4.daddr, meta.pid) multi-component hash set, with the PID of the connecting process
    (! udp4_connect_self "chain c BF_HOOK_CGROUP_SOCK_ADDR_CONNECT4{cgpath=${CGROUP_PATH}} ACCEPT rule (ip4.daddr, meta.pid) in { ${HOST_IP_ADDR}, \$\$ } counter DROP" ${HOST_IP_ADDR} 9990)
    udp4_connect ${HOST_IP_ADDR} 9990
    test "$(get_counter c 0)" = "1"

    # (meta.dport, meta.pid): match on a misaligned meta.pid set key component
    (! udp4_connect_self "chain c BF_HOOK_CGROUP_SOCK_ADDR_CONNECT4{cgpath=${CGROUP_PATH}} ACCEPT rule (meta.dport, meta.pid) in { 9990, \$\$ } counter DROP" ${HOST_IP_ADDR} 9990)
    udp4_connect ${HOST_IP_ADDR} 9991
    test "$(get_counter c 0)" = "1"

    # (ip4.proto, meta.pid): match on an odd-offset meta.pid set key component
    (! udp4_connect_self "chain c BF_HOOK_CGROUP_SOCK_ADDR_CONNECT4{cgpath=${CGROUP_PATH}} ACCEPT rule (ip4.proto, meta.pid) in { udp, \$\$ } counter DROP" ${HOST_IP_ADDR} 9990)
    udp4_connect ${HOST_IP_ADDR} 9990
    test "$(get_counter c 0)" = "1"
fi
