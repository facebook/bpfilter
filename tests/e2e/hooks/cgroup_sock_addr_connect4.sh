#!/usr/bin/env bash

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

# Unsupported set components
(! ${BFCLI} ruleset set --dry-run --from-str "chain test BF_HOOK_CGROUP_SOCK_ADDR_CONNECT4 ACCEPT rule (ip4.saddr) in { 1.1.1.1 } counter DROP")
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

get_counter() {
    ${FROM_NS} bpftool map dump pinned ${WORKDIR}/bpf/bpfilter/$1/bf_cmap | jq ".[$2].value.count"
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
