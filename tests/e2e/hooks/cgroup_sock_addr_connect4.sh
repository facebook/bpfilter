#!/usr/bin/env bash

. "$(dirname "$0")"/../e2e_test_util.sh

# Supported matchers
bfcli ruleset set --dry-run --from-str "chain test BF_HOOK_CGROUP_SOCK_ADDR_CONNECT4 ACCEPT rule meta.l3_proto eq ipv4 counter DROP"
bfcli ruleset set --dry-run --from-str "chain test BF_HOOK_CGROUP_SOCK_ADDR_CONNECT4 ACCEPT rule meta.l4_proto eq tcp counter DROP"
bfcli ruleset set --dry-run --from-str "chain test BF_HOOK_CGROUP_SOCK_ADDR_CONNECT4 ACCEPT rule meta.l4_proto not udp counter DROP"
bfcli ruleset set --dry-run --from-str "chain test BF_HOOK_CGROUP_SOCK_ADDR_CONNECT4 ACCEPT rule meta.probability eq 50% counter DROP"
bfcli ruleset set --dry-run --from-str "chain test BF_HOOK_CGROUP_SOCK_ADDR_CONNECT4 ACCEPT rule meta.dport eq 443 counter DROP"
bfcli ruleset set --dry-run --from-str "chain test BF_HOOK_CGROUP_SOCK_ADDR_CONNECT4 ACCEPT rule meta.dport not 80 counter DROP"
bfcli ruleset set --dry-run --from-str "chain test BF_HOOK_CGROUP_SOCK_ADDR_CONNECT4 ACCEPT rule meta.dport range 8000-9000 counter DROP"
bfcli ruleset set --dry-run --from-str "chain test BF_HOOK_CGROUP_SOCK_ADDR_CONNECT4 ACCEPT rule ip4.daddr eq 1.1.1.1 counter DROP"
bfcli ruleset set --dry-run --from-str "chain test BF_HOOK_CGROUP_SOCK_ADDR_CONNECT4 ACCEPT rule ip4.daddr not 10.0.0.1 counter DROP"
bfcli ruleset set --dry-run --from-str "chain test BF_HOOK_CGROUP_SOCK_ADDR_CONNECT4 ACCEPT rule ip4.dnet eq 192.168.1.0/24 counter DROP"
bfcli ruleset set --dry-run --from-str "chain test BF_HOOK_CGROUP_SOCK_ADDR_CONNECT4 ACCEPT rule ip4.dnet not 10.0.0.0/8 counter DROP"
bfcli ruleset set --dry-run --from-str "chain test BF_HOOK_CGROUP_SOCK_ADDR_CONNECT4 ACCEPT rule ip4.proto eq tcp counter DROP"
bfcli ruleset set --dry-run --from-str "chain test BF_HOOK_CGROUP_SOCK_ADDR_CONNECT4 ACCEPT rule ip4.proto not udp counter DROP"
bfcli ruleset set --dry-run --from-str "chain test BF_HOOK_CGROUP_SOCK_ADDR_CONNECT4 ACCEPT rule tcp.dport eq 443 counter DROP"
bfcli ruleset set --dry-run --from-str "chain test BF_HOOK_CGROUP_SOCK_ADDR_CONNECT4 ACCEPT rule tcp.dport range 1024-65535 counter DROP"
bfcli ruleset set --dry-run --from-str "chain test BF_HOOK_CGROUP_SOCK_ADDR_CONNECT4 ACCEPT rule udp.dport eq 53 counter DROP"
bfcli ruleset set --dry-run --from-str "chain test BF_HOOK_CGROUP_SOCK_ADDR_CONNECT4 ACCEPT rule udp.dport range 1024-65535 counter DROP"

# Unsupported matchers
(! bfcli ruleset set --dry-run --from-str "chain test BF_HOOK_CGROUP_SOCK_ADDR_CONNECT4 ACCEPT rule meta.iface eq lo counter DROP")
(! bfcli ruleset set --dry-run --from-str "chain test BF_HOOK_CGROUP_SOCK_ADDR_CONNECT4 ACCEPT rule meta.sport eq 1234 counter DROP")
(! bfcli ruleset set --dry-run --from-str "chain test BF_HOOK_CGROUP_SOCK_ADDR_CONNECT4 ACCEPT rule meta.mark eq 0xff counter DROP")
(! bfcli ruleset set --dry-run --from-str "chain test BF_HOOK_CGROUP_SOCK_ADDR_CONNECT4 ACCEPT rule ip4.saddr eq 1.1.1.1 counter DROP")
(! bfcli ruleset set --dry-run --from-str "chain test BF_HOOK_CGROUP_SOCK_ADDR_CONNECT4 ACCEPT rule ip4.snet eq 10.0.0.0/8 counter DROP")
(! bfcli ruleset set --dry-run --from-str "chain test BF_HOOK_CGROUP_SOCK_ADDR_CONNECT4 ACCEPT rule ip4.dscp eq 46 counter DROP")
(! bfcli ruleset set --dry-run --from-str "chain test BF_HOOK_CGROUP_SOCK_ADDR_CONNECT4 ACCEPT rule tcp.sport eq 1234 counter DROP")
(! bfcli ruleset set --dry-run --from-str "chain test BF_HOOK_CGROUP_SOCK_ADDR_CONNECT4 ACCEPT rule tcp.flags eq SYN counter DROP")
(! bfcli ruleset set --dry-run --from-str "chain test BF_HOOK_CGROUP_SOCK_ADDR_CONNECT4 ACCEPT rule udp.sport eq 1234 counter DROP")
(! bfcli ruleset set --dry-run --from-str "chain test BF_HOOK_CGROUP_SOCK_ADDR_CONNECT4 ACCEPT rule icmp.type eq echo-request counter DROP")
(! bfcli ruleset set --dry-run --from-str "chain test BF_HOOK_CGROUP_SOCK_ADDR_CONNECT4 ACCEPT rule icmp.code eq 0 counter DROP")
(! bfcli ruleset set --dry-run --from-str "chain test BF_HOOK_CGROUP_SOCK_ADDR_CONNECT4 ACCEPT rule ip6.daddr eq ::1 counter DROP")
(! bfcli ruleset set --dry-run --from-str "chain test BF_HOOK_CGROUP_SOCK_ADDR_CONNECT4 ACCEPT rule ip6.dnet eq 2001:db8::/32 counter DROP")

make_sandbox
start_bpfilter

CGROUP_PATH=/sys/fs/cgroup/bftest_${_TEST_NAME}
mkdir -p ${CGROUP_PATH}
trap 'ret=$?; rmdir ${CGROUP_PATH} 2>/dev/null; cleanup; exit ${ret}' EXIT

tcp4_connect() {
    ${FROM_NS} bash -c "echo \$\$ > ${CGROUP_PATH}/cgroup.procs && echo > /dev/tcp/$1/$2" 2>/dev/null
}

udp4_connect() {
    ${FROM_NS} bash -c "echo \$\$ > ${CGROUP_PATH}/cgroup.procs && echo > /dev/udp/$1/$2" 2>/dev/null
}

# meta.l3_proto
${FROM_NS} bfcli chain set --from-str "chain c BF_HOOK_CGROUP_SOCK_ADDR_CONNECT4{cgpath=${CGROUP_PATH}} ACCEPT rule meta.l3_proto eq ipv4 DROP"
(! tcp4_connect ${HOST_IP_ADDR} 9990)
${FROM_NS} bfcli ruleset flush

# meta.l4_proto
${FROM_NS} bfcli chain set --from-str "chain c BF_HOOK_CGROUP_SOCK_ADDR_CONNECT4{cgpath=${CGROUP_PATH}} ACCEPT rule meta.l4_proto eq tcp DROP"
(! tcp4_connect ${HOST_IP_ADDR} 9990)
udp4_connect ${HOST_IP_ADDR} 9990
${FROM_NS} bfcli ruleset flush

# meta.probability
${FROM_NS} bfcli chain set --from-str "chain c BF_HOOK_CGROUP_SOCK_ADDR_CONNECT4{cgpath=${CGROUP_PATH}} ACCEPT rule meta.probability eq 100% DROP"
(! tcp4_connect ${HOST_IP_ADDR} 9990)
${FROM_NS} bfcli ruleset flush

# meta.dport eq
${FROM_NS} bfcli chain set --from-str "chain c BF_HOOK_CGROUP_SOCK_ADDR_CONNECT4{cgpath=${CGROUP_PATH}} ACCEPT rule meta.dport eq 9990 DROP"
(! udp4_connect ${HOST_IP_ADDR} 9990)
udp4_connect ${HOST_IP_ADDR} 9991
${FROM_NS} bfcli ruleset flush

# meta.dport range
${FROM_NS} bfcli chain set --from-str "chain c BF_HOOK_CGROUP_SOCK_ADDR_CONNECT4{cgpath=${CGROUP_PATH}} ACCEPT rule meta.dport range 9990-9995 DROP"
(! udp4_connect ${HOST_IP_ADDR} 9990)
(! udp4_connect ${HOST_IP_ADDR} 9995)
udp4_connect ${HOST_IP_ADDR} 9996
${FROM_NS} bfcli ruleset flush

# ip4.daddr
${FROM_NS} bfcli chain set --from-str "chain c BF_HOOK_CGROUP_SOCK_ADDR_CONNECT4{cgpath=${CGROUP_PATH}} ACCEPT rule ip4.daddr eq ${HOST_IP_ADDR} DROP"
(! tcp4_connect ${HOST_IP_ADDR} 9990)
${FROM_NS} bfcli ruleset flush

# ip4.dnet
${FROM_NS} bfcli chain set --from-str "chain c BF_HOOK_CGROUP_SOCK_ADDR_CONNECT4{cgpath=${CGROUP_PATH}} ACCEPT rule ip4.dnet eq 10.0.0.0/8 DROP"
(! tcp4_connect ${HOST_IP_ADDR} 9990)
${FROM_NS} bfcli ruleset flush

# ip4.proto
${FROM_NS} bfcli chain set --from-str "chain c BF_HOOK_CGROUP_SOCK_ADDR_CONNECT4{cgpath=${CGROUP_PATH}} ACCEPT rule ip4.proto eq tcp DROP"
(! tcp4_connect ${HOST_IP_ADDR} 9990)
udp4_connect ${HOST_IP_ADDR} 9990
${FROM_NS} bfcli ruleset flush

# tcp.dport
${FROM_NS} bfcli chain set --from-str "chain c BF_HOOK_CGROUP_SOCK_ADDR_CONNECT4{cgpath=${CGROUP_PATH}} ACCEPT rule tcp.dport eq 9990 DROP"
(! tcp4_connect ${HOST_IP_ADDR} 9990)
udp4_connect ${HOST_IP_ADDR} 9990
${FROM_NS} bfcli ruleset flush

# udp.dport
${FROM_NS} bfcli chain set --from-str "chain c BF_HOOK_CGROUP_SOCK_ADDR_CONNECT4{cgpath=${CGROUP_PATH}} ACCEPT rule udp.dport eq 9990 DROP"
(! udp4_connect ${HOST_IP_ADDR} 9990)
udp4_connect ${HOST_IP_ADDR} 9991
${FROM_NS} bfcli ruleset flush

# Default policy DROP with explicit ACCEPT rule
${FROM_NS} bfcli chain set --from-str "chain c BF_HOOK_CGROUP_SOCK_ADDR_CONNECT4{cgpath=${CGROUP_PATH}} DROP rule meta.dport eq 9990 ACCEPT"
udp4_connect ${HOST_IP_ADDR} 9990
(! udp4_connect ${HOST_IP_ADDR} 9991)
${FROM_NS} bfcli ruleset flush
