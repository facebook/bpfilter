#!/usr/bin/env bash
# Copyright (c) Meta Platforms, Inc. and affiliates.

. "$(dirname "$0")"/../e2e_test_util.sh

make_sandbox

HOST_IP6_ADDR="fd00:${_OCTET2}:${_OCTET3}::1"
NS_IP6_ADDR="fd00:${_OCTET2}:${_OCTET3}::2"

ip -6 addr add ${HOST_IP6_ADDR}/64 dev ${VETH_HOST} nodad
ip netns exec ${NETNS_NAME} ip -6 addr add ${NS_IP6_ADDR}/64 dev ${VETH_NS} nodad

# A 3000 bytes echo request is sent in 3 fragments on the 1500 bytes MTU veth
RULES="rule ip6.nexthdr eq frag counter CONTINUE
       rule icmpv6.type eq echo-request counter CONTINUE"

# Without defrag=, the chain sees every fragment, only the first one has the
# ICMPv6 header
${FROM_NS} ${BFCLI} chain set --from-str "chain nf_frag BF_HOOK_NF_LOCAL_IN{priorities=101-102} ACCEPT ${RULES}"
ping -6 -c 1 -W 1 -s 3000 ${NS_IP6_ADDR}
test "$(get_counter nf_frag 0)" = 3
test "$(get_counter nf_frag 1)" = 1
${FROM_NS} ${BFCLI} chain flush --name nf_frag

if ! out=$(${FROM_NS} ${BFCLI} chain set --from-str "chain nf_defrag BF_HOOK_NF_LOCAL_IN{priorities=101-102,defrag=yes} ACCEPT ${RULES}" 2>&1); then
    echo "${out}"
    # The kernel doesn't support BPF_F_NETFILTER_IP_DEFRAG (before Linux 6.6)
    grep -q "doesn't support defrag=yes" <<< "${out}"
    exit 0
fi

# With defrag=yes, the chain sees the reassembled datagram
${FROM_NS} ${BFCLI} chain get --name nf_defrag | grep -q "defrag=yes"
ping -6 -c 1 -W 1 -s 3000 ${NS_IP6_ADDR}
test "$(get_counter nf_defrag 0)" = 0
test "$(get_counter nf_defrag 1)" = 1

# The option is kept when the chain is updated
${FROM_NS} ${BFCLI} chain update --name nf_defrag --from-str "chain nf_defrag BF_HOOK_NF_LOCAL_IN ACCEPT ${RULES}"
${FROM_NS} ${BFCLI} chain get --name nf_defrag | grep -q "defrag=yes"
ping -6 -c 1 -W 1 -s 3000 ${NS_IP6_ADDR}
test "$(get_counter nf_defrag 0)" = 0
test "$(get_counter nf_defrag 1)" = 1

${FROM_NS} ${BFCLI} chain flush --name nf_defrag
