#!/usr/bin/env bash

set -eux
set -o pipefail

. "$(dirname "$0")"/../e2e_test_util.sh

make_sandbox
start_bpfilter

get_rule_counter() {
    local chain_name=$1
    local rule_idx=$2
    ${FROM_NS} bfcli chain get --name "${chain_name}" \
        | grep "counters" \
        | grep -v "policy\|error" \
        | sed -n "${rule_idx}p" \
        | awk '{print $2}'
}

get_policy_counter() {
    local chain_name=$1
    ${FROM_NS} bfcli chain get --name "${chain_name}" \
        | grep "counters policy" \
        | awk '{print $3}'
}

CHAIN="counter_restore"

# Test 1: counter preservation with rule reordering

${FROM_NS} bfcli chain set --from-str \
    "chain ${CHAIN} BF_HOOK_XDP{ifindex=${NS_IFINDEX}} ACCEPT rule ip4.proto icmp counter DROP"
(! ping -c 1 -W 0.1 ${NS_IP_ADDR})
COUNTER=$(get_rule_counter ${CHAIN} 1)
POLICY=$(get_policy_counter ${CHAIN})
test "${COUNTER}" -eq 1

${FROM_NS} bfcli chain update --from-str \
    "chain ${CHAIN} BF_HOOK_XDP ACCEPT rule ip4.saddr eq ${HOST_IP_ADDR} counter ACCEPT rule ip4.proto icmp counter DROP"
test "$(get_rule_counter ${CHAIN} 1)" -eq 0
test "$(get_rule_counter ${CHAIN} 2)" -eq "${COUNTER}"
test "$(get_policy_counter ${CHAIN})" -ge "${POLICY}"

POLICY=$(get_policy_counter ${CHAIN})
${FROM_NS} bfcli chain update --from-str \
    "chain ${CHAIN} BF_HOOK_XDP ACCEPT rule ip4.proto icmp counter ACCEPT"
test "$(get_rule_counter ${CHAIN} 1)" -eq 0
test "$(get_policy_counter ${CHAIN})" -ge "${POLICY}"

${FROM_NS} bfcli chain flush --name ${CHAIN}

# Test 2: set index reordering
# Rules reference sets by content, so counters should be preserved
# despite the set index shuffle.

${FROM_NS} bfcli chain set --from-str \
    "chain ${CHAIN} BF_HOOK_XDP{ifindex=${NS_IFINDEX}} ACCEPT \
    set s1 (ip4.saddr) in { 10.0.0.1 } \
    set s2 (ip4.saddr) in { 10.0.0.2 } \
    rule (ip4.saddr) in s1 counter ACCEPT \
    rule (ip4.saddr) in s2 counter DROP"

ping -c 1 -W 0.1 ${NS_IP_ADDR}
COUNTER_S1=$(get_rule_counter ${CHAIN} 1)
test "${COUNTER_S1}" -eq 1

${FROM_NS} bfcli chain update --from-str \
    "chain ${CHAIN} BF_HOOK_XDP ACCEPT \
    set s2 (ip4.saddr) in { 10.0.0.2 } \
    set s1 (ip4.saddr) in { 10.0.0.1 } \
    set s3 (ip4.saddr) in { 10.0.0.3 } \
    rule (ip4.saddr) in s1 counter ACCEPT \
    rule (ip4.saddr) in s2 counter DROP"
test "$(get_rule_counter ${CHAIN} 1)" -eq "${COUNTER_S1}"
test "$(get_rule_counter ${CHAIN} 2)" -eq 0

COUNTER_S2=$(get_rule_counter ${CHAIN} 2)
${FROM_NS} bfcli chain update --from-str \
    "chain ${CHAIN} BF_HOOK_XDP ACCEPT \
    set s1 (ip4.saddr) in { 10.0.0.99 } \
    set s2 (ip4.saddr) in { 10.0.0.2 } \
    rule (ip4.saddr) in s1 counter ACCEPT \
    rule (ip4.saddr) in s2 counter DROP"
test "$(get_rule_counter ${CHAIN} 1)" -eq 0
test "$(get_rule_counter ${CHAIN} 2)" -eq "${COUNTER_S2}"

${FROM_NS} bfcli chain flush --name ${CHAIN}
