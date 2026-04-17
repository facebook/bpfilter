#!/usr/bin/env bash

. "$(dirname "$0")"/../e2e_test_util.sh

get_counter() {
    ${FROM_NS} bfcli chain get --name "$1" | awk '/counters [0-9]+ packets/{print $2}'
}

make_sandbox
start_bpfilter

# NEXT as a chain policy on TC: with no next program attached, TCX_NEXT
# behaves like pass, so ping succeeds.
${FROM_NS} bfcli chain set --from-str "chain c BF_HOOK_TC_INGRESS{ifindex=${NS_IFINDEX}} NEXT"
ping -c 1 -W 1 ${NS_IP_ADDR}

# NEXT as a rule verdict on TC: matched packets are handed to the next BPF
# program. With no next program attached, TCX_NEXT behaves like pass, so ping
# succeeds. The counter verifies the rule was actually evaluated.
${FROM_NS} bfcli chain set --from-str "chain c BF_HOOK_TC_INGRESS{ifindex=${NS_IFINDEX}} DROP rule ip4.proto icmp counter NEXT"
test "$(get_counter c)" = "0"
ping -c 1 -W 1 ${NS_IP_ADDR}
test "$(get_counter c)" = "1"

${FROM_NS} bfcli ruleset get
# NEXT as a rule verdict on TC: matched packets are handed to the next BPF
# program. With no next program attached, TCX_NEXT behaves like pass, so ping
# succeeds. The counter verifies the rule was actually evaluated.
${FROM_NS} bfcli chain set --from-str "chain c BF_HOOK_TC_INGRESS{ifindex=${NS_IFINDEX}} NEXT rule ip4.proto icmp counter DROP"
test "$(get_counter c)" = "0"
(! ping -c 1 -W 1 ${NS_IP_ADDR})
test "$(get_counter c)" = "1"
