#!/usr/bin/env bash

. "$(dirname "$0")"/../e2e_test_util.sh

make_sandbox

${FROM_NS} ping -c 1 -W 0.1 ${NS_IP_ADDR}
${FROM_NS} ${BFCLI} ruleset set --from-str "chain xdp BF_HOOK_TC_INGRESS{ifindex=${NS_IFINDEX}} ACCEPT rule icmp.type eq echo-request icmp.code eq 0 counter DROP"
(! ping -c 1 -W 0.1 ${NS_IP_ADDR})
test "$(get_counter xdp 0)" = "1"
${FROM_NS} ${BFCLI} ruleset flush