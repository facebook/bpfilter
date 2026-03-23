#!/usr/bin/env bash

. "$(dirname "$0")"/../e2e_test_util.sh

make_sandbox

${FROM_NS} ping -c 1 -W 0.1 ${NS_IP_ADDR}
${FROM_NS} ${BFCLI} ruleset set --from-str "chain xdp BF_HOOK_XDP{ifindex=${NS_IFINDEX}} ACCEPT rule icmp.type eq echo-request icmp.code eq 0 log transport,internet counter DROP"
(! ping -c 1 -W 0.1 ${NS_IP_ADDR})
${FROM_NS} ${BFCLI} chain get --name xdp | awk '/log internet,transport/{getline; print $2}' | grep -q "^1$" && exit 0 || exit 1
${FROM_NS} ${BFCLI} ruleset flush