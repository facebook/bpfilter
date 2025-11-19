#!/usr/bin/env bash

set -eux
set -o pipefail

. "$(dirname "$0")"/../e2e_test_util.sh

make_sandbox
start_bpfilter

(! ${FROM_NS} bfcli ruleset set --from-str "chain xdp BF_HOOK_XDP{ifindex=${HOST_IFINDEX}} ACCEPT rule ip4.proto icmp log link,transport counter DROP")
${FROM_NS} ping -c 1 -W 0.1 ${HOST_IP_ADDR}
${FROM_NS} bfcli ruleset set --from-str "chain xdp BF_HOOK_TC_INGRESS{ifindex=${NS_IFINDEX}} ACCEPT rule ip4.proto icmp log link,internet counter DROP"
(! ping -c 1 -W 0.1 ${NS_IP_ADDR})
${FROM_NS} bfcli chain get --name xdp | awk '/log link,internet/{getline; print $2}' | grep -q "^1$" && exit 0 || exit 1
${FROM_NS} bfcli ruleset flush