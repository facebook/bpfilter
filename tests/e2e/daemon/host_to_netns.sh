#!/usr/bin/env bash

set -eux
set -o pipefail

. "$(dirname "$0")"/../e2e_test_util.sh

make_sandbox
start_bpfilter

(! ${FROM_NS} bfcli ruleset set --from-str "chain xdp BF_HOOK_XDP{ifindex=${HOST_IFINDEX}} ACCEPT rule ip4.proto icmp log link counter DROP")
ping -c 1 -W 0.1 ${NS_IP_ADDR}
${FROM_NS} bfcli ruleset set --from-str "chain xdp BF_HOOK_XDP{ifindex=${NS_IFINDEX}} ACCEPT rule ip4.proto icmp counter DROP"
(! ping -c 1 -W 0.1 ${NS_IP_ADDR})
${FROM_NS} bfcli chain get --name xdp | awk '/ip4.proto eq icmp/{getline; print $2}' | grep -q "^1$" && exit 0 || exit 1
${FROM_NS} bfcli ruleset flush