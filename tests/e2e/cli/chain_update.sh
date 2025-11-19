#!/usr/bin/env bash

set -eux
set -o pipefail

. "$(dirname "$0")"/../e2e_test_util.sh

make_sandbox
start_bpfilter

# Failures
(! ${FROM_NS} bfcli chain update --from-str "")
(! ${FROM_NS} bfcli chain update --name invalid_name --from-str "chain chain_load_xdp_0 BF_HOOK_XDP ACCEPT")
(! ${FROM_NS} bfcli chain update --name chain_load_xdp_1 --from-str "chain chain_load_xdp_1 BF_HOOK_XDP ACCEPT")
${FROM_NS} bfcli chain set --from-str "chain chain_load_xdp_2 BF_HOOK_XDP ACCEPT"
(! ${FROM_NS} bfcli chain update --from-str "chain chain_load_xdp_2 BF_HOOK_XDP ACCEPT")

# Chain exist and is attached
${FROM_NS} bfcli chain set --from-str "chain chain_load_xdp_3 BF_HOOK_XDP{ifindex=${NS_IFINDEX}} ACCEPT"
ping -c 1 -W 0.1 ${NS_IP_ADDR}
${FROM_NS} bfcli chain update --from-str "chain chain_load_xdp_3 BF_HOOK_XDP ACCEPT rule ip4.proto icmp log transport counter DROP"
(! ping -c 1 -W 0.1 ${NS_IP_ADDR})
${FROM_NS} bfcli chain update --name chain_load_xdp_3 --from-str "chain chain_load_xdp_3 BF_HOOK_XDP{ifindex=${NS_IFINDEX}} ACCEPT"
ping -c 1 -W 0.1 ${NS_IP_ADDR}
${FROM_NS} bfcli chain flush --name chain_load_xdp_3