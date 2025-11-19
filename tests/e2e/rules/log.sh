#!/usr/bin/env bash

set -eux
set -o pipefail

. "$(dirname "$0")"/../e2e_test_util.sh

make_sandbox
start_bpfilter

(! ${FROM_NS} bfcli chain set --from-str "chain chain_load_xdp_3 BF_HOOK_XDP ACCEPT rule ip4.proto icmp log counter DROP")
(! ${FROM_NS} bfcli chain set --from-str "chain chain_load_xdp_3 BF_HOOK_XDP ACCEPT rule ip4.proto icmp log ip counter DROP")
${FROM_NS} bfcli chain set --from-str "chain chain_load_xdp_3 BF_HOOK_XDP ACCEPT rule ip4.proto icmp log link counter DROP"
${FROM_NS} bfcli chain set --from-str "chain chain_load_xdp_3 BF_HOOK_XDP ACCEPT rule ip4.proto icmp log link,internet counter DROP"
${FROM_NS} bfcli chain set --from-str "chain chain_load_xdp_3 BF_HOOK_XDP ACCEPT rule ip4.proto icmp log link,transport counter DROP"
${FROM_NS} bfcli chain set --from-str "chain chain_load_xdp_3 BF_HOOK_XDP ACCEPT rule ip4.proto icmp log internet,link counter DROP"