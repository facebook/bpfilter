#!/usr/bin/env bash

set -eux
set -o pipefail

. "$(dirname "$0")"/../e2e_test_util.sh

make_sandbox
start_bpfilter

(! ${FROM_NS} bfcli chain set --from-str "chain xdp_mark BF_HOOK_XDP ACCEPT rule ip4.proto icmp mark 0x16 DROP")
(! ${FROM_NS} bfcli chain set --from-str "chain xdp_mark BF_HOOK_NF_LOCAL_IN ACCEPT rule ip4.proto icmp mark 0x16 DROP")
(! ${FROM_NS} bfcli chain set --from-str "chain xdp_mark BF_HOOK_TC_INGRESS ACCEPT rule ip4.proto icmp mark DROP")
(! ${FROM_NS} bfcli chain set --from-str "chain xdp_mark BF_HOOK_TC_INGRESS ACCEPT rule ip4.proto icmp mark 0x14aw DROP")
(! ${FROM_NS} bfcli chain set --from-str "chain xdp_mark BF_HOOK_TC_INGRESS ACCEPT rule ip4.proto icmp mark -3 DROP")
(! ${FROM_NS} bfcli chain set --from-str "chain xdp_mark BF_HOOK_TC_INGRESS ACCEPT rule ip4.proto icmp mark 0xffffffffff DROP")

${FROM_NS} bfcli chain set --from-str "chain xdp_mark BF_HOOK_TC_INGRESS ACCEPT rule ip4.proto icmp mark 14 DROP"
${FROM_NS} bfcli chain set --from-str "chain xdp_mark BF_HOOK_TC_INGRESS ACCEPT rule ip4.proto icmp mark 0x14 DROP"