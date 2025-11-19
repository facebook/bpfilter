#!/usr/bin/env bash

set -eux
set -o pipefail

. "$(dirname "$0")"/../e2e_test_util.sh

make_sandbox
start_bpfilter

(! ${FROM_NS} bfcli chain set --from-str "")
(! ${FROM_NS} bfcli chain set --from-str "chain test0 BF_HOOK_XDP ACCEPT chain test1 BF_HOOK_XDP ACCEPT")
(! ${FROM_NS} bfcli chain set --name invalid --from-str "chain test0 BF_HOOK_XDP ACCEPT chain test1 BF_HOOK_XDP ACCEPT")
${FROM_NS} bfcli chain set --from-str "chain chain_set_xdp_0 BF_HOOK_XDP ACCEPT"
${FROM_NS} bfcli chain set --from-str "chain chain_set_xdp_1 BF_HOOK_XDP{ifindex=${NS_IFINDEX}} ACCEPT"
${FROM_NS} bfcli chain set --name chain_set_tc_0 --from-str "chain chain_set_tc_0 BF_HOOK_TC_INGRESS ACCEPT chain chain_set_tc_1 BF_HOOK_TC_INGRESS ACCEPT"
${FROM_NS} bfcli chain set --name chain_set_tc_2 --from-str "chain chain_set_tc_2 BF_HOOK_TC_EGRESS{ifindex=${NS_IFINDEX}} ACCEPT chain chain_set_tc_3 BF_HOOK_TC_INGRESS ACCEPT"
${FROM_NS} bfcli chain set --from-str "chain chain_set_xdp_0 BF_HOOK_NF_LOCAL_IN ACCEPT"
${FROM_NS} bfcli chain set --from-str "chain chain_set_tc_0 BF_HOOK_NF_LOCAL_IN{family=inet4,priorities=101-102} ACCEPT"
${FROM_NS} bfcli chain set --from-str "chain chain_set_xdp_1 BF_HOOK_NF_LOCAL_IN ACCEPT"
${FROM_NS} bfcli chain set --from-str "chain chain_set_tc_2 BF_HOOK_NF_LOCAL_IN{family=inet4,priorities=103-104} ACCEPT"
${FROM_NS} bfcli chain flush --name chain_set_xdp_0
${FROM_NS} bfcli chain flush --name chain_set_xdp_1
${FROM_NS} bfcli chain flush --name chain_set_tc_0
${FROM_NS} bfcli chain flush --name chain_set_tc_2
(! ${FROM_NS} bfcli chain get --name chain_set_tc_2)