#!/usr/bin/env bash

set -eux
set -o pipefail

. "$(dirname "$0")"/../e2e_test_util.sh

make_sandbox
start_bpfilter

# No chain found
(! ${FROM_NS} bfcli chain load --from-str "")

# Single chain found
(! ${FROM_NS} bfcli chain load --name invalid_name --from-str "chain chain_load_xdp_0 BF_HOOK_XDP ACCEPT")
${FROM_NS} bfcli chain load --from-str "chain chain_load_xdp_1 BF_HOOK_XDP ACCEPT"
${FROM_NS} bfcli chain load --name chain_load_xdp_2 --from-str "chain chain_load_xdp_2 BF_HOOK_XDP ACCEPT"
${FROM_NS} bfcli chain get --name chain_load_xdp_1
${FROM_NS} bfcli chain get --name chain_load_xdp_2
${FROM_NS} bfcli chain flush --name chain_load_xdp_1
${FROM_NS} bfcli chain flush --name chain_load_xdp_2

# Multiple chains found
(! ${FROM_NS} bfcli chain load --from-str "chain chain_load_tc_0 BF_HOOK_TC_INGRESS ACCEPT chain chain_load_tc_1 BF_HOOK_TC_INGRESS ACCEPT")
(! ${FROM_NS} bfcli chain load --name invalid --from-str "chain chain_load_tc_2 BF_HOOK_TC_INGRESS ACCEPT chain chain_load_tc_3 BF_HOOK_TC_INGRESS ACCEPT")
${FROM_NS} bfcli chain load --name chain_load_tc_4 --from-str "chain chain_load_tc_4 BF_HOOK_TC_INGRESS ACCEPT chain chain_load_tc_5 BF_HOOK_TC_INGRESS ACCEPT"
${FROM_NS} bfcli chain get --name chain_load_tc_4
${FROM_NS} bfcli chain flush --name chain_load_tc_4