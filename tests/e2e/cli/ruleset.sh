#!/usr/bin/env bash

set -eux
set -o pipefail

. "$(dirname "$0")"/../e2e_test_util.sh

make_sandbox
start_bpfilter

${FROM_NS} bfcli ruleset set --from-str "chain ruleset_set_xdp_0 BF_HOOK_XDP{ifindex=${NS_IFINDEX}} ACCEPT chain ruleset_set_xdp_1 BF_HOOK_XDP DROP chain ruleset_set_tc_0 BF_HOOK_NF_LOCAL_IN{family=inet4,priorities=103-104} ACCEPT"
${FROM_NS} bfcli chain flush --name ruleset_set_xdp_0
${FROM_NS} bfcli ruleset get
${FROM_NS} bfcli ruleset set --from-str "chain ruleset_set_xdp_0 BF_HOOK_XDP{ifindex=${NS_IFINDEX}} ACCEPT chain ruleset_set_xdp_1 BF_HOOK_XDP DROP chain ruleset_set_tc_0 BF_HOOK_NF_LOCAL_IN{family=inet4,priorities=103-104} ACCEPT"
${FROM_NS} bfcli ruleset flush