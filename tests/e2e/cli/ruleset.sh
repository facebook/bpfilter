#!/usr/bin/env bash

. "$(dirname "$0")"/../e2e_test_util.sh

make_sandbox

${FROM_NS} ${BFCLI} ruleset set --from-str "chain ruleset_set_xdp_0 BF_HOOK_XDP{ifindex=${NS_IFINDEX}} ACCEPT chain ruleset_set_xdp_1 BF_HOOK_XDP DROP chain ruleset_set_tc_0 BF_HOOK_NF_LOCAL_IN{family=inet4,priorities=103-104} ACCEPT"
${FROM_NS} ${BFCLI} chain flush --name ruleset_set_xdp_0
${FROM_NS} ${BFCLI} ruleset get
${FROM_NS} ${BFCLI} ruleset set --from-str "chain ruleset_set_xdp_0 BF_HOOK_XDP{ifindex=${NS_IFINDEX}} ACCEPT chain ruleset_set_xdp_1 BF_HOOK_XDP DROP chain ruleset_set_tc_0 BF_HOOK_NF_LOCAL_IN{family=inet4,priorities=103-104} ACCEPT"
${FROM_NS} ${BFCLI} ruleset flush