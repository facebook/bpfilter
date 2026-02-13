#!/usr/bin/env bash

. "$(dirname "$0")"/../e2e_test_util.sh

make_sandbox

start_bpfilter
    ${FROM_NS} bfcli chain set --from-str "chain test_chain BF_HOOK_XDP ACCEPT"
stop_bpfilter --skip-cleanup

start_bpfilter
    ${FROM_NS} bfcli chain attach --name test_chain --option ifindex=${NS_IFINDEX}
stop_bpfilter