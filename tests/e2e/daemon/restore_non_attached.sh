#!/usr/bin/env bash

. "$(dirname "$0")"/../e2e_test_util.sh

make_sandbox

start_bpfilter
    ${FROM_NS} bfcli chain set --from-str "chain test_chain BF_HOOK_XDP ACCEPT"
stop_bpfilter --skip-cleanup

start_bpfilter
    ${FROM_NS} bfcli chain attach --name test_chain --option ifindex=${NS_IFINDEX}

    # Non-attached chains with sets: set elements survive a restart, and the
    # chain can be attached afterward
    ${FROM_NS} bfcli chain set --from-str "chain test_chain BF_HOOK_XDP ACCEPT
        set myset (ip4.saddr) in { ${HOST_IP_ADDR}; 192.168.1.2 }
        set empty_set (ip4.saddr) in {}
        rule (ip4.saddr) in myset counter DROP
        rule (ip4.saddr) in empty_set ACCEPT"

    ping -c 1 -W 1 ${NS_IP_ADDR}
stop_bpfilter --skip-cleanup

start_bpfilter
    chain_output=$(${FROM_NS} bfcli chain get --name test_chain)
    echo "$chain_output"
    echo "$chain_output" | grep -q "${HOST_IP_ADDR}"
    echo "$chain_output" | grep -q "192.168.1.2"
    echo "$chain_output" | grep -q "empty_set"

    ${FROM_NS} bfcli chain attach --name test_chain --option ifindex=${NS_IFINDEX}
    (! ping -c 1 -W 1 ${NS_IP_ADDR})
stop_bpfilter
