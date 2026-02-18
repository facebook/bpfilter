#!/usr/bin/env bash

. "$(dirname "$0")"/../e2e_test_util.sh

make_sandbox

start_bpfilter
    ${FROM_NS} bfcli chain set --from-str "chain test_chain BF_HOOK_XDP{ifindex=${NS_IFINDEX}} ACCEPT"
    ping -c 1 -W 1 ${NS_IP_ADDR}
stop_bpfilter --skip-cleanup

start_bpfilter
    # Ensure it's restored as attached with the correct ifindex
    chain_output=$(${FROM_NS} bfcli chain get --name test_chain)
    echo "$chain_output"
    echo "$chain_output" | grep -q "ifindex=${NS_IFINDEX}"

    # Attached chains with sets: set elements and filtering survive a restart
    ${FROM_NS} bfcli chain set --from-str "chain test_chain BF_HOOK_XDP{ifindex=${NS_IFINDEX}} ACCEPT
        set myset (ip4.saddr) in { ${HOST_IP_ADDR}; 192.168.1.2 }
        set empty_set (ip4.saddr) in {}
        rule (ip4.saddr) in myset counter DROP
        rule (ip4.saddr) in empty_set ACCEPT"
    (! ping -c 1 -W 1 ${NS_IP_ADDR})
stop_bpfilter --skip-cleanup

start_bpfilter
    chain_output=$(${FROM_NS} bfcli chain get --name test_chain)
    echo "$chain_output"
    echo "$chain_output" | grep -q "${HOST_IP_ADDR}"
    echo "$chain_output" | grep -q "192.168.1.2"
    echo "$chain_output" | grep -q "empty_set"
    (! ping -c 1 -W 1 ${NS_IP_ADDR})
stop_bpfilter
