#!/usr/bin/env bash

set -eux
set -o pipefail

. "$(dirname "$0")"/../e2e_test_util.sh
make_sandbox

start_bpfilter
    # Test set 1: Basic tests
    ${FROM_NS} bfcli chain set --from-str "chain test_xdp BF_HOOK_XDP{ifindex=${NS_IFINDEX}} ACCEPT
        set blocked_ips (ip4.saddr) in {
            10.0.0.1;
            10.0.0.2
        }
        rule
            (ip4.saddr) in blocked_ips
            counter
            DROP
    "

    chain_output=$(${FROM_NS} bfcli chain get --name test_xdp)
    echo "$chain_output"
    echo "$chain_output" | grep -q '10.0.0.1'
    echo "$chain_output" | grep -q '10.0.0.2'

    # Test 1.1: Add new elements
    ${FROM_NS} bfcli chain update-set \
        --name test_xdp \
        --set-name blocked_ips \
        --add 10.0.0.3 --add 10.0.0.4

    chain_output=$(${FROM_NS} bfcli chain get --name test_xdp)
    echo "$chain_output"
    echo "$chain_output" | grep -q '10.0.0.1'
    echo "$chain_output" | grep -q '10.0.0.2'
    echo "$chain_output" | grep -q '10.0.0.3'
    echo "$chain_output" | grep -q '10.0.0.4'

    # Test 1.2: Remove elements
    ${FROM_NS} bfcli chain update-set \
        --name test_xdp \
        --set-name blocked_ips \
        --remove 10.0.0.1 --remove 10.0.0.2

    chain_output=$(${FROM_NS} bfcli chain get --name test_xdp)
    echo "$chain_output"
    (! echo "$chain_output" | grep -q '10.0.0.1')
    (! echo "$chain_output" | grep -q '10.0.0.2')
    echo "$chain_output" | grep -q '10.0.0.3'
    echo "$chain_output" | grep -q '10.0.0.4'

    # Test 1.3: Add and remove in one operation
    ${FROM_NS} bfcli chain update-set \
        --name test_xdp \
        --set-name blocked_ips \
        --add 10.0.0.5 --add 10.0.0.6 \
        --remove 10.0.0.3

    chain_output=$(${FROM_NS} bfcli chain get --name test_xdp)
    echo "$chain_output"
    (! echo "$chain_output" | grep -q '10.0.0.1')
    (! echo "$chain_output" | grep -q '10.0.0.2')
    (! echo "$chain_output" | grep -q '10.0.0.3')
    echo "$chain_output" | grep -q '10.0.0.4'
    echo "$chain_output" | grep -q '10.0.0.5'
    echo "$chain_output" | grep -q '10.0.0.6'

    # Test 1.4: Try to update non-existent set (should fail)
    (! ${FROM_NS} bfcli chain update-set \
        --name test_xdp \
        --set-name nonexistent_set \
        --add 10.0.0.1 2>&1)

    # Verify the set still contains the correct data after failed update
    chain_output=$(${FROM_NS} bfcli chain get --name test_xdp)
    echo "$chain_output"
    (! echo "$chain_output" | grep -q '10.0.0.1')
    (! echo "$chain_output" | grep -q '10.0.0.2')
    (! echo "$chain_output" | grep -q '10.0.0.3')
    echo "$chain_output" | grep -q '10.0.0.4'
    echo "$chain_output" | grep -q '10.0.0.5'
    echo "$chain_output" | grep -q '10.0.0.6'

    # Test 1.5: Try to update with mismatched key structure (should fail)
    (! ${FROM_NS} bfcli chain update-set \
        --name test_xdp \
        --set-name blocked_ips \
        --add 10.0.0.1,tcp 2>&1)

    # Verify the set still contains the correct data after failed update
    chain_output=$(${FROM_NS} bfcli chain get --name test_xdp)
    echo "$chain_output"
    (! echo "$chain_output" | grep -q '10.0.0.1')
    (! echo "$chain_output" | grep -q '10.0.0.2')
    (! echo "$chain_output" | grep -q '10.0.0.3')
    echo "$chain_output" | grep -q '10.0.0.4'
    echo "$chain_output" | grep -q '10.0.0.5'
    echo "$chain_output" | grep -q '10.0.0.6'

    # Test 1.6: Trying to add duplicate elements is no-op
    ${FROM_NS} bfcli chain update-set \
        --name test_xdp \
        --set-name blocked_ips \
        --add 10.0.0.4
    ${FROM_NS} bfcli chain update-set \
        --name test_xdp \
        --set-name blocked_ips \
        --add 10.0.0.4

    # Should appear once
    count=$(echo "$chain_output" | grep -o '10.0.0.4' | wc -l)
    if [ "$count" -ne 1 ]; then
        echo "Expected 1 occurrence of 10.0.0.4, got $count"
        exit 1
    fi

    # Test 1.7: Add and remove of same element is no-op.
    ${FROM_NS} bfcli chain update-set \
        --name test_xdp \
        --set-name blocked_ips \
        --add 10.0.0.5 \
        --remove 10.0.0.5

    chain_output=$(${FROM_NS} bfcli chain get --name test_xdp)
    echo "$chain_output"
    (! echo "$chain_output" | grep -q '10.0.0.5')

    ${FROM_NS} bfcli chain flush --name test_xdp
stop_bpfilter --skip-cleanup

start_bpfilter
    # Test set 2: Compound key tests
    ${FROM_NS} bfcli chain set --from-str "chain compound_key_test BF_HOOK_XDP{ifindex=${NS_IFINDEX}} ACCEPT
        set blocked_addrs (ip4.saddr, tcp.sport) in {
            192.168.1.1, 10001;
            192.168.1.2, 10002
        }
        rule
            (ip4.saddr, tcp.sport) in blocked_addrs
            counter
            DROP
    "

    chain_output=$(${FROM_NS} bfcli chain get --name compound_key_test)
    echo "$chain_output"
    echo "$chain_output" | grep -q '192.168.1.1, 10001'
    echo "$chain_output" | grep -q '192.168.1.2, 10002'

    # Test 2.1: Add new elements.
    ${FROM_NS} bfcli chain update-set \
        --name compound_key_test \
        --set-name blocked_addrs \
        --add 192.168.1.3,10003 --add '192.168.1.4, 10004'

    chain_output=$(${FROM_NS} bfcli chain get --name compound_key_test)
    echo "$chain_output"
    echo "$chain_output" | grep -q '192.168.1.1, 10001'
    echo "$chain_output" | grep -q '192.168.1.2, 10002'
    echo "$chain_output" | grep -q '192.168.1.3, 10003'
    echo "$chain_output" | grep -q '192.168.1.4, 10004'

    # Test 2.2: Remove elements.
    ${FROM_NS} bfcli chain update-set \
        --name compound_key_test \
        --set-name blocked_addrs \
        --remove 192.168.1.1,10001

    chain_output=$(${FROM_NS} bfcli chain get --name compound_key_test)
    echo "$chain_output"
    (! echo "$chain_output" | grep -q '192.168.1.1, 10001')
    echo "$chain_output" | grep -q '192.168.1.2, 10002'
    echo "$chain_output" | grep -q '192.168.1.3, 10003'
    echo "$chain_output" | grep -q '192.168.1.4, 10004'

    # Test 2.3: Updating with wrong arity should fail.
    (! ${FROM_NS} bfcli chain update-set \
        --name compound_key_test \
        --set-name blocked_addrs \
        --add 192.168.1.1 2>&1)

    # Verify the set still contains the correct data after failed update
    chain_output=$(${FROM_NS} bfcli chain get --name compound_key_test)
    echo "$chain_output"
    (! echo "$chain_output" | grep -q '192.168.1.1, 10001')
    echo "$chain_output" | grep -q '192.168.1.2, 10002'
    echo "$chain_output" | grep -q '192.168.1.3, 10003'
    echo "$chain_output" | grep -q '192.168.1.4, 10004'
stop_bpfilter --skip-cleanup

start_bpfilter
    # Test 3: Unattached chain updates
    ${FROM_NS} bfcli chain load --from-str "chain unattached_chain BF_HOOK_XDP ACCEPT
        set test_set (ip4.saddr) in { 192.168.1.1 }
        rule (ip4.saddr) in test_set ACCEPT
    "

    ${FROM_NS} bfcli chain update-set \
        --name unattached_chain \
        --set-name test_set \
        --add 192.168.1.2

    chain_output=$(${FROM_NS} bfcli chain get --name unattached_chain)
    echo "$chain_output"
    echo "$chain_output" | grep -q '192.168.1.1'
    echo "$chain_output" | grep -q '192.168.1.2'
stop_bpfilter --skip-cleanup
