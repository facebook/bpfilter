#!/usr/bin/env bash

set -eux
set -o pipefail

. "$(dirname "$0")"/../e2e_test_util.sh
make_sandbox
start_bpfilter

# Test 1: Create chain, attach it, add elements to set
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

# Add new elements to the set
${FROM_NS} bfcli chain update-set \
    --name test_xdp \
    --set-name blocked_ips \
    --set-format '(ip4.saddr)' \
    --set-add '{10.0.0.3; 10.0.0.4}'

chain_output=$(${FROM_NS} bfcli chain get --name test_xdp)
echo "$chain_output"
echo "$chain_output" | grep -q '10.0.0.1'
echo "$chain_output" | grep -q '10.0.0.2'
echo "$chain_output" | grep -q '10.0.0.3'
echo "$chain_output" | grep -q '10.0.0.4'

# Test 2: Remove elements from set
${FROM_NS} bfcli chain update-set \
    --name test_xdp \
    --set-name blocked_ips \
    --set-format '(ip4.saddr)' \
    --set-remove '{10.0.0.1; 10.0.0.2}'

chain_output=$(${FROM_NS} bfcli chain get --name test_xdp)
echo "$chain_output"
(! echo "$chain_output" | grep -q '10.0.0.1')
(! echo "$chain_output" | grep -q '10.0.0.2')
echo "$chain_output" | grep -q '10.0.0.3'
echo "$chain_output" | grep -q '10.0.0.4'

# Test 3: Add and remove in one operation
${FROM_NS} bfcli chain update-set \
    --name test_xdp \
    --set-name blocked_ips \
    --set-format '(ip4.saddr)' \
    --set-add '{10.0.0.5; 10.0.0.6}' \
    --set-remove '{10.0.0.3}'

chain_output=$(${FROM_NS} bfcli chain get --name test_xdp)
echo "$chain_output"
(! echo "$chain_output" | grep -q '10.0.0.1')
(! echo "$chain_output" | grep -q '10.0.0.2')
(! echo "$chain_output" | grep -q '10.0.0.3')
echo "$chain_output" | grep -q '10.0.0.4'
echo "$chain_output" | grep -q '10.0.0.5'
echo "$chain_output" | grep -q '10.0.0.6'

# Test 4: Try to update non-existent set (should fail)
(! ${FROM_NS} bfcli chain update-set \
    --name test_xdp \
    --set-name nonexistent_set \
    --set-format '(ip4.saddr)' \
    --set-add '{10.0.0.1}' 2>&1)

# Verify the set still contains the correct data after failed update
chain_output=$(${FROM_NS} bfcli chain get --name test_xdp)
echo "$chain_output"
(! echo "$chain_output" | grep -q '10.0.0.1')
(! echo "$chain_output" | grep -q '10.0.0.2')
(! echo "$chain_output" | grep -q '10.0.0.3')
echo "$chain_output" | grep -q '10.0.0.4'
echo "$chain_output" | grep -q '10.0.0.5'
echo "$chain_output" | grep -q '10.0.0.6'

# Test 5: Try to update with mismatched key structure (should fail)
(! ${FROM_NS} bfcli chain update-set \
    --name test_xdp \
    --set-name blocked_ips \
    --set-format '(ip4.saddr, ip4.proto)' \
    --set-add '{10.0.0.1, tcp}' 2>&1)

# Verify the set still contains the correct data after failed update
chain_output=$(${FROM_NS} bfcli chain get --name test_xdp)
echo "$chain_output"
(! echo "$chain_output" | grep -q '10.0.0.1')
(! echo "$chain_output" | grep -q '10.0.0.2')
(! echo "$chain_output" | grep -q '10.0.0.3')
echo "$chain_output" | grep -q '10.0.0.4'
echo "$chain_output" | grep -q '10.0.0.5'
echo "$chain_output" | grep -q '10.0.0.6'

# Test 6: Try to update with wrong key type (ip4.daddr instead of ip4.saddr)
(! ${FROM_NS} bfcli chain update-set \
    --name test_xdp \
    --set-name blocked_ips \
    --set-format '(ip4.daddr)' \
    --set-add '{10.0.0.10}' 2>&1)

# Verify the set still contains the correct data after failed update
chain_output=$(${FROM_NS} bfcli chain get --name test_xdp)
echo "$chain_output"
(! echo "$chain_output" | grep -q '10.0.0.1')
(! echo "$chain_output" | grep -q '10.0.0.2')
(! echo "$chain_output" | grep -q '10.0.0.3')
echo "$chain_output" | grep -q '10.0.0.4'
echo "$chain_output" | grep -q '10.0.0.5'
echo "$chain_output" | grep -q '10.0.0.6'

# Test 7: Create unattached chain and update set
${FROM_NS} bfcli chain load --from-str "chain unattached_chain BF_HOOK_XDP ACCEPT
    set test_set (ip4.saddr) in { 192.168.1.1 }
    rule (ip4.saddr) in test_set ACCEPT
"

${FROM_NS} bfcli chain update-set \
    --name unattached_chain \
    --set-name test_set \
    --set-format '(ip4.saddr)' \
    --set-add '{192.168.1.2; 192.168.1.3}'

chain_output=$(${FROM_NS} bfcli chain get --name unattached_chain)
echo "$chain_output"
echo "$chain_output" | grep -q '192.168.1.1'
echo "$chain_output" | grep -q '192.168.1.2'
echo "$chain_output" | grep -q '192.168.1.3'

# Test 8: Adding duplicate elements is allowed
# Until bf_sets are backed by hashsets, duplicates will be visible
# in userspace representation, but deduplicated by the kernel
# when loaded into BPF hash maps
${FROM_NS} bfcli chain update-set \
    --name test_xdp \
    --set-name blocked_ips \
    --set-format '(ip4.saddr)' \
    --set-add '{10.0.0.4}'

chain_output=$(${FROM_NS} bfcli chain get --name test_xdp)
echo "$chain_output"

# Count how many times 10.0.0.4 appears (should be 2 - original + duplicate)
count=$(echo "$chain_output" | grep -o '10.0.0.4' | wc -l)
if [ "$count" -ne 2 ]; then
    echo "Expected 2 occurrences of 10.0.0.4, got $count"
    exit 1
fi

# Cleanup
${FROM_NS} bfcli chain flush --name test_xdp
${FROM_NS} bfcli chain flush --name unattached_chain
