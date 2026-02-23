#!/usr/bin/env bash

. "$(dirname "$0")"/../e2e_test_util.sh
make_sandbox
start_bpfilter

# Adding new elements
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

# Removing elements
${FROM_NS} bfcli chain set --from-str "chain test_xdp BF_HOOK_XDP{ifindex=${NS_IFINDEX}} ACCEPT
    set blocked_ips (ip4.saddr) in {
        10.0.0.1;
        10.0.0.2;
        10.0.0.3;
        10.0.0.4
    }
    rule
        (ip4.saddr) in blocked_ips
        counter
        DROP
"

${FROM_NS} bfcli chain update-set \
    --name test_xdp \
    --set-name blocked_ips \
    --remove 10.0.0.3 --remove 10.0.0.4

chain_output=$(${FROM_NS} bfcli chain get --name test_xdp)
echo "$chain_output"
echo "$chain_output" | grep -q '10.0.0.1'
echo "$chain_output" | grep -q '10.0.0.2'
(! echo "$chain_output" | grep -q '10.0.0.3')
(! echo "$chain_output" | grep -q '10.0.0.4')

# Adding and removing in one operation
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

${FROM_NS} bfcli chain update-set \
    --name test_xdp \
    --set-name blocked_ips \
    --add 10.0.0.3 --add 10.0.0.4 \
    --remove 10.0.0.1 --remove 10.0.0.4

chain_output=$(${FROM_NS} bfcli chain get --name test_xdp)
echo "$chain_output"
(! echo "$chain_output" | grep -q '10.0.0.1')
echo "$chain_output" | grep -q '10.0.0.2'
echo "$chain_output" | grep -q '10.0.0.3'
(! echo "$chain_output" | grep -q '10.0.0.4')

# Trying to update non-existent set should fail
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

(! ${FROM_NS} bfcli chain update-set \
    --name test_xdp \
    --set-name nonexistent_set \
    --add 10.0.0.3 2>&1)

chain_output=$(${FROM_NS} bfcli chain get --name test_xdp)
echo "$chain_output"
echo "$chain_output" | grep -q '10.0.0.1'
echo "$chain_output" | grep -q '10.0.0.2'

# Trying to update with mismatched key format should fail
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

(! ${FROM_NS} bfcli chain update-set \
    --name test_xdp \
    --set-name blocked_ips \
    --add 10.0.0.1,tcp 2>&1)

chain_output=$(${FROM_NS} bfcli chain get --name test_xdp)
echo "$chain_output"
echo "$chain_output" | grep -q '10.0.0.1'
echo "$chain_output" | grep -q '10.0.0.2'

# Trying to update with nothing to add or remove should fail
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

(! ${FROM_NS} bfcli chain update-set \
    --name test_xdp \
    --set-name blocked_ips 2>&1)

# Trying to add duplicate elements is no-op
${FROM_NS} bfcli chain set --from-str "chain test_xdp BF_HOOK_XDP{ifindex=${NS_IFINDEX}} ACCEPT
    set blocked_ips (ip4.saddr) in {
        10.0.0.1
    }
    rule
        (ip4.saddr) in blocked_ips
        counter
        DROP
"

${FROM_NS} bfcli chain update-set \
    --name test_xdp \
    --set-name blocked_ips \
    --add 10.0.0.1

chain_output=$(${FROM_NS} bfcli chain get --name test_xdp)
echo "$chain_output"
count=$(echo "$chain_output" | grep -o '10.0.0.1' | wc -l)
if [ "$count" -ne 1 ]; then
    echo "Expected 1 occurrence of 10.0.0.1, got $count"
    exit 1
fi

# Works with compound keys
${FROM_NS} bfcli chain set --from-str "chain test_xdp BF_HOOK_XDP{ifindex=${NS_IFINDEX}} ACCEPT
    set blocked_addrs (ip4.saddr, tcp.sport) in {
        10.0.0.1, 10001;
        10.0.0.2, 10002
    }
    rule
        (ip4.saddr, tcp.sport) in blocked_addrs
        counter
        DROP
"

${FROM_NS} bfcli chain update-set \
    --name test_xdp \
    --set-name blocked_addrs \
    --add 10.0.0.3,10003 --add '10.0.0.4, 10004'

chain_output=$(${FROM_NS} bfcli chain get --name test_xdp)
echo "$chain_output"
echo "$chain_output" | grep -q '10.0.0.1, 10001'
echo "$chain_output" | grep -q '10.0.0.2, 10002'
echo "$chain_output" | grep -q '10.0.0.3, 10003'
echo "$chain_output" | grep -q '10.0.0.4, 10004'

# Unattached chain can be updated
${FROM_NS} bfcli chain set --from-str "chain test_xdp BF_HOOK_XDP ACCEPT
    set test_set (ip4.saddr) in { 10.0.0.1 }
    rule (ip4.saddr) in test_set ACCEPT
"

${FROM_NS} bfcli chain update-set \
    --name test_xdp \
    --set-name test_set \
    --add 10.0.0.2

chain_output=$(${FROM_NS} bfcli chain get --name test_xdp)
echo "$chain_output"
echo "$chain_output" | grep -q '10.0.0.1'
echo "$chain_output" | grep -q '10.0.0.2'

# Counters are preserved after update-set for both set and non-set rules
${FROM_NS} bfcli chain set --from-str "chain test_xdp BF_HOOK_XDP{ifindex=${NS_IFINDEX}} ACCEPT
    set blocked_ips (ip4.saddr) in {
        10.0.0.1
    }
    rule
        (ip4.saddr) in blocked_ips
        counter
        DROP
    rule
        ip4.proto icmp
        counter
        DROP
"

(! ping -c 1 -W 0.1 ${NS_IP_ADDR})
${FROM_NS} bfcli chain update-set \
    --name test_xdp \
    --set-name blocked_ips \
    --add ${HOST_IP_ADDR}

(! ping -c 1 -W 0.1 ${NS_IP_ADDR})
${FROM_NS} bfcli chain update-set \
    --name test_xdp \
    --set-name blocked_ips \
    --add 10.0.0.2

counter=$(${FROM_NS} bpftool map dump pinned ${WORKDIR}/bpf/bpfilter/test_xdp/bf_cmap | jq '.[0].value.count')
test "$counter" = "1"
counter=$(${FROM_NS} bpftool map dump pinned ${WORKDIR}/bpf/bpfilter/test_xdp/bf_cmap | jq '.[1].value.count')
test "$counter" = "1"
${FROM_NS} bfcli chain flush --name test_xdp
