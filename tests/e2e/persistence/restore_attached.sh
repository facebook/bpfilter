#!/usr/bin/env bash

. "$(dirname "$0")"/../e2e_test_util.sh

make_sandbox

# Create and attach chain, verify filtering works
${FROM_NS} ${BFCLI} chain set --from-str "chain test_chain BF_HOOK_XDP{ifindex=${NS_IFINDEX}} ACCEPT"
ping -c 1 -W 0.1 ${NS_IP_ADDR}

# Chain is discoverable from bpffs with correct ifindex
chain_output=$(${FROM_NS} ${BFCLI} chain get --name test_chain)
echo "$chain_output"
echo "$chain_output" | grep -q "ifindex=${NS_IFINDEX}"

# Attached chain with sets: set elements and filtering persist
${FROM_NS} ${BFCLI} chain set --from-str "chain test_chain BF_HOOK_XDP{ifindex=${NS_IFINDEX}} ACCEPT
    set myset (ip4.saddr) in { ${HOST_IP_ADDR}; 192.168.1.2 }
    set empty_set (ip4.saddr) in {}
    rule (ip4.saddr) in myset counter DROP
    rule (ip4.saddr) in empty_set ACCEPT"
(! ping -c 1 -W 0.1 ${NS_IP_ADDR})

# Chain with sets is discoverable from bpffs
chain_output=$(${FROM_NS} ${BFCLI} chain get --name test_chain)
echo "$chain_output"
echo "$chain_output" | grep -q "${HOST_IP_ADDR}"
echo "$chain_output" | grep -q "192.168.1.2"
echo "$chain_output" | grep -q "empty_set"
(! ping -c 1 -W 0.1 ${NS_IP_ADDR})

${FROM_NS} ${BFCLI} chain flush --name test_chain
