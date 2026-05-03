#!/usr/bin/env bash

. "$(dirname "$0")"/../e2e_test_util.sh

make_sandbox

${FROM_NS} ${BFCLI} chain set --from-str "chain test_xdp BF_HOOK_XDP{ifindex=${NS_IFINDEX}} ACCEPT
    set blocked_ips (ip4.saddr) in {
        10.0.0.1;
        10.0.0.2;
        10.0.0.3
    }
    rule
        (ip4.saddr) in blocked_ips
        DROP
    rule
        (ip4.saddr) in {
            192.168.1.1;
            192.168.1.2
        }
        DROP
"

# Without --no-set-content, all elements are printed
chain_output=$(${FROM_NS} ${BFCLI} chain get --name test_xdp)
echo "$chain_output"
echo "$chain_output" | grep -q '10.0.0.1'
echo "$chain_output" | grep -q '192.168.1.1'
(! echo "$chain_output" | grep -q 'elided')

# With --no-set-content, elements are replaced by an element count
chain_output=$(${FROM_NS} ${BFCLI} chain get --name test_xdp --no-set-content)
echo "$chain_output"
(! echo "$chain_output" | grep -q '10.0.0.1')
(! echo "$chain_output" | grep -q '192.168.1.1')
# Set name and key are still printed so users can identify the set
echo "$chain_output" | grep -q 'blocked_ips (ip4.saddr)'
# Counts are correct
echo "$chain_output" | grep -q '3 elements, content elided'
echo "$chain_output" | grep -q '2 elements, content elided'

# ruleset get --no-set-content honors the flag too
ruleset_output=$(${FROM_NS} ${BFCLI} ruleset get --no-set-content)
echo "$ruleset_output"
(! echo "$ruleset_output" | grep -q '10.0.0.1')
(! echo "$ruleset_output" | grep -q '192.168.1.1')
echo "$ruleset_output" | grep -q '3 elements, content elided'
echo "$ruleset_output" | grep -q '2 elements, content elided'

# ruleset get without the flag still prints elements
ruleset_output=$(${FROM_NS} ${BFCLI} ruleset get)
echo "$ruleset_output"
echo "$ruleset_output" | grep -q '10.0.0.1'
echo "$ruleset_output" | grep -q '192.168.1.1'
(! echo "$ruleset_output" | grep -q 'elided')

${FROM_NS} ${BFCLI} chain flush --name test_xdp
