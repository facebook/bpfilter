#!/usr/bin/env bash

. "$(dirname "$0")"/../e2e_test_util.sh

make_sandbox

PINNED_PROG="${WORKDIR}/bpf/bpfilter/test_chain/bf_prog"

# Create attached chain, verify filtering and pinned program
${FROM_NS} ${BFCLI} chain set --from-str "chain test_chain BF_HOOK_XDP{ifindex=${NS_IFINDEX}} ACCEPT"
ping -c 1 -W 0.1 ${NS_IP_ADDR}
${FROM_NS} ${BFCLI} ruleset get | grep "^chain" | awk 'END{exit NR!=1}'
${FROM_NS} test -e ${PINNED_PROG}

# Update chain, verify pinned program persists
${FROM_NS} ${BFCLI} chain update --from-str "chain test_chain BF_HOOK_XDP{ifindex=${NS_IFINDEX}} ACCEPT rule meta.l4_proto eq icmp DROP"
(! ping -c 1 -W 0.1 ${NS_IP_ADDR})
${FROM_NS} ${BFCLI} ruleset get | grep "^chain" | awk 'END{exit NR!=1}'
${FROM_NS} test -e ${PINNED_PROG}

# Chain is still discoverable from bpffs after update
${FROM_NS} ${BFCLI} ruleset get | grep "^chain" | awk 'END{exit NR!=1}'
${FROM_NS} test -e ${PINNED_PROG}

${FROM_NS} ${BFCLI} chain flush --name test_chain
