#!/usr/bin/env bash

. "$(dirname "$0")"/../e2e_test_util.sh

make_sandbox

PINNED_PROG="${WORKDIR}/bpf/bpfilter/test_chain/bf_prog"

start_bpfilter
    ${FROM_NS} bfcli chain set --from-str "chain test_chain BF_HOOK_XDP{ifindex=${NS_IFINDEX}} ACCEPT"
    ${FROM_NS} ping -c 1 -W 0.1 ${NS_IP_ADDR}
    ${FROM_NS} bfcli ruleset get | grep "^chain" | awk 'END{exit NR!=1}'
    ${FROM_NS} test -e ${PINNED_PROG}

    ${FROM_NS} bfcli chain update --from-str "chain test_chain BF_HOOK_XDP{ifindex=${NS_IFINDEX}} ACCEPT rule meta.l4_proto eq icmp DROP"
    (! ping -c 1 -W 0.1 ${NS_IP_ADDR})
    ${FROM_NS} bfcli ruleset get | grep "^chain" | awk 'END{exit NR!=1}'
    ${FROM_NS} test -e ${PINNED_PROG}
stop_bpfilter --skip-cleanup

start_bpfilter
    ${FROM_NS} bfcli ruleset get | grep "^chain" | awk 'END{exit NR!=1}'
    ${FROM_NS} test -e ${PINNED_PROG}
stop_bpfilter