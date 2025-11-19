#!/usr/bin/env bash

set -eux
set -o pipefail

. "$(dirname "$0")"/../e2e_test_util.sh

make_sandbox

start_bpfilter
    echo "before"
    bpftool prog
    ${FROM_NS} bfcli chain set --from-str "chain test_chain BF_HOOK_XDP{ifindex=${NS_IFINDEX}} ACCEPT"
    ${FROM_NS} ping -c 1 -W 0.1 ${NS_IP_ADDR}
    ${FROM_NS} bfcli ruleset get | grep "^chain" | awk 'END{exit NR!=1}'
    echo "after"
    bpftool prog
    bpftool prog | grep "name bf_prog" | awk 'END{exit NR!=1}'

    echo "before update"
    bpftool prog
    ${FROM_NS} bfcli chain update --from-str "chain test_chain BF_HOOK_XDP{ifindex=${NS_IFINDEX}} ACCEPT rule meta.l4_proto eq icmp DROP"
    (! ping -c 1 -W 0.1 ${NS_IP_ADDR})
    ${FROM_NS} bfcli ruleset get | grep "^chain" | awk 'END{exit NR!=1}'
    echo "after update"
    bpftool prog
    bpftool prog | grep "name bf_prog" | awk 'END{exit NR!=1}'
stop_bpfilter

start_bpfilter
    echo "before reboot"
    bpftool prog
    ${FROM_NS} bfcli ruleset get | grep "^chain" | awk 'END{exit NR!=1}'
    bpftool prog | grep "name bf_prog" | awk 'END{exit NR!=1}'
stop_bpfilter