#!/usr/bin/env bash

set -eux
set -o pipefail

. "$(dirname "$0")"/../e2e_test_util.sh

make_sandbox

start_bpfilter
    ${FROM_NS} bfcli chain set --from-str "chain test BF_HOOK_XDP{ifindex=${NS_IFINDEX}} ACCEPT
        set myset (ip4.saddr) in { 192.168.1.1; 192.168.1.2 }
        rule (ip4.saddr) in myset counter DROP"
stop_bpfilter --skip-cleanup

start_bpfilter
    # Verify chain with sets is restored properly
    ${FROM_NS} bfcli chain get --name test
stop_bpfilter
