#!/usr/bin/env bash

set -eux
set -o pipefail

. "$(dirname "$0")"/../e2e_test_util.sh

make_sandbox

start_bpfilter
    ${FROM_NS} bfcli chain set --from-str "chain test_chain BF_HOOK_XDP{ifindex=${NS_IFINDEX}} ACCEPT"
stop_bpfilter --skip-cleanup

start_bpfilter
    # Ensure it's restored properly
    ${FROM_NS} bfcli chain set --from-str "chain test_chain BF_HOOK_XDP{ifindex=${NS_IFINDEX}} ACCEPT"
stop_bpfilter