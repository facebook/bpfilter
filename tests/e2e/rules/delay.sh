#!/usr/bin/env bash

set -eux
set -o pipefail

. "$(dirname "$0")"/../e2e_test_util.sh

make_sandbox
start_bpfilter

# Delay is only supported on TC hooks
(! ${FROM_NS} bfcli chain set --from-str "chain tc_delay BF_HOOK_XDP ACCEPT rule ip4.proto icmp delay 100ms DROP")
(! ${FROM_NS} bfcli chain set --from-str "chain tc_delay BF_HOOK_NF_LOCAL_IN ACCEPT rule ip4.proto icmp delay 100ms DROP")
(! ${FROM_NS} bfcli chain set --from-str "chain tc_delay BF_HOOK_CGROUP_INGRESS ACCEPT rule ip4.proto icmp delay 100ms DROP")

# Invalid delay values
(! ${FROM_NS} bfcli chain set --from-str "chain tc_delay BF_HOOK_TC_INGRESS ACCEPT rule ip4.proto icmp delay DROP")
(! ${FROM_NS} bfcli chain set --from-str "chain tc_delay BF_HOOK_TC_INGRESS ACCEPT rule ip4.proto icmp delay 0ms DROP")
(! ${FROM_NS} bfcli chain set --from-str "chain tc_delay BF_HOOK_TC_INGRESS ACCEPT rule ip4.proto icmp delay -1ms DROP")

# Valid delay on TC ingress and egress
${FROM_NS} bfcli chain set --from-str "chain tc_delay BF_HOOK_TC_INGRESS ACCEPT rule ip4.proto icmp delay 100ms DROP"
${FROM_NS} bfcli chain set --from-str "chain tc_delay BF_HOOK_TC_EGRESS ACCEPT rule ip4.proto icmp delay 50ms DROP"
