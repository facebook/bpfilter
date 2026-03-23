#!/usr/bin/env bash

set -eux
set -o pipefail

. "$(dirname "$0")"/../e2e_test_util.sh

# Unsupported hooks: all NF hooks
(! ${BFCLI} ruleset set --dry-run --from-str "chain test BF_HOOK_NF_FORWARD ACCEPT rule meta.flow_probability eq 50% counter DROP")
(! ${BFCLI} ruleset set --dry-run --from-str "chain test BF_HOOK_NF_LOCAL_IN ACCEPT rule meta.flow_probability eq 50% counter DROP")
(! ${BFCLI} ruleset set --dry-run --from-str "chain test BF_HOOK_NF_LOCAL_OUT ACCEPT rule meta.flow_probability eq 50% counter DROP")
(! ${BFCLI} ruleset set --dry-run --from-str "chain test BF_HOOK_NF_POST_ROUTING ACCEPT rule meta.flow_probability eq 50% counter DROP")
(! ${BFCLI} ruleset set --dry-run --from-str "chain test BF_HOOK_NF_PRE_ROUTING ACCEPT rule meta.flow_probability eq 50% counter DROP")

# Supported hooks: XDP, TC, and CGROUP_SKB
${BFCLI} ruleset set --dry-run --from-str "chain test BF_HOOK_XDP ACCEPT rule meta.flow_probability eq 50% counter DROP"
${BFCLI} ruleset set --dry-run --from-str "chain test BF_HOOK_TC_INGRESS ACCEPT rule meta.flow_probability eq 0% counter DROP"
${BFCLI} ruleset set --dry-run --from-str "chain test BF_HOOK_TC_INGRESS ACCEPT rule meta.flow_probability eq 50% counter DROP"
${BFCLI} ruleset set --dry-run --from-str "chain test BF_HOOK_TC_INGRESS ACCEPT rule meta.flow_probability eq 100% counter DROP"
${BFCLI} ruleset set --dry-run --from-str "chain test BF_HOOK_TC_EGRESS ACCEPT rule meta.flow_probability eq 50% counter DROP"
${BFCLI} ruleset set --dry-run --from-str "chain test BF_HOOK_CGROUP_SKB_INGRESS ACCEPT rule meta.flow_probability eq 50% counter DROP"
${BFCLI} ruleset set --dry-run --from-str "chain test BF_HOOK_CGROUP_SKB_EGRESS ACCEPT rule meta.flow_probability eq 50% counter DROP"

# Floating-point percentages
${BFCLI} ruleset set --dry-run --from-str "chain test BF_HOOK_TC_INGRESS ACCEPT rule meta.flow_probability eq 33.33% counter DROP"
${BFCLI} ruleset set --dry-run --from-str "chain test BF_HOOK_TC_INGRESS ACCEPT rule meta.flow_probability eq 0.1% counter DROP"
${BFCLI} ruleset set --dry-run --from-str "chain test BF_HOOK_TC_INGRESS ACCEPT rule meta.flow_probability eq 99.99% counter DROP"
${BFCLI} ruleset set --dry-run --from-str "chain test BF_HOOK_TC_INGRESS ACCEPT rule meta.flow_probability eq 50.0% counter DROP"
${BFCLI} ruleset set --dry-run --from-str "chain test BF_HOOK_TC_INGRESS ACCEPT rule meta.flow_probability eq 0.00% counter DROP"
${BFCLI} ruleset set --dry-run --from-str "chain test BF_HOOK_TC_INGRESS ACCEPT rule meta.flow_probability eq 100.00% counter DROP"

# Invalid probability values
(! ${BFCLI} ruleset set --dry-run --from-str "chain test BF_HOOK_TC_INGRESS ACCEPT rule meta.flow_probability eq 0 counter DROP")
(! ${BFCLI} ruleset set --dry-run --from-str "chain test BF_HOOK_TC_INGRESS ACCEPT rule meta.flow_probability eq -10% counter DROP")
(! ${BFCLI} ruleset set --dry-run --from-str "chain test BF_HOOK_TC_INGRESS ACCEPT rule meta.flow_probability eq 1000 counter DROP")
(! ${BFCLI} ruleset set --dry-run --from-str "chain test BF_HOOK_TC_INGRESS ACCEPT rule meta.flow_probability eq 1000% counter DROP")
(! ${BFCLI} ruleset set --dry-run --from-str "chain test BF_HOOK_TC_INGRESS ACCEPT rule meta.flow_probability eq 100.01% counter DROP")
(! ${BFCLI} ruleset set --dry-run --from-str "chain test BF_HOOK_TC_INGRESS ACCEPT rule meta.flow_probability eq teapot counter DROP")
