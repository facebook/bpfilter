#!/usr/bin/env bash
# Copyright (c) Meta Platforms, Inc. and affiliates.

. "$(dirname "$0")"/../e2e_test_util.sh

${BFCLI} ruleset set --dry-run --from-str "chain test BF_HOOK_XDP ACCEPT rule meta.frag eq none counter DROP"
${BFCLI} ruleset set --dry-run --from-str "chain test BF_HOOK_TC_INGRESS ACCEPT rule meta.frag eq first counter DROP"
${BFCLI} ruleset set --dry-run --from-str "chain test BF_HOOK_NF_LOCAL_IN ACCEPT rule meta.frag eq later counter DROP"
${BFCLI} ruleset set --dry-run --from-str "chain test BF_HOOK_CGROUP_SKB_INGRESS ACCEPT rule meta.frag later counter DROP"
${BFCLI} ruleset set --dry-run --from-str "chain test BF_HOOK_NF_LOCAL_IN ACCEPT rule meta.frag eq LATER counter DROP"
${BFCLI} ruleset set --dry-run --from-str "chain test BF_HOOK_NF_LOCAL_IN ACCEPT rule meta.frag not none counter DROP"
${BFCLI} ruleset set --dry-run --from-str "chain test BF_HOOK_NF_LOCAL_IN ACCEPT rule ip6.snet eq 2001:db8::/32 meta.frag eq later counter ACCEPT"

(! ${BFCLI} ruleset set --dry-run --from-str "chain test BF_HOOK_XDP ACCEPT rule meta.frag eq middle counter DROP")
(! ${BFCLI} ruleset set --dry-run --from-str "chain test BF_HOOK_XDP ACCEPT rule meta.frag eq 1 counter DROP")
(! ${BFCLI} ruleset set --dry-run --from-str "chain test BF_HOOK_XDP ACCEPT rule meta.frag range none-later counter DROP")
(! ${BFCLI} ruleset set --dry-run --from-str "chain test BF_HOOK_XDP ACCEPT rule (meta.frag) in { later } counter DROP")

# cgroup_sock_addr programs don't see packets
(! ${BFCLI} ruleset set --dry-run --from-str "chain test BF_HOOK_CGROUP_SOCK_ADDR_CONNECT4 ACCEPT rule meta.frag eq later counter DROP")
