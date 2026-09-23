#!/usr/bin/env bash
# Copyright (c) Meta Platforms, Inc. and affiliates.

. "$(dirname "$0")"/../e2e_test_util.sh

${BFCLI} ruleset set --dry-run --from-str "chain test BF_HOOK_CGROUP_SOCK_ADDR_CONNECT4 ACCEPT rule meta.pid eq 1 counter DROP"
${BFCLI} ruleset set --dry-run --from-str "chain test BF_HOOK_CGROUP_SOCK_ADDR_CONNECT6 ACCEPT rule meta.pid eq 1234 counter DROP"
${BFCLI} ruleset set --dry-run --from-str "chain test BF_HOOK_CGROUP_SOCK_ADDR_SENDMSG4 ACCEPT rule meta.pid 1234 counter DROP"
${BFCLI} ruleset set --dry-run --from-str "chain test BF_HOOK_CGROUP_SOCK_ADDR_SENDMSG6 ACCEPT rule meta.pid eq 2147483647 counter DROP"

${BFCLI} ruleset set --dry-run --from-str "chain test BF_HOOK_CGROUP_SOCK_ADDR_CONNECT4 ACCEPT rule meta.pid not 1234 counter DROP"
${BFCLI} ruleset set --dry-run --from-str "chain test BF_HOOK_CGROUP_SOCK_ADDR_CONNECT4 ACCEPT rule meta.pid not eq 1234 counter DROP"

${BFCLI} ruleset set --dry-run --from-str "chain test BF_HOOK_CGROUP_SOCK_ADDR_CONNECT4 ACCEPT rule (meta.pid) in { 1; 1234 } counter DROP"
${BFCLI} ruleset set --dry-run --from-str "chain test BF_HOOK_CGROUP_SOCK_ADDR_CONNECT4 ACCEPT rule (meta.pid) not in { 1234 } counter DROP"
${BFCLI} ruleset set --dry-run --from-str "chain test BF_HOOK_CGROUP_SOCK_ADDR_CONNECT4 ACCEPT rule (ip4.daddr, meta.pid) in { 1.1.1.1, 1234 } counter DROP"

(! ${BFCLI} ruleset set --dry-run --from-str "chain test BF_HOOK_CGROUP_SOCK_ADDR_CONNECT4 ACCEPT rule meta.pid eq 0 counter DROP")
(! ${BFCLI} ruleset set --dry-run --from-str "chain test BF_HOOK_CGROUP_SOCK_ADDR_CONNECT4 ACCEPT rule meta.pid eq -1 counter DROP")
(! ${BFCLI} ruleset set --dry-run --from-str "chain test BF_HOOK_CGROUP_SOCK_ADDR_CONNECT4 ACCEPT rule meta.pid eq 2147483648 counter DROP")
(! ${BFCLI} ruleset set --dry-run --from-str "chain test BF_HOOK_CGROUP_SOCK_ADDR_CONNECT4 ACCEPT rule meta.pid eq 0x10 counter DROP")
(! ${BFCLI} ruleset set --dry-run --from-str "chain test BF_HOOK_CGROUP_SOCK_ADDR_CONNECT4 ACCEPT rule meta.pid eq 12a counter DROP")
(! ${BFCLI} ruleset set --dry-run --from-str "chain test BF_HOOK_CGROUP_SOCK_ADDR_CONNECT4 ACCEPT rule meta.pid eq qw counter DROP")
(! ${BFCLI} ruleset set --dry-run --from-str "chain test BF_HOOK_CGROUP_SOCK_ADDR_CONNECT4 ACCEPT rule meta.pid range 1-10 counter DROP")
(! ${BFCLI} ruleset set --dry-run --from-str "chain test BF_HOOK_CGROUP_SOCK_ADDR_CONNECT4 ACCEPT rule (meta.pid) in { 0 } counter DROP")

# Only cgroup_sock_addr programs run in the context of the process
(! ${BFCLI} ruleset set --dry-run --from-str "chain test BF_HOOK_XDP ACCEPT rule meta.pid eq 1234 counter DROP")
(! ${BFCLI} ruleset set --dry-run --from-str "chain test BF_HOOK_TC_INGRESS ACCEPT rule meta.pid eq 1234 counter DROP")
(! ${BFCLI} ruleset set --dry-run --from-str "chain test BF_HOOK_NF_LOCAL_OUT ACCEPT rule meta.pid eq 1234 counter DROP")
(! ${BFCLI} ruleset set --dry-run --from-str "chain test BF_HOOK_CGROUP_SKB_EGRESS ACCEPT rule meta.pid eq 1234 counter DROP")
(! ${BFCLI} ruleset set --dry-run --from-str "chain test BF_HOOK_CGROUP_SKB_EGRESS ACCEPT rule (meta.pid) in { 1234 } counter DROP")
