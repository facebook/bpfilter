#!/usr/bin/env bash

. "$(dirname "$0")"/../e2e_test_util.sh

(! bfcli ruleset set --dry-run --from-str "chain test BF_HOOK_XDP ACCEPT rule meta.flow_hash eq 0 counter DROP")
(! bfcli ruleset set --dry-run --from-str "chain test BF_HOOK_CGROUP_INGRESS ACCEPT rule meta.flow_hash eq 0 counter DROP")
(! bfcli ruleset set --dry-run --from-str "chain test BF_HOOK_CGROUP_EGRESS ACCEPT rule meta.flow_hash eq 0 counter DROP")
(! bfcli ruleset set --dry-run --from-str "chain test BF_HOOK_NF_FORWARD ACCEPT rule meta.flow_hash eq 0 counter DROP")
(! bfcli ruleset set --dry-run --from-str "chain test BF_HOOK_NF_LOCAL_IN ACCEPT rule meta.flow_hash eq 0 counter DROP")
(! bfcli ruleset set --dry-run --from-str "chain test BF_HOOK_NF_LOCAL_OUT ACCEPT rule meta.flow_hash eq 0 counter DROP")
(! bfcli ruleset set --dry-run --from-str "chain test BF_HOOK_NF_POST_ROUTING ACCEPT rule meta.flow_hash eq 0 counter DROP")
(! bfcli ruleset set --dry-run --from-str "chain test BF_HOOK_NF_PRE_ROUTING ACCEPT rule meta.flow_hash eq 0 counter DROP")

bfcli ruleset set --dry-run --from-str "chain test BF_HOOK_TC_INGRESS ACCEPT rule meta.flow_hash eq 0 counter DROP"
bfcli ruleset set --dry-run --from-str "chain test BF_HOOK_TC_INGRESS ACCEPT rule meta.flow_hash eq 4294967295 counter DROP"
bfcli ruleset set --dry-run --from-str "chain test BF_HOOK_TC_INGRESS ACCEPT rule meta.flow_hash eq 0x00 counter DROP"
bfcli ruleset set --dry-run --from-str "chain test BF_HOOK_TC_INGRESS ACCEPT rule meta.flow_hash eq 0x0 counter DROP"
bfcli ruleset set --dry-run --from-str "chain test BF_HOOK_TC_INGRESS ACCEPT rule meta.flow_hash eq 0xffffffff counter DROP"
bfcli ruleset set --dry-run --from-str "chain test BF_HOOK_TC_INGRESS ACCEPT rule meta.flow_hash eq 0xeff counter DROP"

(! bfcli ruleset set --dry-run --from-str "chain test BF_HOOK_TC_INGRESS ACCEPT rule meta.flow_hash eq -1 counter DROP")
(! bfcli ruleset set --dry-run --from-str "chain test BF_HOOK_TC_INGRESS ACCEPT rule meta.flow_hash eq 0xfffffffff counter DROP")
(! bfcli ruleset set --dry-run --from-str "chain test BF_HOOK_TC_INGRESS ACCEPT rule meta.flow_hash eq 1qw counter DROP")
(! bfcli ruleset set --dry-run --from-str "chain test BF_HOOK_TC_INGRESS ACCEPT rule meta.flow_hash eq qw counter DROP")
(! bfcli ruleset set --dry-run --from-str "chain test BF_HOOK_TC_INGRESS ACCEPT rule meta.flow_hash eq 0x counter DROP")

bfcli ruleset set --dry-run --from-str "chain test BF_HOOK_TC_INGRESS ACCEPT rule meta.flow_hash not 0 counter DROP"
bfcli ruleset set --dry-run --from-str "chain test BF_HOOK_TC_INGRESS ACCEPT rule meta.flow_hash not 4294967295 counter DROP"
bfcli ruleset set --dry-run --from-str "chain test BF_HOOK_TC_INGRESS ACCEPT rule meta.flow_hash not 0x00 counter DROP"
bfcli ruleset set --dry-run --from-str "chain test BF_HOOK_TC_INGRESS ACCEPT rule meta.flow_hash not 0x0 counter DROP"
bfcli ruleset set --dry-run --from-str "chain test BF_HOOK_TC_INGRESS ACCEPT rule meta.flow_hash not 0xffffffff counter DROP"
bfcli ruleset set --dry-run --from-str "chain test BF_HOOK_TC_INGRESS ACCEPT rule meta.flow_hash not 0xeff counter DROP"

(! bfcli ruleset set --dry-run --from-str "chain test BF_HOOK_TC_INGRESS ACCEPT rule meta.flow_hash not -1 counter DROP")
(! bfcli ruleset set --dry-run --from-str "chain test BF_HOOK_TC_INGRESS ACCEPT rule meta.flow_hash not 0xfffffffff counter DROP")
(! bfcli ruleset set --dry-run --from-str "chain test BF_HOOK_TC_INGRESS ACCEPT rule meta.flow_hash not 1qw counter DROP")
(! bfcli ruleset set --dry-run --from-str "chain test BF_HOOK_TC_INGRESS ACCEPT rule meta.flow_hash not qw counter DROP")
(! bfcli ruleset set --dry-run --from-str "chain test BF_HOOK_TC_INGRESS ACCEPT rule meta.flow_hash not 0x counter DROP")

bfcli ruleset set --dry-run --from-str "chain test BF_HOOK_TC_INGRESS ACCEPT rule meta.flow_hash range 0-0 counter DROP"
bfcli ruleset set --dry-run --from-str "chain test BF_HOOK_TC_INGRESS ACCEPT rule meta.flow_hash range 0-4294967295 counter DROP"
bfcli ruleset set --dry-run --from-str "chain test BF_HOOK_TC_INGRESS ACCEPT rule meta.flow_hash range 4294967294-4294967295 counter DROP"
bfcli ruleset set --dry-run --from-str "chain test BF_HOOK_TC_INGRESS ACCEPT rule meta.flow_hash range 4294967295-4294967295 counter DROP"
bfcli ruleset set --dry-run --from-str "chain test BF_HOOK_TC_INGRESS ACCEPT rule meta.flow_hash range 0x0-0x0 counter DROP"
bfcli ruleset set --dry-run --from-str "chain test BF_HOOK_TC_INGRESS ACCEPT rule meta.flow_hash range 0x0-0xffffffff counter DROP"
bfcli ruleset set --dry-run --from-str "chain test BF_HOOK_TC_INGRESS ACCEPT rule meta.flow_hash range 0xfffffffe-0xffffffff counter DROP"
bfcli ruleset set --dry-run --from-str "chain test BF_HOOK_TC_INGRESS ACCEPT rule meta.flow_hash range 0xffffffff-0xffffffff counter DROP"

(! bfcli ruleset set --dry-run --from-str "chain test BF_HOOK_TC_INGRESS ACCEPT rule meta.flow_hash range 1-0x00 counter DROP")
(! bfcli ruleset set --dry-run --from-str "chain test BF_HOOK_TC_INGRESS ACCEPT rule meta.flow_hash range 0x01-0x00 counter DROP")
(! bfcli ruleset set --dry-run --from-str "chain test BF_HOOK_TC_INGRESS ACCEPT rule meta.flow_hash range 0x-0x counter DROP")
(! bfcli ruleset set --dry-run --from-str "chain test BF_HOOK_TC_INGRESS ACCEPT rule meta.flow_hash range 0 counter DROP")
