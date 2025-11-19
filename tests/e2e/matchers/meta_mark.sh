#!/usr/bin/env bash

bfcli ruleset set --dry-run --from-str "chain test BF_HOOK_TC_INGRESS ACCEPT rule meta.mark eq 0 counter DROP"
bfcli ruleset set --dry-run --from-str "chain test BF_HOOK_TC_INGRESS ACCEPT rule meta.mark eq 15 counter DROP"
bfcli ruleset set --dry-run --from-str "chain test BF_HOOK_TC_INGRESS ACCEPT rule meta.mark eq 0x00 counter DROP"
bfcli ruleset set --dry-run --from-str "chain test BF_HOOK_TC_INGRESS ACCEPT rule meta.mark eq 0xffffffff counter DROP"

(! bfcli ruleset set --dry-run --from-str "chain test BF_HOOK_TC_INGRESS ACCEPT rule meta.mark eq -1 counter DROP")
(! bfcli ruleset set --dry-run --from-str "chain test BF_HOOK_TC_INGRESS ACCEPT rule meta.mark eq 0xffffffffff counter DROP")
(! bfcli ruleset set --dry-run --from-str "chain test BF_HOOK_TC_INGRESS ACCEPT rule meta.mark eq 1qw counter DROP")
(! bfcli ruleset set --dry-run --from-str "chain test BF_HOOK_TC_INGRESS ACCEPT rule meta.mark eq qw counter DROP")
