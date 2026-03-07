#!/usr/bin/env bash

. "$(dirname "$0")"/../e2e_test_util.sh

(! ${BFCLI} ruleset set --dry-run --from-str "chain test BF_HOOK_XDP ACCEPT rule meta.mark eq 0 counter DROP")

${BFCLI} ruleset set --dry-run --from-str "chain test BF_HOOK_TC_INGRESS ACCEPT rule meta.mark eq 0 counter DROP"
${BFCLI} ruleset set --dry-run --from-str "chain test BF_HOOK_TC_INGRESS ACCEPT rule meta.mark eq 15 counter DROP"
${BFCLI} ruleset set --dry-run --from-str "chain test BF_HOOK_TC_INGRESS ACCEPT rule meta.mark eq 0x00 counter DROP"
${BFCLI} ruleset set --dry-run --from-str "chain test BF_HOOK_TC_INGRESS ACCEPT rule meta.mark eq 0xffffffff counter DROP"

(! ${BFCLI} ruleset set --dry-run --from-str "chain test BF_HOOK_TC_INGRESS ACCEPT rule meta.mark eq -1 counter DROP")
(! ${BFCLI} ruleset set --dry-run --from-str "chain test BF_HOOK_TC_INGRESS ACCEPT rule meta.mark eq 0xffffffffff counter DROP")
(! ${BFCLI} ruleset set --dry-run --from-str "chain test BF_HOOK_TC_INGRESS ACCEPT rule meta.mark eq 1qw counter DROP")
(! ${BFCLI} ruleset set --dry-run --from-str "chain test BF_HOOK_TC_INGRESS ACCEPT rule meta.mark eq qw counter DROP")
