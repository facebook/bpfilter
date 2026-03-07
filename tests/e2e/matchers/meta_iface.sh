#!/usr/bin/env bash

. "$(dirname "$0")"/../e2e_test_util.sh

${BFCLI} ruleset set --dry-run --from-str "chain xdp BF_HOOK_XDP ACCEPT rule meta.iface eq lo counter DROP"
${BFCLI} ruleset set --dry-run --from-str "chain xdp BF_HOOK_XDP ACCEPT rule meta.iface eq 1 counter DROP"
${BFCLI} ruleset set --dry-run --from-str "chain xdp BF_HOOK_XDP ACCEPT rule meta.iface eq 01 counter DROP"
${BFCLI} ruleset set --dry-run --from-str "chain xdp BF_HOOK_XDP ACCEPT rule meta.iface eq 4294967294 counter DROP"

(! ${BFCLI} ruleset set --dry-run --from-str "chain xdp BF_HOOK_XDP ACCEPT rule meta.iface eq 0x10 counter DROP")
(! ${BFCLI} ruleset set --dry-run --from-str "chain xdp BF_HOOK_XDP ACCEPT rule meta.iface eq -1 counter DROP")
(! ${BFCLI} ruleset set --dry-run --from-str "chain xdp BF_HOOK_XDP ACCEPT rule meta.iface eq 42949672941 counter DROP")
(! ${BFCLI} ruleset set --dry-run --from-str "chain xdp BF_HOOK_XDP ACCEPT rule meta.iface eq -2147483646 counter DROP")
(! ${BFCLI} ruleset set --dry-run --from-str "chain xdp BF_HOOK_XDP ACCEPT rule meta.iface eq -1 counter DROP")
(! ${BFCLI} ruleset set --dry-run --from-str "chain xdp BF_HOOK_XDP ACCEPT rule meta.iface eq -100 counter DROP")
(! ${BFCLI} ruleset set --dry-run --from-str "chain xdp BF_HOOK_XDP ACCEPT rule meta.iface eq 0 counter DROP")
(! ${BFCLI} ruleset set --dry-run --from-str "chain xdp BF_HOOK_XDP ACCEPT rule meta.iface eq noiface counter DROP")
(! ${BFCLI} ruleset set --dry-run --from-str "chain xdp BF_HOOK_XDP ACCEPT rule meta.iface eq iface_name_is_too_long counter DROP")
