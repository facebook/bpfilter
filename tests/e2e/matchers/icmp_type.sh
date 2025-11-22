#!/usr/bin/env bash

set -eux
set -o pipefail

. "$(dirname "$0")"/../e2e_test_util.sh

bfcli ruleset set --dry-run --from-str "chain xdp BF_HOOK_XDP ACCEPT rule icmp.type eq echo-reply counter DROP"
bfcli ruleset set --dry-run --from-str "chain xdp BF_HOOK_XDP ACCEPT rule icmp.type eq router-advertisement counter DROP"
bfcli ruleset set --dry-run --from-str "chain xdp BF_HOOK_XDP ACCEPT rule icmp.type eq 0x23 counter DROP"
bfcli ruleset set --dry-run --from-str "chain xdp BF_HOOK_XDP ACCEPT rule icmp.type eq 14 counter DROP"

(! bfcli ruleset set --dry-run --from-str "chain xdp BF_HOOK_XDP ACCEPT rule icmp.type eq echo-repl counter DROP")
(! bfcli ruleset set --dry-run --from-str "chain xdp BF_HOOK_XDP ACCEPT rule icmp.type eq r counter DROP")
(! bfcli ruleset set --dry-run --from-str "chain xdp BF_HOOK_XDP ACCEPT rule icmp.type eq 0xf23 counter DROP")
(! bfcli ruleset set --dry-run --from-str "chain xdp BF_HOOK_XDP ACCEPT rule icmp.type eq -14 counter DROP")
(! bfcli ruleset set --dry-run --from-str "chain xdp BF_HOOK_XDP ACCEPT rule icmp.type eq 45574614 counter DROP")

bfcli ruleset set --dry-run --from-str "chain xdp BF_HOOK_XDP ACCEPT rule icmp.type not echo-reply counter DROP"
bfcli ruleset set --dry-run --from-str "chain xdp BF_HOOK_XDP ACCEPT rule icmp.type not router-advertisement counter DROP"
bfcli ruleset set --dry-run --from-str "chain xdp BF_HOOK_XDP ACCEPT rule icmp.type not 0x23 counter DROP"
bfcli ruleset set --dry-run --from-str "chain xdp BF_HOOK_XDP ACCEPT rule icmp.type not 14 counter DROP"

(! bfcli ruleset set --dry-run --from-str "chain xdp BF_HOOK_XDP ACCEPT rule icmp.type not echo-repl counter DROP")
(! bfcli ruleset set --dry-run --from-str "chain xdp BF_HOOK_XDP ACCEPT rule icmp.type not r counter DROP")
(! bfcli ruleset set --dry-run --from-str "chain xdp BF_HOOK_XDP ACCEPT rule icmp.type not 0xf23 counter DROP")
(! bfcli ruleset set --dry-run --from-str "chain xdp BF_HOOK_XDP ACCEPT rule icmp.type not -14 counter DROP")
(! bfcli ruleset set --dry-run --from-str "chain xdp BF_HOOK_XDP ACCEPT rule icmp.type not 45574614 counter DROP")
