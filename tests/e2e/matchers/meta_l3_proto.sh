#!/usr/bin/env bash

set -eux
set -o pipefail

. "$(dirname "$0")"/../e2e_test_util.sh

bfcli ruleset set --dry-run --from-str "chain xdp BF_HOOK_XDP ACCEPT rule meta.l3_proto eq ipv4 counter DROP"
bfcli ruleset set --dry-run --from-str "chain xdp BF_HOOK_XDP ACCEPT rule meta.l3_proto eq IPv6 counter DROP"
bfcli ruleset set --dry-run --from-str "chain xdp BF_HOOK_XDP ACCEPT rule meta.l3_proto eq 0 counter DROP"
bfcli ruleset set --dry-run --from-str "chain xdp BF_HOOK_XDP ACCEPT rule meta.l3_proto eq 17 counter DROP"
bfcli ruleset set --dry-run --from-str "chain xdp BF_HOOK_XDP ACCEPT rule meta.l3_proto eq 65535 counter DROP"
bfcli ruleset set --dry-run --from-str "chain xdp BF_HOOK_XDP ACCEPT rule meta.l3_proto eq 0x00 counter DROP"
bfcli ruleset set --dry-run --from-str "chain xdp BF_HOOK_XDP ACCEPT rule meta.l3_proto eq 0x17 counter DROP"
bfcli ruleset set --dry-run --from-str "chain xdp BF_HOOK_XDP ACCEPT rule meta.l3_proto eq 0xffff counter DROP"

(! bfcli ruleset set --dry-run --from-str "chain xdp BF_HOOK_XDP ACCEPT rule meta.l3_proto eq ipv65 counter DROP")
(! bfcli ruleset set --dry-run --from-str "chain xdp BF_HOOK_XDP ACCEPT rule meta.l3_proto eq thisiswaytolongforaprotocolname counter DROP")
(! bfcli ruleset set --dry-run --from-str "chain xdp BF_HOOK_XDP ACCEPT rule meta.l3_proto eq 0xffffff counter DROP")
(! bfcli ruleset set --dry-run --from-str "chain xdp BF_HOOK_XDP ACCEPT rule meta.l3_proto eq -154252 counter DROP")
