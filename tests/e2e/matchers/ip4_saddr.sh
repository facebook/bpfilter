#!/usr/bin/env bash

set -eux
set -o pipefail

. "$(dirname "$0")"/../e2e_test_util.sh

bfcli ruleset set --dry-run --from-str "chain xdp BF_HOOK_XDP ACCEPT rule ip4.saddr eq 1.1.1.1 counter DROP"
bfcli ruleset set --dry-run --from-str "chain xdp BF_HOOK_XDP ACCEPT rule ip4.saddr eq 255.255.255.255 counter DROP"

(! bfcli ruleset set --dry-run --from-str "chain xdp BF_HOOK_XDP ACCEPT rule ip4.saddr eq notanip counter DROP")
(! bfcli ruleset set --dry-run --from-str "chain xdp BF_HOOK_XDP ACCEPT rule ip4.saddr eq 1.1.1.1.1 counter DROP")
(! bfcli ruleset set --dry-run --from-str "chain xdp BF_HOOK_XDP ACCEPT rule ip4.saddr eq 1.1.1.1/24 counter DROP")
(! bfcli ruleset set --dry-run --from-str "chain xdp BF_HOOK_XDP ACCEPT rule ip4.saddr eq -1.1.1.1 counter DROP")

bfcli ruleset set --dry-run --from-str "chain xdp BF_HOOK_XDP ACCEPT rule ip4.saddr not 1.1.1.1 counter DROP"
bfcli ruleset set --dry-run --from-str "chain xdp BF_HOOK_XDP ACCEPT rule ip4.saddr not 255.255.255.255 counter DROP"

(! bfcli ruleset set --dry-run --from-str "chain xdp BF_HOOK_XDP ACCEPT rule ip4.saddr not notanip counter DROP")
(! bfcli ruleset set --dry-run --from-str "chain xdp BF_HOOK_XDP ACCEPT rule ip4.saddr not 1.1.1.1.1 counter DROP")
(! bfcli ruleset set --dry-run --from-str "chain xdp BF_HOOK_XDP ACCEPT rule ip4.saddr not 1.1.1.1/24 counter DROP")
(! bfcli ruleset set --dry-run --from-str "chain xdp BF_HOOK_XDP ACCEPT rule ip4.saddr not -1.1.1.1 counter DROP")
