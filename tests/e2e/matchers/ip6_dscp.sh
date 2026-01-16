#!/usr/bin/env bash

set -eux
set -o pipefail

. "$(dirname "$0")"/../e2e_test_util.sh

# Test valid decimal values with 'eq' operator
bfcli ruleset set --dry-run --from-str "chain xdp BF_HOOK_XDP ACCEPT rule ip6.dscp eq 0 counter DROP"
bfcli ruleset set --dry-run --from-str "chain xdp BF_HOOK_XDP ACCEPT rule ip6.dscp eq 46 counter DROP"
bfcli ruleset set --dry-run --from-str "chain xdp BF_HOOK_XDP ACCEPT rule ip6.dscp eq 255 counter DROP"

# Test valid hexadecimal values with 'eq' operator
bfcli ruleset set --dry-run --from-str "chain xdp BF_HOOK_XDP ACCEPT rule ip6.dscp eq 0x00 counter DROP"
bfcli ruleset set --dry-run --from-str "chain xdp BF_HOOK_XDP ACCEPT rule ip6.dscp eq 0x2e counter DROP"
bfcli ruleset set --dry-run --from-str "chain xdp BF_HOOK_XDP ACCEPT rule ip6.dscp eq 0xff counter DROP"

# Test invalid values with 'eq' operator (should fail)
(! bfcli ruleset set --dry-run --from-str "chain xdp BF_HOOK_XDP ACCEPT rule ip6.dscp eq abc counter DROP")
(! bfcli ruleset set --dry-run --from-str "chain xdp BF_HOOK_XDP ACCEPT rule ip6.dscp eq -1 counter DROP")
(! bfcli ruleset set --dry-run --from-str "chain xdp BF_HOOK_XDP ACCEPT rule ip6.dscp eq 256 counter DROP")
(! bfcli ruleset set --dry-run --from-str "chain xdp BF_HOOK_XDP ACCEPT rule ip6.dscp eq -0x01 counter DROP")
(! bfcli ruleset set --dry-run --from-str "chain xdp BF_HOOK_XDP ACCEPT rule ip6.dscp eq 0x100 counter DROP")

# Test valid decimal values with 'not' operator
bfcli ruleset set --dry-run --from-str "chain xdp BF_HOOK_XDP ACCEPT rule ip6.dscp not 0 counter DROP"
bfcli ruleset set --dry-run --from-str "chain xdp BF_HOOK_XDP ACCEPT rule ip6.dscp not 46 counter DROP"
bfcli ruleset set --dry-run --from-str "chain xdp BF_HOOK_XDP ACCEPT rule ip6.dscp not 255 counter DROP"

# Test valid hexadecimal values with 'not' operator
bfcli ruleset set --dry-run --from-str "chain xdp BF_HOOK_XDP ACCEPT rule ip6.dscp not 0x00 counter DROP"
bfcli ruleset set --dry-run --from-str "chain xdp BF_HOOK_XDP ACCEPT rule ip6.dscp not 0x2e counter DROP"
bfcli ruleset set --dry-run --from-str "chain xdp BF_HOOK_XDP ACCEPT rule ip6.dscp not 0xff counter DROP"

# Test invalid values with 'not' operator (should fail)
(! bfcli ruleset set --dry-run --from-str "chain xdp BF_HOOK_XDP ACCEPT rule ip6.dscp not abc counter DROP")
(! bfcli ruleset set --dry-run --from-str "chain xdp BF_HOOK_XDP ACCEPT rule ip6.dscp not -1 counter DROP")
(! bfcli ruleset set --dry-run --from-str "chain xdp BF_HOOK_XDP ACCEPT rule ip6.dscp not 256 counter DROP")
(! bfcli ruleset set --dry-run --from-str "chain xdp BF_HOOK_XDP ACCEPT rule ip6.dscp not -0x01 counter DROP")
(! bfcli ruleset set --dry-run --from-str "chain xdp BF_HOOK_XDP ACCEPT rule ip6.dscp not 0x100 counter DROP")
