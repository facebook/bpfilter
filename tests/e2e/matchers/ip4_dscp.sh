#!/usr/bin/env bash

. "$(dirname "$0")"/../e2e_test_util.sh

# Test valid decimal values
bfcli ruleset set --dry-run --from-str "chain xdp BF_HOOK_XDP ACCEPT rule ip4.dscp eq 0 counter DROP"
bfcli ruleset set --dry-run --from-str "chain xdp BF_HOOK_XDP ACCEPT rule ip4.dscp eq 16 counter DROP"
bfcli ruleset set --dry-run --from-str "chain xdp BF_HOOK_XDP ACCEPT rule ip4.dscp eq 255 counter DROP"

# Test valid hexadecimal values
bfcli ruleset set --dry-run --from-str "chain xdp BF_HOOK_XDP ACCEPT rule ip4.dscp eq 0x00 counter DROP"
bfcli ruleset set --dry-run --from-str "chain xdp BF_HOOK_XDP ACCEPT rule ip4.dscp eq 0x10 counter DROP"
bfcli ruleset set --dry-run --from-str "chain xdp BF_HOOK_XDP ACCEPT rule ip4.dscp eq 0xff counter DROP"

# Test invalid values (should fail)
(! bfcli ruleset set --dry-run --from-str "chain xdp BF_HOOK_XDP ACCEPT rule ip4.dscp eq 256 counter DROP")
(! bfcli ruleset set --dry-run --from-str "chain xdp BF_HOOK_XDP ACCEPT rule ip4.dscp eq -1 counter DROP")
(! bfcli ruleset set --dry-run --from-str "chain xdp BF_HOOK_XDP ACCEPT rule ip4.dscp eq invalid counter DROP")
(! bfcli ruleset set --dry-run --from-str "chain xdp BF_HOOK_XDP ACCEPT rule ip4.dscp eq 0x100 counter DROP")

# Test with 'not' operator
bfcli ruleset set --dry-run --from-str "chain xdp BF_HOOK_XDP ACCEPT rule ip4.dscp not 0 counter DROP"
bfcli ruleset set --dry-run --from-str "chain xdp BF_HOOK_XDP ACCEPT rule ip4.dscp not 16 counter DROP"
bfcli ruleset set --dry-run --from-str "chain xdp BF_HOOK_XDP ACCEPT rule ip4.dscp not 255 counter DROP"
bfcli ruleset set --dry-run --from-str "chain xdp BF_HOOK_XDP ACCEPT rule ip4.dscp not 0x10 counter DROP"

# Test invalid values with 'not' operator (should fail)
(! bfcli ruleset set --dry-run --from-str "chain xdp BF_HOOK_XDP ACCEPT rule ip4.dscp not 256 counter DROP")
(! bfcli ruleset set --dry-run --from-str "chain xdp BF_HOOK_XDP ACCEPT rule ip4.dscp not -1 counter DROP")
(! bfcli ruleset set --dry-run --from-str "chain xdp BF_HOOK_XDP ACCEPT rule ip4.dscp not invalid counter DROP")
