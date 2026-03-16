#!/usr/bin/env bash

. "$(dirname "$0")"/../e2e_test_util.sh

# Test valid decimal DSCP values (0-63)
${BFCLI} ruleset set --dry-run --from-str "chain xdp BF_HOOK_XDP ACCEPT rule ip4.dscp eq 0 counter DROP"
${BFCLI} ruleset set --dry-run --from-str "chain xdp BF_HOOK_XDP ACCEPT rule ip4.dscp eq 16 counter DROP"
${BFCLI} ruleset set --dry-run --from-str "chain xdp BF_HOOK_XDP ACCEPT rule ip4.dscp eq 63 counter DROP"

# Test valid hexadecimal values
${BFCLI} ruleset set --dry-run --from-str "chain xdp BF_HOOK_XDP ACCEPT rule ip4.dscp eq 0x00 counter DROP"
${BFCLI} ruleset set --dry-run --from-str "chain xdp BF_HOOK_XDP ACCEPT rule ip4.dscp eq 0x10 counter DROP"
${BFCLI} ruleset set --dry-run --from-str "chain xdp BF_HOOK_XDP ACCEPT rule ip4.dscp eq 0x3f counter DROP"

# Test invalid values (should fail)
(! ${BFCLI} ruleset set --dry-run --from-str "chain xdp BF_HOOK_XDP ACCEPT rule ip4.dscp eq 64 counter DROP")
(! ${BFCLI} ruleset set --dry-run --from-str "chain xdp BF_HOOK_XDP ACCEPT rule ip4.dscp eq 255 counter DROP")
(! ${BFCLI} ruleset set --dry-run --from-str "chain xdp BF_HOOK_XDP ACCEPT rule ip4.dscp eq -1 counter DROP")
(! ${BFCLI} ruleset set --dry-run --from-str "chain xdp BF_HOOK_XDP ACCEPT rule ip4.dscp eq invalid counter DROP")
(! ${BFCLI} ruleset set --dry-run --from-str "chain xdp BF_HOOK_XDP ACCEPT rule ip4.dscp eq 0x40 counter DROP")

# Test valid class name keywords
${BFCLI} ruleset set --dry-run --from-str "chain xdp BF_HOOK_XDP ACCEPT rule ip4.dscp eq ef counter DROP"
${BFCLI} ruleset set --dry-run --from-str "chain xdp BF_HOOK_XDP ACCEPT rule ip4.dscp not cs1 counter DROP"
${BFCLI} ruleset set --dry-run --from-str "chain xdp BF_HOOK_XDP ACCEPT rule ip4.dscp eq AF21 counter DROP"
${BFCLI} ruleset set --dry-run --from-str "chain xdp BF_HOOK_XDP ACCEPT rule ip4.dscp not BE counter DROP"
${BFCLI} ruleset set --dry-run --from-str "chain xdp BF_HOOK_XDP ACCEPT rule ip4.dscp eq voice-admit counter DROP"

# Test invalid class name keywords (should fail)
(! ${BFCLI} ruleset set --dry-run --from-str "chain xdp BF_HOOK_XDP ACCEPT rule ip4.dscp eq cs8 counter DROP")
(! ${BFCLI} ruleset set --dry-run --from-str "chain xdp BF_HOOK_XDP ACCEPT rule ip4.dscp eq AF14 counter DROP")

# Test with 'not' operator
${BFCLI} ruleset set --dry-run --from-str "chain xdp BF_HOOK_XDP ACCEPT rule ip4.dscp not 0 counter DROP"
${BFCLI} ruleset set --dry-run --from-str "chain xdp BF_HOOK_XDP ACCEPT rule ip4.dscp not 16 counter DROP"
${BFCLI} ruleset set --dry-run --from-str "chain xdp BF_HOOK_XDP ACCEPT rule ip4.dscp not 63 counter DROP"
${BFCLI} ruleset set --dry-run --from-str "chain xdp BF_HOOK_XDP ACCEPT rule ip4.dscp not 0x10 counter DROP"

# Test invalid values with 'not' operator (should fail)
(! ${BFCLI} ruleset set --dry-run --from-str "chain xdp BF_HOOK_XDP ACCEPT rule ip4.dscp not 64 counter DROP")
(! ${BFCLI} ruleset set --dry-run --from-str "chain xdp BF_HOOK_XDP ACCEPT rule ip4.dscp not 255 counter DROP")
(! ${BFCLI} ruleset set --dry-run --from-str "chain xdp BF_HOOK_XDP ACCEPT rule ip4.dscp not -1 counter DROP")
(! ${BFCLI} ruleset set --dry-run --from-str "chain xdp BF_HOOK_XDP ACCEPT rule ip4.dscp not invalid counter DROP")
