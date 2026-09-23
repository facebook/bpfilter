#!/usr/bin/env bash
# Copyright (c) Meta Platforms, Inc. and affiliates.

. "$(dirname "$0")"/../e2e_test_util.sh

# min-size is accepted on named sets
${BFCLI} ruleset set --dry-run --from-str "chain xdp BF_HOOK_XDP ACCEPT
    set myset (ip4.saddr) min-size=4096 in {
        192.168.1.1;
        192.168.1.2
    }
    rule
        (ip4.saddr) in myset
        counter
        ACCEPT
"

# min-size=0 is the default: size the map to fit the elements
${BFCLI} ruleset set --dry-run --from-str "chain xdp BF_HOOK_XDP ACCEPT
    set myset (ip4.saddr) min-size=0 in { 192.168.1.1 }
    rule (ip4.saddr) in myset ACCEPT
"

# min-size is accepted on empty sets
${BFCLI} ruleset set --dry-run --from-str "chain xdp BF_HOOK_XDP ACCEPT
    set myset (ip4.saddr) min-size=128 in {}
    rule (ip4.saddr) in myset ACCEPT
"

# min-size is accepted on compound keys and LPM trie sets
${BFCLI} ruleset set --dry-run --from-str "chain xdp BF_HOOK_XDP ACCEPT
    set myset (ip4.saddr, tcp.sport) min-size=16 in { 192.168.1.1, 80 }
    rule (ip4.saddr, tcp.sport) in myset ACCEPT
"
${BFCLI} ruleset set --dry-run --from-str "chain xdp BF_HOOK_XDP ACCEPT
    set myset (ip4.snet) min-size=16 in { 192.168.1.0/24 }
    rule (ip4.snet) in myset ACCEPT
"

# min-size is limited to 32 bits
(! ${BFCLI} ruleset set --dry-run --from-str "chain xdp BF_HOOK_XDP ACCEPT
    set myset (ip4.saddr) min-size=4294967296 in { 192.168.1.1 }
    rule (ip4.saddr) in myset ACCEPT
")

# min-size is not supported on anonymous sets
(! ${BFCLI} ruleset set --dry-run --from-str "chain xdp BF_HOOK_XDP ACCEPT
    rule (ip4.saddr) min-size=10 in { 192.168.1.1 } ACCEPT
")

# Malformed min-size values are rejected
(! ${BFCLI} ruleset set --dry-run --from-str "chain xdp BF_HOOK_XDP ACCEPT
    set myset (ip4.saddr) min-size=abc in { 192.168.1.1 }
    rule (ip4.saddr) in myset ACCEPT
")
(! ${BFCLI} ruleset set --dry-run --from-str "chain xdp BF_HOOK_XDP ACCEPT
    set myset (ip4.saddr) min-size= in { 192.168.1.1 }
    rule (ip4.saddr) in myset ACCEPT
")
(! ${BFCLI} ruleset set --dry-run --from-str "chain xdp BF_HOOK_XDP ACCEPT
    set myset (ip4.saddr) min-size=-1 in { 192.168.1.1 }
    rule (ip4.saddr) in myset ACCEPT
")
