#!/usr/bin/env bash
# Copyright (c) Meta Platforms, Inc. and affiliates.

. "$(dirname "$0")"/../e2e_test_util.sh

make_sandbox

# Print the max_entries of chain NAME's single set map.
#
# Usage: get_set_map_entries NAME
get_set_map_entries() {
    local pin
    pin=$(${FROM_NS} find ${WORKDIR}/bpf/bpfilter/$1/ -name 'bf_set_*')
    ${FROM_NS} bpftool -j map show pinned "${pin}" | jq '.max_entries'
}

# The set map reserves room for min-size elements
${FROM_NS} ${BFCLI} chain set --from-str "chain minsize BF_HOOK_XDP ACCEPT
    set blocklist (ip4.saddr) min-size=64 in { 192.0.2.1; 192.0.2.2 }
    rule (ip4.saddr) in blocklist counter DROP"
test "$(get_set_map_entries minsize)" = "64"
${FROM_NS} ${BFCLI} chain flush --name minsize

# A set with more elements than min-size is sized to its content
${FROM_NS} ${BFCLI} chain set --from-str "chain content BF_HOOK_XDP ACCEPT
    set blocklist (ip4.saddr) min-size=2 in { 192.0.2.1; 192.0.2.2; 192.0.2.3 }
    rule (ip4.saddr) in blocklist counter DROP"
test "$(get_set_map_entries content)" = "3"
${FROM_NS} ${BFCLI} chain flush --name content

# Grouped sets don't borrow reserved room from each other: each set
# contributes max(min-size, element count) to the shared map.
${FROM_NS} ${BFCLI} chain set --from-str "chain grouped BF_HOOK_XDP ACCEPT
    set a (ip4.saddr) min-size=10 in { 192.0.2.1 }
    set b (ip4.saddr) in { 192.0.2.2; 192.0.2.3 }
    rule (ip4.saddr) in a counter DROP
    rule (ip4.saddr) in b counter DROP"
test "$(get_set_map_entries grouped)" = "12"
${FROM_NS} ${BFCLI} chain flush --name grouped

# min-size applies to LPM trie maps too
${FROM_NS} ${BFCLI} chain set --from-str "chain trie BF_HOOK_XDP ACCEPT
    set nets (ip4.snet) min-size=32 in { 192.0.2.0/24 }
    rule (ip4.snet) in nets counter DROP"
test "$(get_set_map_entries trie)" = "32"
${FROM_NS} ${BFCLI} chain flush --name trie

# A set can grow past its min-size through update-set, and the declared
# min-size is preserved, not inflated by the set's content
${FROM_NS} ${BFCLI} chain set --from-str "chain grow BF_HOOK_XDP ACCEPT
    set blocklist (ip4.saddr) min-size=3 in { 192.0.2.1; 192.0.2.2 }
    rule (ip4.saddr) in blocklist counter DROP"
test "$(get_set_map_entries grow)" = "3"

${FROM_NS} ${BFCLI} chain update-set \
    --name grow \
    --set-name blocklist \
    --add 192.0.2.3 --add 192.0.2.4
test "$(get_set_map_entries grow)" = "4"

chain_output=$(${FROM_NS} ${BFCLI} chain get --name grow)
echo "$chain_output"
echo "$chain_output" | grep -q 'min-size=3'
${FROM_NS} ${BFCLI} chain flush --name grow

# An empty set creates no map; the reservation takes effect once the set
# becomes non-empty
${FROM_NS} ${BFCLI} chain set --from-str "chain lazy BF_HOOK_XDP ACCEPT
    set blocklist (ip4.saddr) min-size=16 in {}
    rule (ip4.saddr) in blocklist counter DROP"
count=$(${FROM_NS} find ${WORKDIR}/bpf/bpfilter/lazy/ -name 'bf_set_*' | wc -l)
test "${count}" -eq 0

${FROM_NS} ${BFCLI} chain update-set \
    --name lazy \
    --set-name blocklist \
    --add 192.0.2.1
test "$(get_set_map_entries lazy)" = "16"
${FROM_NS} ${BFCLI} chain flush --name lazy
