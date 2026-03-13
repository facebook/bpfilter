#!/usr/bin/env bash

. "$(dirname "$0")"/../e2e_test_util.sh

get_counter() {
    ${FROM_NS} bpftool map dump pinned ${WORKDIR}/bpf/bpfilter/$1/bf_cmap | jq ".[$2].value.count"
}

make_sandbox

# --- NEXT as chain policy (single chain) ---
# Without a next program in the TCX link, NEXT allows the packet through.
ping -c 1 -W 0.1 ${NS_IP_ADDR}
${FROM_NS} ${BFCLI} chain set --from-str \
    "chain pol_next BF_HOOK_TC_INGRESS{ifindex=${NS_IFINDEX}} NEXT"
ping -c 1 -W 0.1 ${NS_IP_ADDR}
${FROM_NS} ${BFCLI} ruleset flush

# --- NEXT is terminal (stops rule evaluation) ---
# First rule matches ICMP and returns NEXT.
# Second rule also matches ICMP with a counter and returns DROP.
# NEXT is terminal: second rule is never evaluated, counter stays 0, ping
# succeeds (TCX_NEXT with no next program passes the packet).
${FROM_NS} ${BFCLI} chain set --from-str \
    "chain next_term BF_HOOK_TC_INGRESS{ifindex=${NS_IFINDEX}} ACCEPT \
     rule ip4.proto icmp counter NEXT \
     rule ip4.proto icmp counter DROP"
ping -c 1 -W 0.1 ${NS_IP_ADDR}
test "$(get_counter next_term 0)" = "1"
test "$(get_counter next_term 1)" = "0"
${FROM_NS} ${BFCLI} ruleset flush

# --- TC ingress: NEXT defers to the next program ---
# Two chains on the same TC_INGRESS hook. Chain A returns NEXT for ICMP,
# deferring to chain B which drops the packet.
${FROM_NS} ${BFCLI} chain set --from-str \
    "chain ing_next_a BF_HOOK_TC_INGRESS{ifindex=${NS_IFINDEX}} ACCEPT \
     rule ip4.proto icmp counter NEXT"
${FROM_NS} ${BFCLI} chain set --from-str \
    "chain ing_next_b BF_HOOK_TC_INGRESS{ifindex=${NS_IFINDEX}} ACCEPT \
     rule ip4.proto icmp counter DROP"
test "$(get_counter ing_next_a 0)" = "0"
test "$(get_counter ing_next_b 0)" = "0"
(! ping -c 1 -W 0.1 ${NS_IP_ADDR})
test "$(get_counter ing_next_a 0)" = "1"
test "$(get_counter ing_next_b 0)" = "1"
${FROM_NS} ${BFCLI} ruleset flush

# --- TC ingress: ACCEPT does NOT defer to the next program ---
# Same setup but chain A uses ACCEPT. TCX_PASS bypasses chain B entirely.
${FROM_NS} ${BFCLI} chain set --from-str \
    "chain ing_accept_a BF_HOOK_TC_INGRESS{ifindex=${NS_IFINDEX}} ACCEPT \
     rule ip4.proto icmp counter ACCEPT"
${FROM_NS} ${BFCLI} chain set --from-str \
    "chain ing_accept_b BF_HOOK_TC_INGRESS{ifindex=${NS_IFINDEX}} ACCEPT \
     rule ip4.proto icmp counter DROP"
test "$(get_counter ing_accept_a 0)" = "0"
test "$(get_counter ing_accept_b 0)" = "0"
ping -c 1 -W 0.1 ${NS_IP_ADDR}
test "$(get_counter ing_accept_a 0)" = "1"
test "$(get_counter ing_accept_b 0)" = "0"
${FROM_NS} ${BFCLI} ruleset flush

# --- TC ingress: NEXT policy defers to the next program ---
# Chain A has NEXT as default policy (no matching rules), deferring all
# packets to chain B.
${FROM_NS} ${BFCLI} chain set --from-str \
    "chain ing_pol_next BF_HOOK_TC_INGRESS{ifindex=${NS_IFINDEX}} NEXT"
${FROM_NS} ${BFCLI} chain set --from-str \
    "chain ing_pol_drop BF_HOOK_TC_INGRESS{ifindex=${NS_IFINDEX}} ACCEPT \
     rule ip4.proto icmp counter DROP"
test "$(get_counter ing_pol_drop 0)" = "0"
(! ping -c 1 -W 0.1 ${NS_IP_ADDR})
test "$(get_counter ing_pol_drop 0)" = "1"
${FROM_NS} ${BFCLI} ruleset flush

# --- TC egress: NEXT defers to the next program ---
# Same multi-chain test on the egress path. The ICMP echo reply is
# intercepted on its way out of the namespace.
${FROM_NS} ${BFCLI} chain set --from-str \
    "chain egr_next_a BF_HOOK_TC_EGRESS{ifindex=${NS_IFINDEX}} ACCEPT \
     rule ip4.proto icmp counter NEXT"
${FROM_NS} ${BFCLI} chain set --from-str \
    "chain egr_next_b BF_HOOK_TC_EGRESS{ifindex=${NS_IFINDEX}} ACCEPT \
     rule ip4.proto icmp counter DROP"
test "$(get_counter egr_next_a 0)" = "0"
test "$(get_counter egr_next_b 0)" = "0"
(! ping -c 1 -W 0.1 ${NS_IP_ADDR})
test "$(get_counter egr_next_a 0)" = "1"
test "$(get_counter egr_next_b 0)" = "1"
${FROM_NS} ${BFCLI} ruleset flush
