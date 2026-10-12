#!/usr/bin/env bash
# Copyright (c) Meta Platforms, Inc. and affiliates.

. "$(dirname "$0")"/../e2e_test_util.sh

${BFCLI} ruleset set --dry-run --from-str "chain xdp BF_HOOK_XDP ACCEPT rule ip6.nexthdr eq icmp counter DROP"
${BFCLI} ruleset set --dry-run --from-str "chain xdp BF_HOOK_XDP ACCEPT rule ip6.nexthdr eq hop counter DROP"
${BFCLI} ruleset set --dry-run --from-str "chain xdp BF_HOOK_XDP ACCEPT rule ip6.nexthdr eq HOP counter DROP"
${BFCLI} ruleset set --dry-run --from-str "chain xdp BF_HOOK_XDP ACCEPT rule ip6.nexthdr eq 17 counter DROP"
${BFCLI} ruleset set --dry-run --from-str "chain xdp BF_HOOK_XDP ACCEPT rule ip6.nexthdr eq 255 counter DROP"

(! ${BFCLI} ruleset set --dry-run --from-str "chain xdp BF_HOOK_XDP ACCEPT rule ip6.nexthdr eq ipv4 counter DROP")
(! ${BFCLI} ruleset set --dry-run --from-str "chain xdp BF_HOOK_XDP ACCEPT rule ip6.nexthdr eq imcp counter DROP")
(! ${BFCLI} ruleset set --dry-run --from-str "chain xdp BF_HOOK_XDP ACCEPT rule ip6.nexthdr eq 0x342 counter DROP")
(! ${BFCLI} ruleset set --dry-run --from-str "chain xdp BF_HOOK_XDP ACCEPT rule ip6.nexthdr eq -18 counter DROP")
(! ${BFCLI} ruleset set --dry-run --from-str "chain xdp BF_HOOK_XDP ACCEPT rule ip6.nexthdr eq 256 counter DROP")

${BFCLI} ruleset set --dry-run --from-str "chain xdp BF_HOOK_XDP ACCEPT rule ip6.nexthdr not icmp counter DROP"
${BFCLI} ruleset set --dry-run --from-str "chain xdp BF_HOOK_XDP ACCEPT rule ip6.nexthdr not hop counter DROP"
${BFCLI} ruleset set --dry-run --from-str "chain xdp BF_HOOK_XDP ACCEPT rule ip6.nexthdr not HOP counter DROP"
${BFCLI} ruleset set --dry-run --from-str "chain xdp BF_HOOK_XDP ACCEPT rule ip6.nexthdr not 17 counter DROP"
${BFCLI} ruleset set --dry-run --from-str "chain xdp BF_HOOK_XDP ACCEPT rule ip6.nexthdr not 255 counter DROP"

(! ${BFCLI} ruleset set --dry-run --from-str "chain xdp BF_HOOK_XDP ACCEPT rule ip6.nexthdr not ipv4 counter DROP")
(! ${BFCLI} ruleset set --dry-run --from-str "chain xdp BF_HOOK_XDP ACCEPT rule ip6.nexthdr not imcp counter DROP")
(! ${BFCLI} ruleset set --dry-run --from-str "chain xdp BF_HOOK_XDP ACCEPT rule ip6.nexthdr not 0x342 counter DROP")
(! ${BFCLI} ruleset set --dry-run --from-str "chain xdp BF_HOOK_XDP ACCEPT rule ip6.nexthdr not -18 counter DROP")
(! ${BFCLI} ruleset set --dry-run --from-str "chain xdp BF_HOOK_XDP ACCEPT rule ip6.nexthdr not 256 counter DROP")

# In sets, ip6.nexthdr is the L4 protocol after the extension headers
${BFCLI} ruleset set --dry-run --from-str "chain xdp BF_HOOK_XDP ACCEPT rule (ip6.nexthdr) in { tcp; udp; 47 } counter DROP"
${BFCLI} ruleset set --dry-run --from-str "chain xdp BF_HOOK_XDP ACCEPT rule (ip6.nexthdr) in { 50 } counter DROP"
${BFCLI} ruleset set --dry-run --from-str "chain xdp BF_HOOK_XDP ACCEPT rule (ip6.saddr, ip6.nexthdr) in { 2001:db8::1, tcp } counter DROP"

(! ${BFCLI} ruleset set --dry-run --from-str "chain xdp BF_HOOK_XDP ACCEPT rule (ip6.nexthdr) in { hop } counter DROP")
(! ${BFCLI} ruleset set --dry-run --from-str "chain xdp BF_HOOK_XDP ACCEPT rule (ip6.nexthdr) in { tcp; frag } counter DROP")
(! ${BFCLI} ruleset set --dry-run --from-str "chain xdp BF_HOOK_XDP ACCEPT rule (ip6.nexthdr) in { 60 } counter DROP")
(! ${BFCLI} ruleset set --dry-run --from-str "chain xdp BF_HOOK_XDP ACCEPT rule (ip6.saddr, ip6.nexthdr) in { 2001:db8::1, ah } counter DROP")
