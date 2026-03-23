#!/usr/bin/env bash

. "$(dirname "$0")"/../e2e_test_util.sh

${BFCLI} ruleset set --dry-run --from-str "chain xdp BF_HOOK_XDP ACCEPT rule ip4.proto eq icmp counter DROP"
${BFCLI} ruleset set --dry-run --from-str "chain xdp BF_HOOK_XDP ACCEPT rule ip4.proto eq ICMPv6 counter DROP"
${BFCLI} ruleset set --dry-run --from-str "chain xdp BF_HOOK_XDP ACCEPT rule ip4.proto eq 0 counter DROP"
${BFCLI} ruleset set --dry-run --from-str "chain xdp BF_HOOK_XDP ACCEPT rule ip4.proto eq 17 counter DROP"
${BFCLI} ruleset set --dry-run --from-str "chain xdp BF_HOOK_XDP ACCEPT rule ip4.proto eq 255 counter DROP"

(! ${BFCLI} ruleset set --dry-run --from-str "chain xdp BF_HOOK_XDP ACCEPT rule ip4.proto eq ipv4 counter DROP")
(! ${BFCLI} ruleset set --dry-run --from-str "chain xdp BF_HOOK_XDP ACCEPT rule ip4.proto eq imcp counter DROP")
(! ${BFCLI} ruleset set --dry-run --from-str "chain xdp BF_HOOK_XDP ACCEPT rule ip4.proto eq 0x342 counter DROP")
(! ${BFCLI} ruleset set --dry-run --from-str "chain xdp BF_HOOK_XDP ACCEPT rule ip4.proto eq -18 counter DROP")
(! ${BFCLI} ruleset set --dry-run --from-str "chain xdp BF_HOOK_XDP ACCEPT rule ip4.proto eq 256 counter DROP")

${BFCLI} ruleset set --dry-run --from-str "chain xdp BF_HOOK_XDP ACCEPT rule ip4.proto not icmp counter DROP"
${BFCLI} ruleset set --dry-run --from-str "chain xdp BF_HOOK_XDP ACCEPT rule ip4.proto not ICMPv6 counter DROP"
${BFCLI} ruleset set --dry-run --from-str "chain xdp BF_HOOK_XDP ACCEPT rule ip4.proto not 0 counter DROP"
${BFCLI} ruleset set --dry-run --from-str "chain xdp BF_HOOK_XDP ACCEPT rule ip4.proto not 17 counter DROP"
${BFCLI} ruleset set --dry-run --from-str "chain xdp BF_HOOK_XDP ACCEPT rule ip4.proto not 255 counter DROP"

(! ${BFCLI} ruleset set --dry-run --from-str "chain xdp BF_HOOK_XDP ACCEPT rule ip4.proto not ipv4 counter DROP")
(! ${BFCLI} ruleset set --dry-run --from-str "chain xdp BF_HOOK_XDP ACCEPT rule ip4.proto not imcp counter DROP")
(! ${BFCLI} ruleset set --dry-run --from-str "chain xdp BF_HOOK_XDP ACCEPT rule ip4.proto not 0x342 counter DROP")
(! ${BFCLI} ruleset set --dry-run --from-str "chain xdp BF_HOOK_XDP ACCEPT rule ip4.proto not -18 counter DROP")
(! ${BFCLI} ruleset set --dry-run --from-str "chain xdp BF_HOOK_XDP ACCEPT rule ip4.proto not 256 counter DROP")
