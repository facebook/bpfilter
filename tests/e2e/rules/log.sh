#!/usr/bin/env bash

. "$(dirname "$0")"/../e2e_test_util.sh

# Parser-only coverage for bare log lookahead and log header tokens.
${BFCLI} ruleset set --dry-run --from-str "chain c1 BF_HOOK_XDP ACCEPT rule ip4.proto icmp log DROP chain c2 BF_HOOK_TC_INGRESS ACCEPT rule ip4.proto icmp counter DROP"
${BFCLI} ruleset set --dry-run --from-str "chain c1 BF_HOOK_XDP ACCEPT rule ip4.proto icmp log
DROP rule ip4.proto icmp counter ACCEPT"
${BFCLI} ruleset set --dry-run --from-str "chain c1 BF_HOOK_XDP ACCEPT rule ip4.proto icmp log
link,internet
DROP"
${BFCLI} ruleset set --dry-run --from-str "chain c1 BF_HOOK_XDP ACCEPT rule ip4.proto icmp log link # hdrs
DROP"
${BFCLI} ruleset set --dry-run --from-str "chain c1 BF_HOOK_XDP ACCEPT rule ip4.proto icmp log # bare
DROP"
${BFCLI} ruleset set --dry-run --from-str "chain c1 BF_HOOK_XDP ACCEPT rule ip4.proto icmp log
# bare
DROP"
${BFCLI} ruleset set --dry-run --from-str "chain c1 BF_HOOK_TC_INGRESS ACCEPT rule ip4.proto icmp log NEXT"
${BFCLI} ruleset set --dry-run --from-str "chain c1 BF_HOOK_TC_INGRESS ACCEPT rule ip4.proto icmp log REDIRECT 1 in"
${BFCLI} ruleset set --dry-run --from-str "chain c1 BF_HOOK_TC_INGRESS ACCEPT rule ip4.proto icmp log mark 0x1 DROP"
(! ${BFCLI} ruleset set --dry-run --from-str "chain c1 BF_HOOK_XDP ACCEPT rule ip4.proto icmp log link,ip DROP")
(! ${BFCLI} ruleset set --dry-run --from-str "chain c1 BF_HOOK_XDP ACCEPT rule ip4.proto icmp log link,,internet DROP")


make_sandbox

${FROM_NS} ${BFCLI} chain set --from-str "chain chain_load_xdp_3 BF_HOOK_XDP ACCEPT rule ip4.proto icmp log counter DROP"
(! ${FROM_NS} ${BFCLI} chain set --from-str "chain chain_load_xdp_3 BF_HOOK_XDP ACCEPT rule ip4.proto icmp log ip counter DROP")
${FROM_NS} ${BFCLI} chain set --from-str "chain chain_load_xdp_3 BF_HOOK_XDP ACCEPT rule ip4.proto icmp log link counter DROP"
${FROM_NS} ${BFCLI} chain set --from-str "chain chain_load_xdp_3 BF_HOOK_XDP ACCEPT rule ip4.proto icmp log link,internet counter DROP"
${FROM_NS} ${BFCLI} chain set --from-str "chain chain_load_xdp_3 BF_HOOK_XDP ACCEPT rule ip4.proto icmp log link,transport counter DROP"
${FROM_NS} ${BFCLI} chain set --from-str "chain chain_load_xdp_3 BF_HOOK_XDP ACCEPT rule ip4.proto icmp log internet,link counter DROP"
