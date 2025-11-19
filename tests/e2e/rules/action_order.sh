#!/usr/bin/env bash

set -eux
set -o pipefail

. "$(dirname "$0")"/../e2e_test_util.sh

make_sandbox
start_bpfilter

(! ${FROM_NS} bfcli chain set --from-str "chain order BF_HOOK_XDP ACCEPT rule ip4.proto icmp counter counter DROP")
(! ${FROM_NS} bfcli chain set --from-str "chain order BF_HOOK_XDP ACCEPT rule ip4.proto icmp counter log link log link DROP")
${FROM_NS} bfcli chain set --from-str "chain order BF_HOOK_XDP ACCEPT rule ip4.proto icmp DROP"
${FROM_NS} bfcli chain set --from-str "chain order BF_HOOK_XDP ACCEPT rule ip4.proto icmp log link DROP"
${FROM_NS} bfcli chain set --from-str "chain order BF_HOOK_XDP ACCEPT rule ip4.proto icmp counter DROP"
${FROM_NS} bfcli chain set --from-str "chain order BF_HOOK_XDP ACCEPT rule ip4.proto icmp log link counter DROP"
${FROM_NS} bfcli chain set --from-str "chain order BF_HOOK_XDP ACCEPT rule ip4.proto icmp counter log link DROP"