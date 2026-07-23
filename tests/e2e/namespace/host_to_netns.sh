#!/usr/bin/env bash
# Copyright (c) Meta Platforms, Inc. and affiliates.

. "$(dirname "$0")"/../e2e_test_util.sh

make_sandbox

(! ${FROM_NS} ${BFCLI} ruleset set --from-str "chain xdp BF_HOOK_XDP{ifindex=${HOST_IFINDEX}} ACCEPT rule ip4.proto icmp log link counter DROP")
ping -c 1 -W 0.1 ${NS_IP_ADDR}
${FROM_NS} ${BFCLI} ruleset set --from-str "chain xdp BF_HOOK_XDP{ifindex=${NS_IFINDEX}} ACCEPT rule ip4.proto icmp counter DROP"
(! ping -c 1 -W 0.1 ${NS_IP_ADDR})
test "$(get_counter xdp 0)" = "1"
${FROM_NS} ${BFCLI} ruleset flush