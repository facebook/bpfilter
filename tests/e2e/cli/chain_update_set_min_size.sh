#!/usr/bin/env bash
# Copyright (c) Meta Platforms, Inc. and affiliates.

. "$(dirname "$0")"/../e2e_test_util.sh

make_sandbox

# Print the ID of chain NAME's BPF program: it changes when the program is
# regenerated.
#
# Usage: get_prog_id NAME
get_prog_id() {
    ${FROM_NS} bpftool -j prog show pinned ${WORKDIR}/bpf/bpfilter/$1/bf_prog | jq '.id'
}

# An empty set with a min-size is backed by a map: elements are added and
# removed in place, without regenerating the program.
${FROM_NS} ${BFCLI} chain set --from-str "chain test_xdp BF_HOOK_XDP{ifindex=${NS_IFINDEX}} ACCEPT
    set blocked (ip4.saddr) min-size=4 in {}
    rule
        ip4.proto icmp
        (ip4.saddr) in blocked
        counter
        DROP
"
prog_id=$(get_prog_id test_xdp)
ping -c 1 -W 0.1 ${NS_IP_ADDR}
test "$(get_counter test_xdp 0)" = "0"

${FROM_NS} ${BFCLI} chain update-set --name test_xdp --set-name blocked --add ${HOST_IP_ADDR}
test "$(get_prog_id test_xdp)" = "${prog_id}"
(! ping -c 1 -W 0.1 ${NS_IP_ADDR})
test "$(get_counter test_xdp 0)" = "1"

# The update is persisted
${FROM_NS} ${BFCLI} chain get --name test_xdp | grep -q "${HOST_IP_ADDR}"

${FROM_NS} ${BFCLI} chain update-set --name test_xdp --set-name blocked --remove ${HOST_IP_ADDR}
test "$(get_prog_id test_xdp)" = "${prog_id}"
ping -c 1 -W 0.1 ${NS_IP_ADDR}
(! ${FROM_NS} ${BFCLI} chain get --name test_xdp | grep -q "${HOST_IP_ADDR}")

# Up to min-size elements are added in place
${FROM_NS} ${BFCLI} chain update-set --name test_xdp --set-name blocked \
    --add 192.0.2.1 --add 192.0.2.2 --add 192.0.2.3 --add 192.0.2.4
test "$(get_prog_id test_xdp)" = "${prog_id}"

# Growing the set past min-size regenerates the program, without losing the
# elements added in place, nor the counters
${FROM_NS} ${BFCLI} chain update-set --name test_xdp --set-name blocked --add ${HOST_IP_ADDR}
test "$(get_prog_id test_xdp)" != "${prog_id}"
prog_id=$(get_prog_id test_xdp)
(! ping -c 1 -W 0.1 ${NS_IP_ADDR})
test "$(get_counter test_xdp 0)" = "2"
chain_output=$(${FROM_NS} ${BFCLI} chain get --name test_xdp)
echo "$chain_output"
for addr in 192.0.2.1 192.0.2.2 192.0.2.3 192.0.2.4 ${HOST_IP_ADDR}; do
    echo "$chain_output" | grep -q "${addr}"
done

# A set with more than min-size elements is updated by regenerating the
# program, even if the update doesn't grow it
${FROM_NS} ${BFCLI} chain update-set --name test_xdp --set-name blocked \
    --remove 192.0.2.1 --add 192.0.2.5
test "$(get_prog_id test_xdp)" != "${prog_id}"
prog_id=$(get_prog_id test_xdp)
(! ping -c 1 -W 0.1 ${NS_IP_ADDR})

# Shrinking the set back to min-size elements is done in place
${FROM_NS} ${BFCLI} chain update-set --name test_xdp --set-name blocked \
    --remove 192.0.2.2 --remove 192.0.2.3
test "$(get_prog_id test_xdp)" = "${prog_id}"
(! ping -c 1 -W 0.1 ${NS_IP_ADDR})
${FROM_NS} ${BFCLI} chain flush --name test_xdp

# Sets without min-size are always updated by regenerating the program
${FROM_NS} ${BFCLI} chain set --from-str "chain test_xdp BF_HOOK_XDP{ifindex=${NS_IFINDEX}} ACCEPT
    set blocked (ip4.saddr) in { 192.0.2.1; 192.0.2.2 }
    rule
        ip4.proto icmp
        (ip4.saddr) in blocked
        counter
        DROP
"
prog_id=$(get_prog_id test_xdp)
${FROM_NS} ${BFCLI} chain update-set --name test_xdp --set-name blocked --remove 192.0.2.1
test "$(get_prog_id test_xdp)" != "${prog_id}"
${FROM_NS} ${BFCLI} chain flush --name test_xdp

# Sets sharing a map are updated in place without affecting each other: the
# host's address is only matched by the rule once it is in set b
${FROM_NS} ${BFCLI} chain set --from-str "chain test_xdp BF_HOOK_XDP{ifindex=${NS_IFINDEX}} ACCEPT
    set a (ip4.saddr) min-size=4 in {}
    set b (ip4.saddr) min-size=4 in {}
    rule
        ip4.proto icmp
        (ip4.saddr) in b
        counter
        DROP
"
prog_id=$(get_prog_id test_xdp)
${FROM_NS} ${BFCLI} chain update-set --name test_xdp --set-name a --add ${HOST_IP_ADDR}
ping -c 1 -W 0.1 ${NS_IP_ADDR}

${FROM_NS} ${BFCLI} chain update-set --name test_xdp --set-name b --add ${HOST_IP_ADDR}
(! ping -c 1 -W 0.1 ${NS_IP_ADDR})

# Removing the address from set a keeps it in the map for set b
${FROM_NS} ${BFCLI} chain update-set --name test_xdp --set-name a --remove ${HOST_IP_ADDR}
(! ping -c 1 -W 0.1 ${NS_IP_ADDR})

${FROM_NS} ${BFCLI} chain update-set --name test_xdp --set-name b --remove ${HOST_IP_ADDR}
ping -c 1 -W 0.1 ${NS_IP_ADDR}
test "$(get_prog_id test_xdp)" = "${prog_id}"
test "$(get_counter test_xdp 0)" = "2"
${FROM_NS} ${BFCLI} chain flush --name test_xdp

# LPM trie sets are updated in place too
${FROM_NS} ${BFCLI} chain set --from-str "chain test_xdp BF_HOOK_XDP{ifindex=${NS_IFINDEX}} ACCEPT
    set nets (ip4.snet) min-size=4 in {}
    rule
        ip4.proto icmp
        (ip4.snet) in nets
        counter
        DROP
"
prog_id=$(get_prog_id test_xdp)
ping -c 1 -W 0.1 ${NS_IP_ADDR}

${FROM_NS} ${BFCLI} chain update-set --name test_xdp --set-name nets --add ${HOST_IP_ADDR%.*}.0/24
test "$(get_prog_id test_xdp)" = "${prog_id}"
(! ping -c 1 -W 0.1 ${NS_IP_ADDR})
${FROM_NS} ${BFCLI} chain flush --name test_xdp

# If an in-place update can't be persisted, the set's map is restored: a
# directory in place of the temporary context pin makes persisting fail
${FROM_NS} ${BFCLI} chain set --from-str "chain test_xdp BF_HOOK_XDP{ifindex=${NS_IFINDEX}} ACCEPT
    set blocked (ip4.saddr) min-size=4 in {}
    rule
        ip4.proto icmp
        (ip4.saddr) in blocked
        counter
        DROP
"
${FROM_NS} mkdir ${WORKDIR}/bpf/bpfilter/test_xdp/bf_ctx_tmp
(! ${FROM_NS} ${BFCLI} chain update-set --name test_xdp --set-name blocked --add ${HOST_IP_ADDR})
ping -c 1 -W 0.1 ${NS_IP_ADDR}
(! ${FROM_NS} ${BFCLI} chain get --name test_xdp | grep -q "${HOST_IP_ADDR}")
${FROM_NS} rmdir ${WORKDIR}/bpf/bpfilter/test_xdp/bf_ctx_tmp
${FROM_NS} ${BFCLI} chain flush --name test_xdp
