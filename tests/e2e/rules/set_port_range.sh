#!/usr/bin/env bash
# Copyright (c) Meta Platforms, Inc. and affiliates.

. "$(dirname "$0")"/../e2e_test_util.sh

make_sandbox

# Send one UDP packet to 127.0.0.1 on port $1, from the namespace.
udp_send() {
    ${FROM_NS} bash -c "echo > /dev/udp/127.0.0.1/$1"
}

# TC egress on the namespace's loopback (ifindex 1) runs before the write
# returns, so the counter is up to date when it is read.
${FROM_NS} ${BFCLI} chain set --from-str "chain tc BF_HOOK_TC_EGRESS{ifindex=1} ACCEPT
    rule (udp.dport) in { 9990-9992 } counter ACCEPT"

# Both ends of the range match, the ports just outside it don't
udp_send 9989
udp_send 9990
udp_send 9992
udp_send 9993
test "$(get_counter tc 0)" = "2"

${FROM_NS} ${BFCLI} chain flush --name tc

# update-set accepts ranges too, and a single port can be removed from one:
# every port but 9991 matches afterwards
${FROM_NS} ${BFCLI} chain set --from-str "chain tc BF_HOOK_TC_EGRESS{ifindex=1} ACCEPT
    set ports (udp.dport) in { 9990-9992 }
    rule (udp.dport) in ports counter ACCEPT"
${FROM_NS} ${BFCLI} chain update-set --name tc --set-name ports --remove 9991 --add 9993-9994
for port in 9990 9991 9992 9993 9994; do
    udp_send ${port}
done
test "$(get_counter tc 0)" = "4"

${FROM_NS} ${BFCLI} chain flush --name tc
