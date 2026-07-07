#!/usr/bin/env bash

. "$(dirname "$0")"/../e2e_test_util.sh

GRE_HOST="gre_h_${_SHORT_ID}"
GRE_NS="gre_n_${_SHORT_ID}"
GRE_HOST_IP="172.16.0.1/30"
GRE_NS_IP="172.16.0.2/30"
GRE_NS_IP_ADDR="172.16.0.2"

# The host-side tunnel device lives in the host namespace and is not removed
# with the sandbox, delete it explicitly.
cleanup() {
    ip link del ${GRE_HOST} 2>/dev/null || true
    destroy_sandbox
}

make_sandbox

# GRE tunnel over the veth pair: inner traffic is encapsulated in IPv4
# protocol 47 packets between HOST_IP_ADDR and NS_IP_ADDR.
ip link del ${GRE_HOST} 2>/dev/null || true
ip link add ${GRE_HOST} type gre local ${HOST_IP_ADDR} remote ${NS_IP_ADDR}
ip addr add ${GRE_HOST_IP} dev ${GRE_HOST}
ip link set ${GRE_HOST} up

${FROM_NS} ip link add ${GRE_NS} type gre local ${NS_IP_ADDR} remote ${HOST_IP_ADDR}
${FROM_NS} ip addr add ${GRE_NS_IP} dev ${GRE_NS}
${FROM_NS} ip link set ${GRE_NS} up

# The tunnel carries traffic before any filtering is applied
ping -c 1 -W 0.5 ${GRE_NS_IP_ADDR}

# Drop GRE (IPv4 protocol 47) entering the namespace
${FROM_NS} ${BFCLI} ruleset set --from-str "chain xdp BF_HOOK_XDP{ifindex=${NS_IFINDEX}} ACCEPT rule ip4.proto eq gre counter DROP"

# Encapsulated traffic is dropped, non-GRE traffic still goes through
(! ping -c 1 -W 0.5 ${GRE_NS_IP_ADDR})
ping -c 1 -W 0.5 ${NS_IP_ADDR}

# Exactly one GRE packet (the dropped echo request) hit the rule
test "$(get_counter xdp 0)" = "1"

${FROM_NS} ${BFCLI} ruleset flush
