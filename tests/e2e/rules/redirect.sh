#!/usr/bin/env bash

. "$(dirname "$0")"/../e2e_test_util.sh

get_counter() {
    ${FROM_NS} bfcli chain get --name "$1" | awk '/counters [0-9]+ packets/{print $2}'
}

make_sandbox
start_bpfilter

# Invalid: REDIRECT not supported for NF/Cgroup hooks, and XDP only supports 'out'
(! ${FROM_NS} bfcli chain set --from-str "chain c BF_HOOK_NF_LOCAL_IN{family=inet4,priorities=100-200} ACCEPT rule ip4.proto icmp REDIRECT 1 out")
(! ${FROM_NS} bfcli chain set --from-str "chain c BF_HOOK_CGROUP_INGRESS{cgpath=/sys/fs/cgroup} ACCEPT rule ip4.proto icmp REDIRECT 1 out")
(! ${FROM_NS} bfcli chain set --from-str "chain c BF_HOOK_XDP{ifindex=${NS_IFINDEX}} ACCEPT rule ip4.proto icmp REDIRECT 1 in")
(! ${FROM_NS} bfcli chain set --from-str "chain c BF_HOOK_TC_INGRESS{ifindex=${NS_IFINDEX}} ACCEPT rule ip4.proto icmp REDIRECT nonexistent_iface in")

# Valid: TC both directions, XDP 'out', with ifindex or interface name
${FROM_NS} bfcli chain set --from-str "chain c1 BF_HOOK_TC_INGRESS{ifindex=${NS_IFINDEX}} ACCEPT rule ip4.proto icmp REDIRECT 1 in"
${FROM_NS} bfcli chain set --from-str "chain c2 BF_HOOK_TC_EGRESS{ifindex=${NS_IFINDEX}} ACCEPT rule ip4.proto icmp REDIRECT lo out"
${FROM_NS} bfcli chain set --from-str "chain c3 BF_HOOK_XDP{ifindex=${NS_IFINDEX}} ACCEPT rule ip4.proto icmp REDIRECT 1 out"
${FROM_NS} bfcli ruleset flush

# Create veth pair: packets egressing redir0 arrive at redir1's ingress
${FROM_NS} ip link add redir0 type veth peer name redir1
${FROM_NS} ip link set redir0 up
${FROM_NS} ip link set redir1 up
REDIR0_IFINDEX=$(${FROM_NS} ip -o link show redir0 | awk '{print $1}' | cut -d: -f1)
REDIR1_IFINDEX=$(${FROM_NS} ip -o link show redir1 | awk '{print $1}' | cut -d: -f1)

# XDP redirect: packets on veth_ns redirected out redir0, counted at redir1
${FROM_NS} bfcli chain set --from-str "chain cnt BF_HOOK_XDP{ifindex=${REDIR1_IFINDEX}} ACCEPT rule ip4.proto icmp counter ACCEPT"
${FROM_NS} bfcli chain set --from-str "chain redir BF_HOOK_XDP{ifindex=${NS_IFINDEX}} ACCEPT rule ip4.proto icmp REDIRECT ${REDIR0_IFINDEX} out"
test "$(get_counter cnt)" = "0"
ping -c 1 -W 1 ${NS_IP_ADDR} || true
test "$(get_counter cnt)" = "1"
${FROM_NS} bfcli ruleset flush

# TC ingress redirect: packets redirected to redir0's ingress
${FROM_NS} bfcli chain set --from-str "chain cnt BF_HOOK_TC_INGRESS{ifindex=${REDIR0_IFINDEX}} ACCEPT rule ip4.proto icmp counter ACCEPT"
${FROM_NS} bfcli chain set --from-str "chain redir BF_HOOK_TC_INGRESS{ifindex=${NS_IFINDEX}} ACCEPT rule ip4.proto icmp REDIRECT ${REDIR0_IFINDEX} in"
test "$(get_counter cnt)" = "0"
ping -c 1 -W 1 ${NS_IP_ADDR} || true
test "$(get_counter cnt)" = "1"
${FROM_NS} bfcli ruleset flush

# TC egress redirect with interface name: packets redirected out redir0, counted at redir1
${FROM_NS} bfcli chain set --from-str "chain cnt BF_HOOK_TC_INGRESS{ifindex=${REDIR1_IFINDEX}} ACCEPT rule ip4.proto icmp counter ACCEPT"
${FROM_NS} bfcli chain set --from-str "chain redir BF_HOOK_TC_EGRESS{ifindex=${NS_IFINDEX}} ACCEPT rule ip4.proto icmp REDIRECT redir0 out"
test "$(get_counter cnt)" = "0"
ping -c 1 -W 1 ${NS_IP_ADDR} || true
test "$(get_counter cnt)" = "1"
${FROM_NS} bfcli ruleset flush

${FROM_NS} ip link del redir0
