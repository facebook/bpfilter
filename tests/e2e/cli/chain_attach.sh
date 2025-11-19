#!/usr/bin/env bash

set -eux
set -o pipefail

. "$(dirname "$0")"/../e2e_test_util.sh

make_sandbox
start_bpfilter

${FROM_NS} bfcli chain load --from-str "chain chain_attach_0 BF_HOOK_XDP ACCEPT"
(! ${FROM_NS} bfcli chain attach --name chain_attach_0 --option family=inet4 --option priorities=101-102)
${FROM_NS} bfcli chain get --name chain_attach_0
${FROM_NS} bfcli chain flush --name chain_attach_0

# XDP
ping -c 1 -W 0.1 ${NS_IP_ADDR}
${FROM_NS} bfcli chain load --from-str "chain chain_attach_xdp_0 BF_HOOK_XDP ACCEPT rule ip4.proto icmp log link,transport,internet counter DROP"
${FROM_NS} bfcli chain load --from-str "chain chain_attach_xdp_1 BF_HOOK_XDP ACCEPT"
${FROM_NS} bfcli chain attach --name chain_attach_xdp_0 --option ifindex=${NS_IFINDEX}
(! ${FROM_NS} bfcli chain attach --name chain_attach_xdp_1 --option ifindex=${NS_IFINDEX})
(! ping -c 1 -W 0.1 ${NS_IP_ADDR})
${FROM_NS} bfcli chain flush --name chain_attach_xdp_0
${FROM_NS} bfcli chain flush --name chain_attach_xdp_1

# TC
ping -c 1 -W 0.1 ${NS_IP_ADDR}
${FROM_NS} bfcli chain load --from-str "chain chain_attach_tc_0 BF_HOOK_TC_EGRESS ACCEPT rule ip4.proto icmp log internet,link,transport counter DROP"
${FROM_NS} bfcli chain load --from-str "chain chain_attach_tc_1 BF_HOOK_TC_EGRESS ACCEPT"
${FROM_NS} bfcli chain attach --name chain_attach_tc_0 --option ifindex=${NS_IFINDEX}
${FROM_NS} bfcli chain attach --name chain_attach_tc_1 --option ifindex=${NS_IFINDEX}
(! ping -c 1 -W 0.1 ${NS_IP_ADDR})
${FROM_NS} bfcli chain flush --name chain_attach_tc_0
${FROM_NS} bfcli chain flush --name chain_attach_tc_1

# cgroup
ping -c 1 -W 0.1 ${NS_IP_ADDR}
${FROM_NS} bfcli chain load --from-str "chain chain_attach_cgroup_0 BF_HOOK_CGROUP_INGRESS ACCEPT"
${FROM_NS} bfcli chain load --from-str "chain chain_attach_cgroup_1 BF_HOOK_CGROUP_INGRESS ACCEPT rule ip4.proto icmp log internet counter DROP"
${FROM_NS} bfcli chain attach --name chain_attach_cgroup_0 --option cgpath=/sys/fs/cgroup
${FROM_NS} bfcli chain attach --name chain_attach_cgroup_1 --option cgpath=/sys/fs/cgroup
(! ping -c 1 -W 0.1 ${NS_IP_ADDR})
${FROM_NS} bfcli chain flush --name chain_attach_cgroup_0
${FROM_NS} bfcli chain flush --name chain_attach_cgroup_1

# Netfilter
ping -c 1 -W 0.1 ${NS_IP_ADDR}
${FROM_NS} bfcli chain load --from-str "chain chain_attach_nf_0 BF_HOOK_NF_LOCAL_IN ACCEPT rule ip4.proto icmp counter DROP"
${FROM_NS} bfcli chain load --from-str "chain chain_attach_nf_1 BF_HOOK_NF_LOCAL_IN ACCEPT"
${FROM_NS} bfcli chain attach --name chain_attach_nf_0 --option family=inet4 --option priorities=101-102
(! ${FROM_NS} bfcli chain attach --name chain_attach_nf_1 --option family=inet4 --option priorities=101-102)
(! ping -c 1 -W 0.1 ${NS_IP_ADDR})
${FROM_NS} bfcli chain flush --name chain_attach_nf_0
${FROM_NS} bfcli chain flush --name chain_attach_nf_1