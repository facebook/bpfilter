#!/usr/bin/env bash

. "$(dirname "$0")"/../e2e_test_util.sh

make_sandbox

${FROM_NS} ${BFCLI} chain load --from-str "chain chain_attach_0 BF_HOOK_XDP ACCEPT"
(! ${FROM_NS} ${BFCLI} chain attach --name chain_attach_0 --option family=inet4 --option priorities=101-102)
${FROM_NS} ${BFCLI} chain get --name chain_attach_0
${FROM_NS} ${BFCLI} chain flush --name chain_attach_0

# XDP
ping -c 1 -W 0.1 ${NS_IP_ADDR}
${FROM_NS} ${BFCLI} chain load --from-str "chain chain_attach_xdp_0 BF_HOOK_XDP ACCEPT rule ip4.proto icmp log link,transport,internet counter DROP"
${FROM_NS} ${BFCLI} chain load --from-str "chain chain_attach_xdp_1 BF_HOOK_XDP ACCEPT"
${FROM_NS} ${BFCLI} chain attach --name chain_attach_xdp_0 --option ifindex=${NS_IFINDEX}
(! ${FROM_NS} ${BFCLI} chain attach --name chain_attach_xdp_1 --option ifindex=${NS_IFINDEX})
(! ping -c 1 -W 0.1 ${NS_IP_ADDR})
${FROM_NS} ${BFCLI} chain flush --name chain_attach_xdp_0
${FROM_NS} ${BFCLI} chain flush --name chain_attach_xdp_1

# TC
ping -c 1 -W 0.1 ${NS_IP_ADDR}
${FROM_NS} ${BFCLI} chain load --from-str "chain chain_attach_tc_0 BF_HOOK_TC_EGRESS ACCEPT rule ip4.proto icmp log internet,link,transport counter DROP"
${FROM_NS} ${BFCLI} chain load --from-str "chain chain_attach_tc_1 BF_HOOK_TC_EGRESS ACCEPT"
${FROM_NS} ${BFCLI} chain attach --name chain_attach_tc_0 --option ifindex=${NS_IFINDEX}
${FROM_NS} ${BFCLI} chain attach --name chain_attach_tc_1 --option ifindex=${NS_IFINDEX}
(! ping -c 1 -W 0.1 ${NS_IP_ADDR})
${FROM_NS} ${BFCLI} chain flush --name chain_attach_tc_0
${FROM_NS} ${BFCLI} chain flush --name chain_attach_tc_1

# cgroup_skb
ping -c 1 -W 0.1 ${NS_IP_ADDR}
${FROM_NS} ${BFCLI} chain load --from-str "chain chain_attach_cgroup_skb_0 BF_HOOK_CGROUP_SKB_INGRESS ACCEPT"
${FROM_NS} ${BFCLI} chain load --from-str "chain chain_attach_cgroup_skb_1 BF_HOOK_CGROUP_SKB_INGRESS ACCEPT rule ip4.proto icmp log internet counter DROP"
${FROM_NS} ${BFCLI} chain attach --name chain_attach_cgroup_skb_0 --option cgpath=/sys/fs/cgroup
${FROM_NS} ${BFCLI} chain attach --name chain_attach_cgroup_skb_1 --option cgpath=/sys/fs/cgroup
(! ping -c 1 -W 0.1 ${NS_IP_ADDR})
${FROM_NS} ${BFCLI} chain flush --name chain_attach_cgroup_skb_0
${FROM_NS} ${BFCLI} chain flush --name chain_attach_cgroup_skb_1

# cgroup_sock_addr
CGROUP_PATH=/sys/fs/cgroup/bftest_chain_attach
mkdir -p ${CGROUP_PATH}
trap 'ret=$?; rmdir ${CGROUP_PATH} 2>/dev/null; cleanup; exit ${ret}' EXIT
${FROM_NS} ${BFCLI} chain load --from-str "chain chain_attach_csa4_0 BF_HOOK_CGROUP_SOCK_ADDR_CONNECT4 ACCEPT rule meta.dport eq 9990 DROP"
${FROM_NS} ${BFCLI} chain load --from-str "chain chain_attach_csa4_1 BF_HOOK_CGROUP_SOCK_ADDR_CONNECT4 ACCEPT"
${FROM_NS} ${BFCLI} chain attach --name chain_attach_csa4_0 --option cgpath=${CGROUP_PATH}
${FROM_NS} ${BFCLI} chain attach --name chain_attach_csa4_1 --option cgpath=${CGROUP_PATH}
(! ${FROM_NS} bash -c "echo \$\$ > ${CGROUP_PATH}/cgroup.procs && echo > /dev/udp/${HOST_IP_ADDR}/9990" 2>/dev/null)
${FROM_NS} ${BFCLI} chain flush --name chain_attach_csa4_0
${FROM_NS} ${BFCLI} chain flush --name chain_attach_csa4_1

# cgroup_sock_addr sendmsg
${FROM_NS} ${BFCLI} chain load --from-str "chain chain_attach_csm4_0 BF_HOOK_CGROUP_SOCK_ADDR_SENDMSG4 ACCEPT rule meta.dport eq 9990 DROP"
${FROM_NS} ${BFCLI} chain load --from-str "chain chain_attach_csm4_1 BF_HOOK_CGROUP_SOCK_ADDR_SENDMSG4 ACCEPT"
${FROM_NS} ${BFCLI} chain attach --name chain_attach_csm4_0 --option cgpath=${CGROUP_PATH}
${FROM_NS} ${BFCLI} chain attach --name chain_attach_csm4_1 --option cgpath=${CGROUP_PATH}
(! ${FROM_NS} python3 -c "
import os, socket
with open('${CGROUP_PATH}/cgroup.procs', 'w') as f:
    f.write(str(os.getpid()))
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.sendto(b'x', ('${HOST_IP_ADDR}', 9990))
s.close()
")
${FROM_NS} ${BFCLI} chain flush --name chain_attach_csm4_0
${FROM_NS} ${BFCLI} chain flush --name chain_attach_csm4_1

# Netfilter
ping -c 1 -W 0.1 ${NS_IP_ADDR}
${FROM_NS} ${BFCLI} chain load --from-str "chain chain_attach_nf_0 BF_HOOK_NF_LOCAL_IN ACCEPT rule ip4.proto icmp counter DROP"
${FROM_NS} ${BFCLI} chain load --from-str "chain chain_attach_nf_1 BF_HOOK_NF_LOCAL_IN ACCEPT"
${FROM_NS} ${BFCLI} chain attach --name chain_attach_nf_0 --option family=inet4 --option priorities=101-102
(! ${FROM_NS} ${BFCLI} chain attach --name chain_attach_nf_1 --option family=inet4 --option priorities=101-102)
(! ping -c 1 -W 0.1 ${NS_IP_ADDR})
${FROM_NS} ${BFCLI} chain flush --name chain_attach_nf_0
${FROM_NS} ${BFCLI} chain flush --name chain_attach_nf_1