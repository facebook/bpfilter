#!/usr/bin/env bash

. "$(dirname "$0")"/../e2e_test_util.sh

make_sandbox
start_bpfilter

# Verify IPv4 connectivity before filtering
ping -c 1 -W 0.1 ${NS_IP_ADDR}

# Attach NF chain - this should create both inet4 and inet6 links
${FROM_NS} bfcli chain set --from-str "chain nf_dual_0 BF_HOOK_NF_LOCAL_IN{priorities=101-102} ACCEPT rule ip4.proto icmp counter DROP"
(! ping -c 1 -W 0.1 ${NS_IP_ADDR})

# Verify that both inet4 and inet6 BPF links were created (bf_link + bf_link_extra)
LINK_COUNT=$(${FROM_NS} find ${WORKDIR}/bpf/bpfilter/nf_dual_0/ -name 'bf_link*' | wc -l)
if [ "${LINK_COUNT}" -ne 2 ]; then
    echo "ERROR: Expected 2 netfilter links (inet4 + inet6), found ${LINK_COUNT}"
    ${FROM_NS} ls -la ${WORKDIR}/bpf/bpfilter/nf_dual_0/ || true
    exit 1
fi

# Update the chain and verify both families remain attached
${FROM_NS} bfcli chain update --name nf_dual_0 --from-str "chain nf_dual_0 BF_HOOK_NF_LOCAL_IN ACCEPT rule ip4.proto icmp counter DROP"

# IPv4 should still be blocked after update
(! ping -c 1 -W 0.1 ${NS_IP_ADDR})

# Verify both links still exist after update
LINK_COUNT_AFTER=$(${FROM_NS} find ${WORKDIR}/bpf/bpfilter/nf_dual_0/ -name 'bf_link*' | wc -l)
if [ "${LINK_COUNT_AFTER}" -ne 2 ]; then
    echo "ERROR: Expected 2 netfilter links after update, found ${LINK_COUNT_AFTER}"
    ${FROM_NS} ls -la ${WORKDIR}/bpf/bpfilter/nf_dual_0/ || true
    exit 1
fi

# Flush the chain and verify connectivity is restored
${FROM_NS} bfcli chain flush --name nf_dual_0
ping -c 1 -W 0.1 ${NS_IP_ADDR}

# Verify links are removed after flush
LINK_COUNT_FINAL=$(${FROM_NS} find ${WORKDIR}/bpf/bpfilter/nf_dual_0/ -name 'bf_link*' | wc -l || echo "0")
if [ "${LINK_COUNT_FINAL}" -ne 0 ]; then
    echo "ERROR: Expected 0 netfilter links after flush, found ${LINK_COUNT_FINAL}"
    ${FROM_NS} ls -la ${WORKDIR}/bpf/bpfilter/nf_dual_0/ || true
    exit 1
fi
