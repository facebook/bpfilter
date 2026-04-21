#!/usr/bin/env bash

. "$(dirname "$0")"/../e2e_test_util.sh

make_sandbox

# Regression test for same-key set map grouping with bitmask values.
# Sets sharing a key format should be grouped into a single BPF map.

# Two non-empty same-key sets collapse to a single map.
${FROM_NS} ${BFCLI} chain set --from-str "chain merged BF_HOOK_XDP ACCEPT
    set a (ip4.saddr) in { 192.0.2.1 }
    set b (ip4.saddr) in { 192.0.2.2 }
    rule (ip4.saddr) in a counter DROP
    rule (ip4.saddr) in b counter DROP"
count=$(${FROM_NS} find ${WORKDIR}/bpf/bpfilter/merged/ -name 'bf_set_*' | wc -l)
[ "${count}" -eq 1 ] || { echo "ERROR: expected 1 map for merged group, got ${count}"; exit 1; }

# Distinct key formats remain in separate maps.
${FROM_NS} ${BFCLI} chain set --from-str "chain split BF_HOOK_XDP ACCEPT
    set a (ip4.saddr) in { 192.0.2.1 }
    set b (ip4.daddr) in { 192.0.2.2 }
    rule (ip4.saddr) in a counter DROP
    rule (ip4.daddr) in b counter DROP"
count=$(${FROM_NS} find ${WORKDIR}/bpf/bpfilter/split/ -name 'bf_set_*' | wc -l)
[ "${count}" -eq 2 ] || { echo "ERROR: expected 2 maps for split groups, got ${count}"; exit 1; }

# Isolation test: the host's address lives in set b only.
# Chain references set a only. We must not match on set b elements.
${FROM_NS} ${BFCLI} chain set --from-str "chain isolation BF_HOOK_XDP{ifindex=${NS_IFINDEX}} ACCEPT
    set a (ip4.saddr) in { 192.0.2.40 }
    set b (ip4.saddr) in { ${HOST_IP_ADDR} }
    rule (ip4.saddr) in a counter DROP"
ping -c 1 -W 1 ${NS_IP_ADDR} || { echo "ERROR: ping should have succeeded"; exit 1; }
${FROM_NS} ${BFCLI} chain flush --name isolation
