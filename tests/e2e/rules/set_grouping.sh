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

# Multibyte bitmask: more than 8 same-key sets force a 2-byte value
# (1 byte per 8 sets). The host's address sits in s8 only (bit_index 8 ->
# byte 1, bit 0). Rule 0 references s0 (byte 0, bit 0) and must miss;
# rule 1 references s8 and must drop.
${FROM_NS} ${BFCLI} chain set --from-str "chain multibyte BF_HOOK_XDP{ifindex=${NS_IFINDEX}} ACCEPT
    set s0 (ip4.saddr) in { 192.0.2.10 }
    set s1 (ip4.saddr) in { 192.0.2.11 }
    set s2 (ip4.saddr) in { 192.0.2.12 }
    set s3 (ip4.saddr) in { 192.0.2.13 }
    set s4 (ip4.saddr) in { 192.0.2.14 }
    set s5 (ip4.saddr) in { 192.0.2.15 }
    set s6 (ip4.saddr) in { 192.0.2.16 }
    set s7 (ip4.saddr) in { 192.0.2.17 }
    set s8 (ip4.saddr) in { ${HOST_IP_ADDR} }
    rule (ip4.saddr) in s0 counter DROP
    rule (ip4.saddr) in s8 counter DROP"
(! ping -c 1 -W 1 ${NS_IP_ADDR}) || { echo "ERROR: ping should have been dropped via s8 (bit 8)"; exit 1; }
count=$(${FROM_NS} find ${WORKDIR}/bpf/bpfilter/multibyte/ -name 'bf_set_*' | wc -l)
[ "${count}" -eq 1 ] || { echo "ERROR: expected 1 map for 9 same-key sets, got ${count}"; exit 1; }
miss=$(${FROM_NS} bpftool map dump pinned ${WORKDIR}/bpf/bpfilter/multibyte/bf_cmap | jq '.[0].value.count')
[ "${miss}" = "0" ] || { echo "ERROR: s0 rule (byte 0) should not match, got ${miss}"; exit 1; }
hit=$(${FROM_NS} bpftool map dump pinned ${WORKDIR}/bpf/bpfilter/multibyte/bf_cmap | jq '.[1].value.count')
[ "${hit}" -ge 1 ] || { echo "ERROR: s8 rule (byte 1) should match at least once, got ${hit}"; exit 1; }
${FROM_NS} ${BFCLI} chain flush --name multibyte
