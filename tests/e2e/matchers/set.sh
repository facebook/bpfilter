#!/usr/bin/env bash

. "$(dirname "$0")"/../e2e_test_util.sh

bfcli ruleset set --dry-run --from-str "chain xdp BF_HOOK_XDP ACCEPT rule (ip4.saddr, icmp.code) in {192.168.1.1,41; 192.168.1.1,42} counter DROP"
bfcli ruleset set --dry-run --from-str "chain xdp BF_HOOK_XDP ACCEPT rule (ip4.saddr, icmp.code) in {192.168.1.1 ,41; 192.168.1.1,42} counter DROP"
bfcli ruleset set --dry-run --from-str "chain xdp BF_HOOK_XDP ACCEPT rule (ip4.saddr, icmp.code) in {192.168.1.1, 41; 192.168.1.1,42} counter DROP"
bfcli ruleset set --dry-run --from-str "chain xdp BF_HOOK_XDP ACCEPT rule (ip4.saddr, icmp.code) in {192.168.1.1,41;192.168.1.1,42} counter DROP"
bfcli ruleset set --dry-run --from-str "chain xdp BF_HOOK_XDP ACCEPT rule (ip4.saddr, icmp.code) in {
    192.168.1.1 , 41;
    192.168.1.1,42
} counter DROP"
bfcli ruleset set --dry-run --from-str "chain xdp BF_HOOK_XDP ACCEPT rule (ip6.saddr) in {
    ::1;
    ::2
} counter DROP"
bfcli ruleset set --dry-run --from-str "chain xdp BF_HOOK_XDP ACCEPT rule (ip6.snet) in {
    ::1/100;
    ::2/89
} counter DROP"
bfcli ruleset set --dry-run --from-str "chain xdp BF_HOOK_XDP ACCEPT rule (ip4.saddr, icmp.code) in {
    192.168.1.1 , 41 ;
    192.168.1.1 , 42 ;
} counter DROP"

bfcli ruleset set --dry-run --from-str "chain xdp BF_HOOK_XDP ACCEPT rule (ip4.saddr, ip4.daddr) in {
    192.168.1.1, 192.168.1.2;
    192.168.1.3, 192.168.1.4
} counter DROP"
bfcli ruleset set --dry-run --from-str "chain xdp BF_HOOK_XDP ACCEPT rule (ip4.proto, ip6.nexthdr) in {6, 40; 40, 6} counter DROP"
bfcli ruleset set --dry-run --from-str "chain xdp BF_HOOK_XDP ACCEPT rule (ip6.saddr, ip6.daddr) in {
    ::1, ::2;
    ::3, ::4
} counter DROP"
bfcli ruleset set --dry-run --from-str "chain xdp BF_HOOK_XDP ACCEPT rule (icmp.code, icmp.type) in {
    3, echo-reply;
    2, echo-request
} counter DROP"
bfcli ruleset set --dry-run --from-str "chain xdp BF_HOOK_XDP ACCEPT rule (icmpv6.code, icmpv6.type) in {
    3, echo-reply;
    2, echo-request
} counter DROP"
bfcli ruleset set --dry-run --from-str "chain xdp BF_HOOK_XDP ACCEPT rule (icmpv6.code, icmpv6.type   ) in {
    3, echo-reply;
    2, echo-request
} counter DROP"
bfcli ruleset set --dry-run --from-str "chain xdp BF_HOOK_XDP ACCEPT rule (icmpv6.code   , icmpv6.type   ) in {
    3, echo-reply;
    2, echo-request
} counter DROP"
bfcli ruleset set --dry-run --from-str "chain xdp BF_HOOK_XDP ACCEPT rule (  icmpv6.code,      icmpv6.type   ) in {
    3, echo-reply;
    2, echo-request
} counter DROP"

(! bfcli ruleset set --dry-run --from-str "chain xdp BF_HOOK_XDP ACCEPT rule (ip4.snet, ip4.dnet) in {
    192.168.1.1/24, 192.167.1.1/24;
    10.211.55.2/24, 192.168.1.1/24
} counter DROP")
(! bfcli ruleset set --dry-run --from-str "chain xdp BF_HOOK_XDP ACCEPT rule (ip6.snet, ip6.dnet) in {
    ::1/32, ::2/64;
    ::3/96, ::4/128
} counter DROP")
(! bfcli ruleset set --dry-run --from-str "chain xdp BF_HOOK_XDP ACCEPT rule (ip4.saddr, ) in {192.168.1.1,41; 192.168.1.1,42} counter DROP")
(! bfcli ruleset set --dry-run --from-str "chain xdp BF_HOOK_XDP ACCEPT rule (ip4.saddr, icmp.code) in {192.168.1.1,41 192.168.1.1,42} counter DROP")
(! bfcli ruleset set --dry-run --from-str "chain xdp BF_HOOK_XDP ACCEPT rule (ip4.saddr, icmp.code) in {192.168.1.141; 192.168.1.1,42} counter DROP")
(! bfcli ruleset set --dry-run --from-str "chain xdp BF_HOOK_XDP ACCEPT rule (ip4.saddr, icmp.code) in {192.168.1.1} counter DROP")
(! bfcli ruleset set --dry-run --from-str "chain xdp BF_HOOK_XDP ACCEPT rule (ip4.saddr;icmp.code) in {192.168.1.1,41; 192.168.1.1,42} counter DROP")
(! bfcli ruleset set --dry-run --from-str "chain xdp BF_HOOK_XDP ACCEPT rule (ip4.saddr, icmp.code) in {192.168.1.,41; 192.168.1.1,42} counter DROP")
(! bfcli ruleset set --dry-run --from-str "chain xdp BF_HOOK_XDP ACCEPT rule (ip4.saddr, icmp.code) in {192.168.1.1,cafe; 192.168.1.1,42} counter DROP")
(! bfcli ruleset set --dry-run --from-str "chain xdp BF_HOOK_XDP ACCEPT rule (ip4.saddr, icmp.code) in {192.168.1.1,41,192.168.1.1,42} counter DROP")

make_sandbox
start_bpfilter
    ${FROM_NS} bfcli chain set --from-str "chain test BF_HOOK_XDP{ifindex=${NS_IFINDEX}} ACCEPT
        rule (ip4.saddr) in { 192.168.1.1 } DROP
        rule (ip4.saddr) in {} ACCEPT"

    # Verify only 1 set map is associated to the program (empty set should not create a map)
    MAP_IDS=$(${FROM_NS} bpftool -j prog show pinned ${WORKDIR}/bpf/bpfilter/test/bf_prog | jq -r '.map_ids[]')
    MAP_COUNT=0
    for map_id in ${MAP_IDS}; do
        name=$(${FROM_NS} bpftool -j map show id ${map_id} | jq -r '.name')
        [[ "${name}" == set_* ]] && MAP_COUNT=$((MAP_COUNT + 1))
    done
    [ "${MAP_COUNT}" -eq 1 ] || { echo "ERROR: Expected 1 set map, found ${MAP_COUNT}"; exit 1; }
stop_bpfilter
