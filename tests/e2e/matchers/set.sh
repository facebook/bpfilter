#!/usr/bin/env bash

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
