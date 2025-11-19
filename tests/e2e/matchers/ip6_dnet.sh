#!/usr/bin/env bash

bfcli ruleset set --dry-run --from-str "chain xdp BF_HOOK_XDP ACCEPT rule ip6.dnet eq 2001:db8::/32 counter DROP"
bfcli ruleset set --dry-run --from-str "chain xdp BF_HOOK_XDP ACCEPT rule ip6.dnet eq 2001:db8:85a3::/48 counter DROP"
bfcli ruleset set --dry-run --from-str "chain xdp BF_HOOK_XDP ACCEPT rule ip6.dnet eq fe80::/10 counter DROP"
bfcli ruleset set --dry-run --from-str "chain xdp BF_HOOK_XDP ACCEPT rule ip6.dnet eq 2001:db8:85a3:8d3::/64 counter DROP"
bfcli ruleset set --dry-run --from-str "chain xdp BF_HOOK_XDP ACCEPT rule ip6.dnet eq 2001:0db8:85a3:0000::/64 counter DROP"
bfcli ruleset set --dry-run --from-str "chain xdp BF_HOOK_XDP ACCEPT rule ip6.dnet eq 2001:db8::1/128 counter DROP"
bfcli ruleset set --dry-run --from-str "chain xdp BF_HOOK_XDP ACCEPT rule ip6.dnet eq ::1/128 counter DROP"
bfcli ruleset set --dry-run --from-str "chain xdp BF_HOOK_XDP ACCEPT rule ip6.dnet eq ::/0 counter DROP"
bfcli ruleset set --dry-run --from-str "chain xdp BF_HOOK_XDP ACCEPT rule ip6.dnet eq 2001:db8::8a2e:370:7334/96 counter DROP"
bfcli ruleset set --dry-run --from-str "chain xdp BF_HOOK_XDP ACCEPT rule ip6.dnet eq ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/128 counter DROP"
bfcli ruleset set --dry-run --from-str "chain xdp BF_HOOK_XDP ACCEPT rule ip6.dnet eq 0:0:0:0:0:0:0:0/0 counter DROP"
bfcli ruleset set --dry-run --from-str "chain xdp BF_HOOK_XDP ACCEPT rule ip6.dnet eq ::0/0 counter DROP"
bfcli ruleset set --dry-run --from-str "chain xdp BF_HOOK_XDP ACCEPT rule ip6.dnet eq 2001:0db8:85a3:0000:0000:8a2e:0370:7334/128 counter DROP"

(! bfcli ruleset set --dry-run --from-str "chain xdp BF_HOOK_XDP ACCEPT rule ip6.dnet eq notanip counter DROP")
(! bfcli ruleset set --dry-run --from-str "chain xdp BF_HOOK_XDP ACCEPT rule ip6.dnet eq 1.1.1.1 counter DROP")
(! bfcli ruleset set --dry-run --from-str "chain xdp BF_HOOK_XDP ACCEPT rule ip6.dnet eq 2001::db8::1 counter DROP")
(! bfcli ruleset set --dry-run --from-str "chain xdp BF_HOOK_XDP ACCEPT rule ip6.dnet eq 2001:0db8:85a3:0000:0000:8a2e:0370:7334:1234 counter DROP")
(! bfcli ruleset set --dry-run --from-str "chain xdp BF_HOOK_XDP ACCEPT rule ip6.dnet eq 2001:db8::/129 counter DROP")
(! bfcli ruleset set --dry-run --from-str "chain xdp BF_HOOK_XDP ACCEPT rule ip6.dnet eq 2001:db8::/256 counter DROP")
(! bfcli ruleset set --dry-run --from-str "chain xdp BF_HOOK_XDP ACCEPT rule ip6.dnet eq 2001:db8::/-1 counter DROP")
(! bfcli ruleset set --dry-run --from-str "chain xdp BF_HOOK_XDP ACCEPT rule ip6.dnet eq 2001:db8::/999 counter DROP")
(! bfcli ruleset set --dry-run --from-str "chain xdp BF_HOOK_XDP ACCEPT rule ip6.dnet eq ::ffff:192.168.0.0/96 counter DROP")
(! bfcli ruleset set --dry-run --from-str "chain xdp BF_HOOK_XDP ACCEPT rule ip6.dnet eq 2001:0db81:85a3::8a2e:370:7334/48 counter DROP")
(! bfcli ruleset set --dry-run --from-str "chain xdp BF_HOOK_XDP ACCEPT rule ip6.dnet eq 2001:xyz8::1/32 counter DROP")
(! bfcli ruleset set --dry-run --from-str "chain xdp BF_HOOK_XDP ACCEPT rule ip6.dnet eq gggg::1/128 counter DROP")
(! bfcli ruleset set --dry-run --from-str "chain xdp BF_HOOK_XDP ACCEPT rule ip6.dnet eq 2001:db8:://32 counter DROP")
(! bfcli ruleset set --dry-run --from-str "chain xdp BF_HOOK_XDP ACCEPT rule ip6.dnet eq 2001:db8::/32/ counter DROP")
(! bfcli ruleset set --dry-run --from-str "chain xdp BF_HOOK_XDP ACCEPT rule ip6.dnet eq 2001:db8::/32/48 counter DROP")
(! bfcli ruleset set --dry-run --from-str "chain xdp BF_HOOK_XDP ACCEPT rule ip6.dnet eq 2001:db8::/3g counter DROP")
(! bfcli ruleset set --dry-run --from-str "chain xdp BF_HOOK_XDP ACCEPT rule ip6.dnet eq 2001:db8::/xx counter DROP")
(! bfcli ruleset set --dry-run --from-str "chain xdp BF_HOOK_XDP ACCEPT rule ip6.dnet eq /64 counter DROP")
(! bfcli ruleset set --dry-run --from-str "chain xdp BF_HOOK_XDP ACCEPT rule ip6.dnet eq 2001:db8::1/ counter DROP")
(! bfcli ruleset set --dry-run --from-str "chain xdp BF_HOOK_XDP ACCEPT rule ip6.dnet eq /128/ counter DROP")
(! bfcli ruleset set --dry-run --from-str "chain xdp BF_HOOK_XDP ACCEPT rule ip6.dnet eq /2001:db8::/32 counter DROP")

bfcli ruleset set --dry-run --from-str "chain xdp BF_HOOK_XDP ACCEPT rule ip6.dnet not 2001:db8::/32 counter DROP"
bfcli ruleset set --dry-run --from-str "chain xdp BF_HOOK_XDP ACCEPT rule ip6.dnet not 2001:db8:85a3::/48 counter DROP"
bfcli ruleset set --dry-run --from-str "chain xdp BF_HOOK_XDP ACCEPT rule ip6.dnet not fe80::/10 counter DROP"
bfcli ruleset set --dry-run --from-str "chain xdp BF_HOOK_XDP ACCEPT rule ip6.dnet not 2001:db8:85a3:8d3::/64 counter DROP"
bfcli ruleset set --dry-run --from-str "chain xdp BF_HOOK_XDP ACCEPT rule ip6.dnet not 2001:0db8:85a3:0000::/64 counter DROP"
bfcli ruleset set --dry-run --from-str "chain xdp BF_HOOK_XDP ACCEPT rule ip6.dnet not 2001:db8::1/128 counter DROP"
bfcli ruleset set --dry-run --from-str "chain xdp BF_HOOK_XDP ACCEPT rule ip6.dnet not ::1/128 counter DROP"
bfcli ruleset set --dry-run --from-str "chain xdp BF_HOOK_XDP ACCEPT rule ip6.dnet not ::/0 counter DROP"
bfcli ruleset set --dry-run --from-str "chain xdp BF_HOOK_XDP ACCEPT rule ip6.dnet not 2001:db8::8a2e:370:7334/96 counter DROP"
bfcli ruleset set --dry-run --from-str "chain xdp BF_HOOK_XDP ACCEPT rule ip6.dnet not ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/128 counter DROP"
bfcli ruleset set --dry-run --from-str "chain xdp BF_HOOK_XDP ACCEPT rule ip6.dnet not 0:0:0:0:0:0:0:0/0 counter DROP"
bfcli ruleset set --dry-run --from-str "chain xdp BF_HOOK_XDP ACCEPT rule ip6.dnet not ::0/0 counter DROP"
bfcli ruleset set --dry-run --from-str "chain xdp BF_HOOK_XDP ACCEPT rule ip6.dnet not 2001:0db8:85a3:0000:0000:8a2e:0370:7334/128 counter DROP"

(! bfcli ruleset set --dry-run --from-str "chain xdp BF_HOOK_XDP ACCEPT rule ip6.dnet not notanip counter DROP")
(! bfcli ruleset set --dry-run --from-str "chain xdp BF_HOOK_XDP ACCEPT rule ip6.dnet not 1.1.1.1 counter DROP")
(! bfcli ruleset set --dry-run --from-str "chain xdp BF_HOOK_XDP ACCEPT rule ip6.dnet not 2001::db8::1 counter DROP")
(! bfcli ruleset set --dry-run --from-str "chain xdp BF_HOOK_XDP ACCEPT rule ip6.dnet not 2001:0db8:85a3:0000:0000:8a2e:0370:7334:1234 counter DROP")
(! bfcli ruleset set --dry-run --from-str "chain xdp BF_HOOK_XDP ACCEPT rule ip6.dnet not 2001:db8::/129 counter DROP")
(! bfcli ruleset set --dry-run --from-str "chain xdp BF_HOOK_XDP ACCEPT rule ip6.dnet not 2001:db8::/256 counter DROP")
(! bfcli ruleset set --dry-run --from-str "chain xdp BF_HOOK_XDP ACCEPT rule ip6.dnet not 2001:db8::/-1 counter DROP")
(! bfcli ruleset set --dry-run --from-str "chain xdp BF_HOOK_XDP ACCEPT rule ip6.dnet not 2001:db8::/999 counter DROP")
(! bfcli ruleset set --dry-run --from-str "chain xdp BF_HOOK_XDP ACCEPT rule ip6.dnet not ::ffff:192.168.0.0/96 counter DROP")
(! bfcli ruleset set --dry-run --from-str "chain xdp BF_HOOK_XDP ACCEPT rule ip6.dnet not 2001:0db81:85a3::8a2e:370:7334/48 counter DROP")
(! bfcli ruleset set --dry-run --from-str "chain xdp BF_HOOK_XDP ACCEPT rule ip6.dnet not 2001:xyz8::1/32 counter DROP")
(! bfcli ruleset set --dry-run --from-str "chain xdp BF_HOOK_XDP ACCEPT rule ip6.dnet not gggg::1/128 counter DROP")
(! bfcli ruleset set --dry-run --from-str "chain xdp BF_HOOK_XDP ACCEPT rule ip6.dnet not 2001:db8:://32 counter DROP")
(! bfcli ruleset set --dry-run --from-str "chain xdp BF_HOOK_XDP ACCEPT rule ip6.dnet not 2001:db8::/32/ counter DROP")
(! bfcli ruleset set --dry-run --from-str "chain xdp BF_HOOK_XDP ACCEPT rule ip6.dnet not 2001:db8::/32/48 counter DROP")
(! bfcli ruleset set --dry-run --from-str "chain xdp BF_HOOK_XDP ACCEPT rule ip6.dnet not 2001:db8::/3g counter DROP")
(! bfcli ruleset set --dry-run --from-str "chain xdp BF_HOOK_XDP ACCEPT rule ip6.dnet not 2001:db8::/xx counter DROP")
(! bfcli ruleset set --dry-run --from-str "chain xdp BF_HOOK_XDP ACCEPT rule ip6.dnet not /64 counter DROP")
(! bfcli ruleset set --dry-run --from-str "chain xdp BF_HOOK_XDP ACCEPT rule ip6.dnet not 2001:db8::1/ counter DROP")
(! bfcli ruleset set --dry-run --from-str "chain xdp BF_HOOK_XDP ACCEPT rule ip6.dnet not /128/ counter DROP")
(! bfcli ruleset set --dry-run --from-str "chain xdp BF_HOOK_XDP ACCEPT rule ip6.dnet not /2001:db8::/32 counter DROP")
