#!/usr/bin/env bash

bfcli ruleset set --dry-run --from-str "chain xdp BF_HOOK_XDP ACCEPT
    set myset (ip4.saddr) in {
        192.168.1.1;
        192.168.1.2
    }
    rule
        (ip4.saddr) in myset
        counter
        ACCEPT
"
bfcli ruleset set --dry-run --from-str "chain xdp BF_HOOK_XDP ACCEPT
    set myset (ip4.saddr, ip4.proto) in {
        192.168.1.1, tcp;
        192.168.1.2, udp
    }
    rule
        (ip4.saddr, ip4.proto) in myset
        counter
        ACCEPT
"

(! bfcli ruleset set --dry-run --from-str "chain xdp BF_HOOK_XDP ACCEPT set myset (ip4.saddr) eq { 192.168.1.1 }")
(! bfcli ruleset set --dry-run --from-str "chain xdp BF_HOOK_XDP ACCEPT set myset (ip4.saddr, meta.ifindex) in { 192.168.1.1 }")
(! bfcli ruleset set --dry-run --from-str "chain xdp BF_HOOK_XDP ACCEPT set myset (ip4.saddr, ip4.proto) in { 192.168.1.1 }")
(! bfcli ruleset set --dry-run --from-str "chain xdp BF_HOOK_XDP ACCEPT
    set myset (ip4.saddr) in { 192.168.1.1 }
    rule (ip4.daddr) in myset
")
(! bfcli ruleset set --dry-run --from-str "chain xdp BF_HOOK_XDP ACCEPT
    set myset (ip4.saddr) in { 192.168.1.1 }
    rule (ip4.daddr) in my_set
")
