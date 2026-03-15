chain cgroup_sock_addr_connect6 BF_HOOK_CGROUP_SOCK_ADDR_CONNECT6 ACCEPT
    rule
        meta.l3_proto eq ipv6
        counter
        ACCEPT
    rule
        meta.l4_proto eq tcp
        meta.l4_proto not udp
        counter
        ACCEPT
    rule
        meta.probability eq 0%
        meta.probability eq 50%
        meta.probability eq 100%
        counter
        ACCEPT
    rule
        meta.dport eq 0
        meta.dport eq 443
        meta.dport eq 65535
        meta.dport not 80
        meta.dport range 0-65535
        meta.dport range 1024-8080
        counter
        ACCEPT
    rule
        ip6.daddr eq 2001:0db8:85a3:0000:0000:8a2e:0370:7334
        ip6.daddr eq 2001:db8::1
        ip6.daddr eq ::1
        ip6.daddr not ::
        counter
        ACCEPT
    rule
        ip6.dnet eq 2001:db8::/32
        ip6.dnet eq fd00::/8
        ip6.dnet eq 2001:0db8:85a3:0000:0000:8a2e:0370:7334/128
        ip6.dnet not ::1/128
        counter
        ACCEPT
    rule
        tcp.dport eq 0
        tcp.dport eq 443
        tcp.dport eq 65535
        tcp.dport not 22
        tcp.dport range 0-65535
        tcp.dport range 8000-9000
        counter
        ACCEPT
    rule
        udp.dport eq 0
        udp.dport eq 53
        udp.dport eq 65535
        udp.dport not 123
        udp.dport range 0-65535
        udp.dport range 1024-4096
        counter
        ACCEPT
