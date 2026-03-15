chain cgroup_sock_addr_connect4 BF_HOOK_CGROUP_SOCK_ADDR_CONNECT4 ACCEPT
    rule
        meta.l3_proto eq ipv4
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
        ip4.daddr eq 1.1.1.1
        ip4.daddr eq 255.255.255.255
        ip4.daddr not 10.0.0.1
        counter
        ACCEPT
    rule
        ip4.dnet eq 192.168.1.0/24
        ip4.dnet eq 10.0.0.0/8
        ip4.dnet not 172.16.0.0/12
        counter
        ACCEPT
    rule
        ip4.proto eq tcp
        ip4.proto eq udp
        ip4.proto not icmp
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
