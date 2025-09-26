chain nf_post_routing BF_HOOK_NF_POST_ROUTING ACCEPT
    set my_custom_set (ip4.saddr, ip4.proto) in {
        192.168.1.1, tcp
        192.168.1.1, udp
    }

    rule
        meta.dport eq 22
        log internet
        counter
        ACCEPT
    rule
        meta.dport eq 22
        counter
        log internet
        ACCEPT
    rule
        meta.dport eq 22
        ACCEPT
    rule
        meta.iface eq lo
        meta.iface eq 1
        counter
        ACCEPT
    rule
        meta.l3_proto eq ipv4
        meta.l3_proto eq ipv6
        meta.l3_proto eq IPv4
        meta.l3_proto eq IPv6
        meta.l3_proto eq 1024
        meta.l3_proto eq 0x0600
        counter
        ACCEPT
    rule
        meta.l4_proto eq icmp
        meta.l4_proto eq ICMPv6
        meta.l4_proto eq 6
        counter
        ACCEPT
    rule
        meta.sport eq 0
        meta.sport eq 17
        meta.sport eq 65535
        meta.sport not 0
        meta.sport not 17
        meta.sport not 65535
        meta.sport range 0-65535
        meta.sport range 17-31
        meta.dport eq 0
        meta.dport eq 17
        meta.dport eq 65535
        meta.dport not 0
        meta.dport not 17
        meta.dport not 65535
        meta.dport range 0-65535
        meta.dport range 17-31
        counter
        ACCEPT
    rule
        meta.probability eq 0%
        meta.probability eq 50%
        meta.probability eq 100%
        counter
        ACCEPT
    rule
        meta.mark eq 15
        meta.mark eq 0x115
        counter
        ACCEPT
    rule
        ip4.saddr eq 1.1.1.1
        ip4.saddr not 1.1.1.1
        counter
        ACCEPT
    rule
        ip4.daddr eq 1.1.1.1
        ip4.daddr not 1.1.1.1
        counter
        ACCEPT
    rule
        ip4.snet eq 1.1.1.1/24
        ip4.snet not 192.168.1.1/10
        counter
        ACCEPT
    rule
        ip4.dnet eq 1.1.1.1/26
        ip4.dnet not 192.168.1.1/12
        counter
        ACCEPT
    rule
        ip4.proto eq icmp
        ip4.proto eq ICMPv6
        ip4.proto eq 6
        counter
        ACCEPT
    rule
        ip6.nexthdr eq tcp
        ip6.nexthdr eq udp
        ip6.nexthdr eq icmpv6
        counter
        ACCEPT
    rule
        ip6.saddr eq 2001:0db8:85a3:0000:0000:8a2e:0370:7334
        ip6.saddr eq 2001:db8:85a3::8a2e:370:7334
        ip6.saddr not ::1
        ip6.saddr not 2001:db8::1
        counter
        ACCEPT
    rule
        ip6.daddr eq 2001:0db8:85a3:0000:0000:8a2e:0370:7334
        ip6.daddr eq 2001:db8:85a3::8a2e:370:7334
        ip6.daddr not ::1
        ip6.daddr not 2001:db8::1
        counter
        CONTINUE
    rule
        ip6.snet eq 2001:db8::1/42
        ip6.snet eq 2001:0db8:85a3:0000:0000:8a2e:0370:7334/64
        ip6.snet eq 2001:0db8:85a3:0000:0000:8a2e:0370:7334/128
        ip6.snet not ::1/64
        ip6.snet not ::1/128
        counter
        CONTINUE
    rule
        ip6.dnet eq 2001:0db8:85a3:0000:0000:8a2e:0370:7334/64
        ip6.dnet eq 2001:0db8:85a3:0000:0000:8a2e:0370:7334/128
        ip6.dnet not ::1/64
        ip6.dnet not ::1/128
        counter
        CONTINUE
    rule
        ip6.nexthdr eq tcp
        ip6.nexthdr eq 21
        ip6.nexthdr eq 15
        ip6.nexthdr eq hop
        ip6.nexthdr eq routing
        counter
        CONTINUE
    rule
        tcp.sport eq 0
        tcp.sport eq 17
        tcp.sport eq 65535
        tcp.sport not 0
        tcp.sport not 17
        tcp.sport not 65535
        (tcp.sport) in {16;124;6463}
        tcp.sport range 0-65535
        tcp.sport range 17-31
        tcp.dport eq 0
        tcp.dport eq 17
        tcp.dport eq 65535
        tcp.dport not 0
        tcp.dport not 17
        tcp.dport not 65535
        (tcp.dport) in {16;124;6463}
        tcp.dport range 0-65535
        tcp.dport range 17-31
        counter
        ACCEPT
    rule
        tcp.flags eq SYN
        tcp.flags eq ACK
        tcp.flags not ECE
        tcp.flags not CWR
        tcp.flags any ack
        tcp.flags any SYN,ack
        tcp.flags any cwr,ece,syn
        tcp.flags all ack
        tcp.flags all SYN,ack
        tcp.flags all cwr,ece,syn
        counter
        ACCEPT
    rule
        udp.sport eq 0
        udp.sport eq 17
        udp.sport eq 65535
        udp.sport not 0
        udp.sport not 17
        udp.sport not 65535
        (udp.sport) in {16;124;6463}
        udp.sport range 0-65535
        udp.sport range 17-31
        udp.dport eq 0
        udp.dport eq 17
        udp.dport eq 65535
        udp.dport not 0
        udp.dport not 17
        udp.dport not 65535
        (udp.dport) in {16;124;6463}
        udp.dport range 0-65535
        udp.dport range 17-31
        counter
        ACCEPT
    rule
        icmp.type eq echo-reply
        icmp.type eq 8
        icmp.type eq 0x08
        icmp.type not echo-reply
        icmp.type not 8
        icmp.type not 0x08
        counter
        ACCEPT
    rule
        icmp.code eq 17
        icmp.code eq 0x17
        icmp.code not 17
        icmp.code not 0x17
        counter
        ACCEPT
    rule
        icmpv6.type eq echo-reply
        icmpv6.type eq 8
        icmpv6.type eq 0x08
        icmpv6.type not echo-reply
        icmpv6.type not 8
        icmpv6.type not 0x08
        counter
        ACCEPT
    rule
        icmpv6.code eq 17
        icmpv6.code eq 0x17
        icmpv6.code not 17
        icmpv6.code not 0x17
        counter
        ACCEPT
    rule
        (ip4.saddr, ip4.proto) in my_custom_set
        (ip4.saddr, ip4.proto) in {
            192.168.1.131, tcp
            192.168.1.132, udp
        }
        (ip6.snet) in {
            fdb2:2c26:f4e4::1/128
            fdb2:2c26:f4e4::1/64
        }
        (ip6.dnet) in {
            fdb2:2c26:f4e4:0:21c:42ff:fe09:1a95/128
            fdb2:2c26:f4e4:0:21c:42ff:fe09:1a95/127
            fdb2:2c26:f4e4:0:21c:42ff:fe09:1a95/126
        }
        counter
        ACCEPT
