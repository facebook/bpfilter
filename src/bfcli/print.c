/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#include "bfcli/print.h"

#include <linux/icmp.h>
#include <linux/icmpv6.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>

#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/socket.h>
#include <time.h>

#include "core/chain.h"
#include "core/counter.h"
#include "core/helper.h"
#include "core/hook.h"
#include "core/list.h"
#include "core/logger.h"
#include "core/matcher.h"
#include "core/rule.h"
#include "core/runtime.h"
#include "core/verdict.h"

struct bfc_chain_opts;

#define INET6_ADDRSTRLEN 46

#define BF_TIME_S 1000000000
#define BF_TIME_US 1000

#define BF_DUMP_HEXDUMP_LEN 8
#define BF_DUMP_TOKEN_LEN 5

#define BF_CHECK_TCP_FLAG(tcphdr, field, flag_enum, flags_str, pos,            \
                          flag_count)                                          \
    if ((tcphdr)->field) {                                                     \
        const char *flag_name = bf_tcp_flag_to_str(flag_enum);                 \
        if (flag_name) {                                                       \
            (pos) += snprintf((flags_str) + (pos), sizeof(flags_str) - (pos),  \
                              "%s%s", (flag_count) > 0 ? "," : "", flag_name); \
            (flag_count)++;                                                    \
        }                                                                      \
    }

extern const char *inet_ntop(int, const void *, char *, socklen_t);

/**
 * Dump a block of memory in hexadecimal format.
 *
 * @param data Pointer to the data to be dumped. Must be non-NULL.
 * @param len Length of the data in bytes.
 */
static void bf_dump_hex_local(const void *data, size_t len)
{
    const void *end = data + len;
    // 5 characters per byte (0x%02x) + 1 for the null terminator.
    char buf[(BF_DUMP_HEXDUMP_LEN * BF_DUMP_TOKEN_LEN) + 1];

    bf_assert(data);

    while (data < end) {
        char *line = buf;
        for (size_t i = 0; i < BF_DUMP_HEXDUMP_LEN && data < end; ++i, ++data)
            line += sprintf(line, "0x%02x ", *(unsigned char *)data);

        (void)fprintf(stdout, "%s", buf);
    }
}

void bfc_chain_dump(struct bf_chain *chain, struct bf_hookopts *hookopts,
                    bf_list *counters)
{
    struct bf_counter *counter;
    bf_list_node *counter_node, *policy_counter_node, *err_counter_node;
    bool need_comma = false;

    bf_assert(chain && counters);

    if (bf_list_size(counters) != bf_list_size(&chain->rules) + 2) {
        bf_err(
            "chain %s is corrupted: total number of counters doesn't match the number of rules and chain counters",
            chain->name);
        return;
    }

    // Last counter is the error counter, the chain counter is second to last
    counter_node = bf_list_get_head(counters);
    err_counter_node = bf_list_get_tail(counters);
    policy_counter_node = bf_list_node_prev(err_counter_node);

    (void)fprintf(stdout, "chain %s %s", chain->name,
                  bf_hook_to_str(chain->hook));
    if (hookopts) {
        (void)fprintf(stdout, "{");

        if (bf_hookopts_is_used(hookopts, BF_HOOKOPTS_IFINDEX)) {
            (void)fprintf(stdout, "%sifindex=%d", need_comma ? "," : "",
                          hookopts->ifindex);
            need_comma = true;
        }

        if (bf_hookopts_is_used(hookopts, BF_HOOKOPTS_CGPATH)) {
            (void)fprintf(stdout, "%scgpath=%s", need_comma ? "," : "",
                          hookopts->cgpath);
            need_comma = true;
        }

        if (bf_hookopts_is_used(hookopts, BF_HOOKOPTS_FAMILY)) {
            (void)fprintf(stdout, "%sfamily=%s", need_comma ? "," : "",
                          hookopts->family == PF_INET ? "inet4" : "inet6");
            need_comma = true;
        }

        if (bf_hookopts_is_used(hookopts, BF_HOOKOPTS_FAMILY)) {
            (void)fprintf(stdout, "%spriorities=%d-%d", need_comma ? "," : "",
                          hookopts->priorities[0], hookopts->priorities[1]);
            need_comma = true;
        }

        (void)fprintf(stdout, "}");
    }

    (void)fprintf(stdout, " %s\n", bf_verdict_to_str(chain->policy));

    counter = bf_list_node_get_data(policy_counter_node);
    (void)fprintf(stdout, "    counters policy %lu packets %lu bytes; ",
                  counter->packets, counter->bytes);

    counter = bf_list_node_get_data(err_counter_node);
    (void)fprintf(stdout, "error %lu packets %lu bytes\n", counter->packets,
                  counter->bytes);

    // Loop over rules
    bf_list_foreach (&chain->rules, rule_node) {
        struct bf_rule *rule = bf_list_node_get_data(rule_node);

        (void)fprintf(stdout, "    rule\n");
        bf_list_foreach (&rule->matchers, matcher_node) {
            struct bf_matcher *matcher = bf_list_node_get_data(matcher_node);
            const struct bf_matcher_ops *ops =
                bf_matcher_get_ops(matcher->type, matcher->op);

            (void)fprintf(stdout, "        %s",
                          bf_matcher_type_to_str(matcher->type));
            (void)fprintf(stdout, " %s ", bf_matcher_op_to_str(matcher->op));

            if (ops) {
                ops->printer_cb(matcher);
            } else {
                bf_dump_hex_local(matcher->payload,
                                  matcher->len - sizeof(struct bf_matcher));
            }

            (void)fprintf(stdout, "\n");
        }

        if (rule->log) {
            uint8_t log = rule->log;

            (void)fprintf(stdout, "        log ");

            for (enum bf_pkthdr hdr = 0; hdr < _BF_PKTHDR_MAX; ++hdr) {
                if (!(log & BF_FLAG(hdr)))
                    continue;

                log &= ~BF_FLAG(hdr);
                (void)fprintf(stdout, "%s%s", bf_pkthdr_to_str(hdr),
                              log ? "," : "\n");
            }
        }

        if (rule->counters) {
            counter = bf_list_node_get_data(counter_node);
            (void)fprintf(stdout, "        counters %lu packets %lu bytes\n",
                          counter->packets, counter->bytes);
        }
        counter_node = bf_list_node_next(counter_node);

        (void)fprintf(stdout, "        %s\n", bf_verdict_to_str(rule->verdict));
    }
}

int bfc_ruleset_dump(bf_list *chains, bf_list *hookopts, bf_list *counters)
{
    struct bf_list_node *chain_node;
    struct bf_list_node *hookopts_node;
    struct bf_list_node *counter_node;

    bf_assert(chains && hookopts && counters);

    if (bf_list_size(chains) != bf_list_size(hookopts))
        return -EINVAL;
    if (bf_list_size(counters) != bf_list_size(chains))
        return -EINVAL;

    chain_node = bf_list_get_head(chains);
    hookopts_node = bf_list_get_head(hookopts);
    counter_node = bf_list_get_head(counters);

    while (chain_node) {
        bfc_chain_dump(bf_list_node_get_data(chain_node),
                       bf_list_node_get_data(hookopts_node),
                       bf_list_node_get_data(counter_node));

        chain_node = bf_list_node_next(chain_node);
        hookopts_node = bf_list_node_next(hookopts_node);
        counter_node = bf_list_node_next(counter_node);
    }

    return 0;
}

static const char *_bf_tcp_flags_to_str(const struct tcphdr *tcphdr)
{
    static char flags_str[128];
    int pos = 0;
    int flag_count = 0;

    flags_str[0] = '\0';

    BF_CHECK_TCP_FLAG(tcphdr, fin, BF_TCP_FIN, flags_str, pos, flag_count);
    BF_CHECK_TCP_FLAG(tcphdr, syn, BF_TCP_SYN, flags_str, pos, flag_count);
    BF_CHECK_TCP_FLAG(tcphdr, rst, BF_TCP_RST, flags_str, pos, flag_count);
    BF_CHECK_TCP_FLAG(tcphdr, psh, BF_TCP_PSH, flags_str, pos, flag_count);
    BF_CHECK_TCP_FLAG(tcphdr, ack, BF_TCP_ACK, flags_str, pos, flag_count);
    BF_CHECK_TCP_FLAG(tcphdr, urg, BF_TCP_URG, flags_str, pos, flag_count);
    BF_CHECK_TCP_FLAG(tcphdr, ece, BF_TCP_ECE, flags_str, pos, flag_count);
    BF_CHECK_TCP_FLAG(tcphdr, cwr, BF_TCP_CWR, flags_str, pos, flag_count);

    return flag_count > 0 ? flags_str : NULL;
}

static void _bf_chain_log_header(const struct bf_log *log)
{
    struct timespec time;
    char time_str[64];

    // Convert timestamp to readable format
    time.tv_sec = (long)log->ts / BF_TIME_S;
    time.tv_nsec = (long)log->ts % BF_TIME_S;

    (void)strftime(time_str, sizeof(time_str), "%H:%M:%S",
                   localtime(&time.tv_sec));

    (void)fprintf(stdout, "\n%s[%s.%06ld]%s Packet: %s%llu bytes%s\n",
                  bf_logger_get_color(BF_COLOR_LIGHT_CYAN, BF_STYLE_NORMAL),
                  time_str, time.tv_nsec / BF_TIME_US,
                  bf_logger_get_color(BF_COLOR_RESET, BF_STYLE_RESET),
                  bf_logger_get_color(BF_COLOR_DEFAULT, BF_STYLE_BOLD),
                  log->pkt_size,
                  bf_logger_get_color(BF_COLOR_RESET, BF_STYLE_RESET));
}

static void _bf_chain_log_l2(const struct bf_log *log)
{
    struct ethhdr *ethhdr = (void *)log->l2hdr;
    const char *ethertype;

    if (!(log->headers & (1 << BF_PKTHDR_LINK))) {
        (void)fprintf(stdout, "  Ethernet  : <unknown header>\n");
        return;
    }

    ethertype = bf_ethertype_to_str(be16toh(ethhdr->h_proto));

    // NOLINTBEGIN
    (void)fprintf(
        stdout,
        "  Ethernet  : %s%02x:%02x:%02x:%02x:%02x:%02x%s → %s%02x:%02x:%02x:%02x:%02x:%02x%s",
        bf_logger_get_color(BF_COLOR_YELLOW, BF_STYLE_BOLD),
        ethhdr->h_source[0], ethhdr->h_source[1], ethhdr->h_source[2],
        ethhdr->h_source[3], ethhdr->h_source[4], ethhdr->h_source[5],
        bf_logger_get_color(BF_COLOR_RESET, BF_STYLE_RESET),
        bf_logger_get_color(BF_COLOR_YELLOW, BF_STYLE_BOLD), ethhdr->h_dest[0],
        ethhdr->h_dest[1], ethhdr->h_dest[2], ethhdr->h_dest[3],
        ethhdr->h_dest[4], ethhdr->h_dest[5],
        bf_logger_get_color(BF_COLOR_RESET, BF_STYLE_RESET));
    // NOLINTEND

    if (ethertype)
        (void)fprintf(stdout, " (%s)\n", ethertype);
    else
        (void)fprintf(stdout, " (0x%04x)\n", be16toh(ethhdr->h_proto));
}

static void _bf_chain_log_l3(const struct bf_log *log)
{
    struct iphdr *iphdr;
    struct ipv6hdr *ipv6hdr;
    char src_addr[INET6_ADDRSTRLEN];
    char dst_addr[INET6_ADDRSTRLEN];
    const char *protocol;

    if (!(log->headers & (1 << BF_PKTHDR_INTERNET))) {
        (void)fprintf(stdout, "  Internet  : <unknown header>\n");
        return;
    }

    switch (be16toh(log->l3_proto)) {
    case ETH_P_IP:
        iphdr = (struct iphdr *)log->l3hdr;

        inet_ntop(AF_INET, &iphdr->saddr, src_addr, sizeof(src_addr));
        inet_ntop(AF_INET, &iphdr->daddr, dst_addr, sizeof(dst_addr));
        protocol = bf_ipproto_to_str(iphdr->protocol);

        (void)fprintf(
            stdout, "  IPv4      : %s%-15s%s → %s%-15s%s",
            bf_logger_get_color(BF_COLOR_CYAN, BF_STYLE_BOLD), src_addr,
            bf_logger_get_color(BF_COLOR_RESET, BF_STYLE_RESET),
            bf_logger_get_color(BF_COLOR_CYAN, BF_STYLE_BOLD), dst_addr,
            bf_logger_get_color(BF_COLOR_RESET, BF_STYLE_RESET));

        if (protocol) {
            (void)fprintf(
                stdout, " [%s%s%s, TTL=%u]\n",
                bf_logger_get_color(BF_COLOR_LIGHT_MAGENTA, BF_STYLE_BOLD),
                protocol, bf_logger_get_color(BF_COLOR_RESET, BF_STYLE_RESET),
                iphdr->ttl);
        } else {
            (void)fprintf(stdout, " [proto=%u, TTL=%u]\n", iphdr->protocol,
                          iphdr->ttl);
        }
        break;

    case ETH_P_IPV6:
        ipv6hdr = (struct ipv6hdr *)log->l3hdr;

        inet_ntop(AF_INET6, &ipv6hdr->saddr, src_addr, sizeof(src_addr));
        inet_ntop(AF_INET6, &ipv6hdr->daddr, dst_addr, sizeof(dst_addr));
        protocol = bf_ipproto_to_str(ipv6hdr->nexthdr);

        (void)fprintf(
            stdout, "  IPv6      : %s%s%s → %s%s%s",
            bf_logger_get_color(BF_COLOR_LIGHT_CYAN, BF_STYLE_BOLD), src_addr,
            bf_logger_get_color(BF_COLOR_RESET, BF_STYLE_RESET),
            bf_logger_get_color(BF_COLOR_LIGHT_CYAN, BF_STYLE_BOLD), dst_addr,
            bf_logger_get_color(BF_COLOR_RESET, BF_STYLE_RESET));

        if (protocol) {
            (void)fprintf(
                stdout, " [%s%s%s, Hop=%u]\n",
                bf_logger_get_color(BF_COLOR_LIGHT_MAGENTA, BF_STYLE_BOLD),
                protocol, bf_logger_get_color(BF_COLOR_RESET, BF_STYLE_RESET),
                ipv6hdr->hop_limit);
        } else {
            (void)fprintf(stdout, " [nexthdr=%u, Hop=%u]\n", ipv6hdr->nexthdr,
                          ipv6hdr->hop_limit);
        }
        break;

    default:
        (void)fprintf(stdout, "  Internet  : <unknown protocol 0x%04x>\n",
                      be16toh(log->l3_proto));
    }
}

static void _bf_chain_log_l4(const struct bf_log *log)
{
    struct icmphdr *icmphdr;
    struct icmp6hdr *icmp6hdr;
    struct tcphdr *tcphdr;
    struct udphdr *udphdr;
    const char *tcp_flags_str;

    if (!(log->headers & (1 << BF_PKTHDR_TRANSPORT))) {
        (void)fprintf(stdout, "  Transport : <unknown header>\n");
        return;
    }

    switch (log->l4_proto) {
    case IPPROTO_TCP:
        tcphdr = (struct tcphdr *)log->l4hdr;
        tcp_flags_str = _bf_tcp_flags_to_str(tcphdr);

        (void)fprintf(stdout, "  TCP       : %s%-5u%s → %s%-5u%s",
                      bf_logger_get_color(BF_COLOR_LIGHT_YELLOW, BF_STYLE_BOLD),
                      be16toh(tcphdr->source),
                      bf_logger_get_color(BF_COLOR_RESET, BF_STYLE_RESET),
                      bf_logger_get_color(BF_COLOR_LIGHT_YELLOW, BF_STYLE_BOLD),
                      be16toh(tcphdr->dest),
                      bf_logger_get_color(BF_COLOR_RESET, BF_STYLE_RESET));

        if (tcp_flags_str) {
            (void)fprintf(
                stdout, " [%s%s%s]",
                bf_logger_get_color(BF_COLOR_LIGHT_GREEN, BF_STYLE_BOLD),
                tcp_flags_str,
                bf_logger_get_color(BF_COLOR_RESET, BF_STYLE_RESET));
        }

        (void)fprintf(stdout, "\n              seq=%-10u ack=%-10u win=%-5u\n",
                      be32toh(tcphdr->seq), be32toh(tcphdr->ack_seq),
                      be16toh(tcphdr->window));
        break;

    case IPPROTO_UDP:
        udphdr = (struct udphdr *)log->l4hdr;

        (void)fprintf(stdout, "  UDP       : %s%-5u%s → %s%-5u%s [len=%u]\n",
                      bf_logger_get_color(BF_COLOR_LIGHT_YELLOW, BF_STYLE_BOLD),
                      be16toh(udphdr->source),
                      bf_logger_get_color(BF_COLOR_RESET, BF_STYLE_RESET),
                      bf_logger_get_color(BF_COLOR_LIGHT_YELLOW, BF_STYLE_BOLD),
                      be16toh(udphdr->dest),
                      bf_logger_get_color(BF_COLOR_RESET, BF_STYLE_RESET),
                      be16toh(udphdr->len));
        break;

    case IPPROTO_ICMP:
        icmphdr = (struct icmphdr *)log->l4hdr;

        (void)fprintf(stdout, "  ICMP      : type=%-3u code=%-3u",
                      icmphdr->type, icmphdr->code);

        if (icmphdr->type == ICMP_ECHO || icmphdr->type == ICMP_ECHOREPLY) {
            (void)fprintf(stdout, " [id=%u seq=%u]\n",
                          be16toh(icmphdr->un.echo.id),
                          be16toh(icmphdr->un.echo.sequence));
        } else {
            (void)fprintf(stdout, "\n");
        }
        break;

    case IPPROTO_ICMPV6:
        icmp6hdr = (struct icmp6hdr *)log->l4hdr;

        (void)fprintf(stdout, "  ICMPv6    : type=%-3u code=%-3u",
                      icmp6hdr->icmp6_type, icmp6hdr->icmp6_code);

        if (icmp6hdr->icmp6_type == ICMPV6_ECHO_REQUEST ||
            icmp6hdr->icmp6_type == ICMPV6_ECHO_REPLY) {
            (void)fprintf(stdout, " [id=%u seq=%u]\n",
                          be16toh(icmp6hdr->icmp6_identifier),
                          be16toh(icmp6hdr->icmp6_sequence));
        } else {
            (void)fprintf(stdout, "\n");
        }
        break;

    default:
        (void)fprintf(stdout, "  Transport : <unknown protocol %u>\n",
                      log->l4_proto);
    }
}

void bfc_print_log(const struct bf_log *log)
{
    _bf_chain_log_header(log);

    if (log->req_headers & (1 << BF_PKTHDR_LINK))
        _bf_chain_log_l2(log);
    if (log->req_headers & (1 << BF_PKTHDR_INTERNET))
        _bf_chain_log_l3(log);
    if (log->req_headers & (1 << BF_PKTHDR_TRANSPORT))
        _bf_chain_log_l4(log);
}
