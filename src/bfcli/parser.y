/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

%{
    #include <stdio.h>
    #include <stdlib.h>
    #include <stdbool.h>

    #include "core/list.h"

    extern int yylex();
    extern int yyparse();
    extern FILE *yyin;

    struct bf_ruleset;

    void yyerror(struct bf_ruleset *ruleset, const char *fmt, ...);
%}

%code requires {
    #include <linux/in.h>
    #include <linux/in6.h>
    #include <linux/if_ether.h>
    #include <limits.h>
    #include "core/verdict.h"
    #include "core/hook.h"
    #include "core/matcher.h"
    #include "core/list.h"
    #include "core/rule.h"
    #include "core/chain.h"
    #include "core/set.h"

    extern int inet_pton(int af, const char *restrict src, void *restrict dst);

    #define AF_INET     2
    #define AF_INET6    10

    #define min(a,b)             \
    ({                           \
        __typeof__ (a) _a = (a); \
        __typeof__ (b) _b = (b); \
        _a < _b ? _a : _b;       \
    })

    #define bf_parse_err(fmt, ...)                                             \
    ({                                                                         \
        yyerror(ruleset, fmt, ##__VA_ARGS__);                                  \
        YYABORT;                                                               \
    })

    struct bf_ruleset
    {
        bf_list chains;
        bf_list sets;
    };
}

%define parse.error detailed
%parse-param {struct bf_ruleset *ruleset}

%union {
    bool bval;
    char *sval;
    enum bf_verdict verdict;
    enum bf_hook hook;
    enum bf_matcher_type matcher_type;
    bf_list *list;
    struct bf_matcher *matcher;
    struct bf_rule *rule;
    struct bf_chain *chain;
    enum bf_matcher_op matcher_op;
}

// Tokens
%token CHAIN
%token POLICY
%token RULE
%token COUNTER
%token <sval> HOOK_OPT
%token <sval> MATCHER_META_IFINDEX  MATCHER_META_L3_PROTO MATCHER_META_L4_PROTO
%token <sval> MATCHER_IP_PROTO MATCHER_IPADDR
%token <sval> MATCHER_IP_ADDR_SET
%token <sval> MATCHER_IP6_ADDR
%token <sval> MATCHER_PORT MATCHER_PORT_RANGE
%token <sval> STRING
%token <sval> HOOK VERDICT MATCHER_TYPE MATCHER_OP MATCHER_TCP_FLAGS

// Grammar types
%type <bval> counter

%type <hook> hook

%type <list> raw_hook_opts
%destructor { bf_list_free(&$$); } raw_hook_opts

%type <verdict> verdict

%type <matcher_type> matcher_type

%type <matcher_op> matcher_op

%type <list> matchers
%destructor { bf_list_free(&$$); } matchers

%type <matcher> matcher
%destructor { bf_matcher_free(&$$); } matcher

%type <list> rules
%destructor { bf_list_free(&$$); } rules

%type <rule> rule
%destructor { bf_rule_free(&$$); } rule

%type <chain> chain
%destructor { bf_chain_free(&$$); } chain

%%
chains          : chain
                {
                    if (bf_list_add_tail(&ruleset->chains, $1) < 0)
                        bf_parse_err("failed to add chain into bf_list\n");

                    TAKE_PTR($1);
                }
                | chains chain
                {
                    if (bf_list_add_tail(&ruleset->chains, $2) < 0)
                        bf_parse_err("failed to insert chain into bf_list\n");

                    TAKE_PTR($2);
                }
                ;

chain           : CHAIN hook raw_hook_opts POLICY verdict rules
                {
                    _cleanup_bf_chain_ struct bf_chain *chain = NULL;
                    _cleanup_bf_list_ bf_list *raw_hook_opts = $3;
                    _cleanup_bf_list_ bf_list *rules = $6;

                    if ($5 >= _BF_TERMINAL_VERDICT_MAX)
                        bf_parse_err("'%s' is not supported for chains\n", bf_verdict_to_str($5));

                    if (bf_chain_new(&chain, $2, $5, &ruleset->sets, rules) < 0)
                        bf_parse_err("failed to create a new bf_chain\n");

                    if (bf_hook_opts_init(&chain->hook_opts, chain->hook, raw_hook_opts) < 0)
                        bf_parse_err("failed to parse hook options");


                    $$ = TAKE_PTR(chain);
                }

verdict         : VERDICT
                {
                    enum bf_verdict verdict;

                    if (bf_verdict_from_str($1, &verdict) < 0)
                        bf_parse_err("unknown verdict '%s'\n", $1);

                    free($1);
                    $$ = verdict;
                }

hook            : HOOK
                {
                    enum bf_hook hook;

                    if (bf_hook_from_str($1, &hook) < 0)
                        bf_parse_err("unknown hook '%s'\n", $1);

                    free($1);
                    $$ = hook;
                }

raw_hook_opts   : %empty { $$ = NULL; }
                | raw_hook_opts HOOK_OPT
                {
                    _cleanup_bf_list_ bf_list *list = $1;

                    if (bf_list_add_tail(list, $2) < 0)
                        bf_parse_err("failed to insert raw hook options '%s' in list", $2);

                    $$ = TAKE_PTR(list);
                }
                | HOOK_OPT
                {
                    _cleanup_bf_list_ bf_list *hook_opts = NULL;

                    if (bf_list_new(&hook_opts, (bf_list_ops[]){{.free = (bf_list_ops_free)freep}}) < 0)
                        bf_parse_err("failed to allocate a new bf_list for raw hook options");

                    if (bf_list_add_tail(hook_opts, $1) < 0)
                        bf_parse_err("failed to insert raw hook option '%s' in list", $1);

                    $$ = TAKE_PTR(hook_opts);
                }
                ;

rules           : %empty { $$ = NULL; }
                | rule
                {
                    _cleanup_bf_list_ bf_list *list = NULL;

                    if (bf_list_new(&list, (bf_list_ops[]){{.free = (bf_list_ops_free)bf_rule_free, .marsh = (bf_list_ops_marsh)bf_rule_marsh}}) < 0)
                        bf_parse_err("failed to allocate a new bf_list for bf_rule\n");

                    if (bf_list_add_tail(list, $1) < 0)
                        bf_parse_err("failed to add rule into bf_list\n");

                    TAKE_PTR($1);
                    $$ = TAKE_PTR(list);
                }
                | rules rule
                {
                    if (bf_list_add_tail($1, $2) < 0)
                        bf_parse_err("failed to insert rule into bf_list\n");

                    TAKE_PTR($2);
                    $$ = TAKE_PTR($1);
                }
                ;
rule            : RULE matchers counter verdict
                {
                    _cleanup_bf_rule_ struct bf_rule *rule = NULL;

                    if (bf_rule_new(&rule) < 0)
                        bf_parse_err("failed to create a new bf_rule\n");

                    rule->counters = $3;
                    rule->verdict = $4;

                    bf_list_foreach ($2, matcher_node) {
                        struct bf_matcher *matcher = bf_list_node_get_data(matcher_node);

                        if (bf_list_add_tail(&rule->matchers, matcher) < 0)
                            bf_parse_err("failed to add matcher to the rule\n");

                        bf_list_node_take_data(matcher_node);
                    }

                    bf_list_free(&$2);
                    $$ = TAKE_PTR(rule);
                }
                ;

matchers        : matcher
                {
                    _cleanup_bf_list_ bf_list *list = NULL;

                    if (bf_list_new(&list, (bf_list_ops[]){{.free = (bf_list_ops_free)bf_matcher_free, .marsh = (bf_list_ops_marsh)bf_matcher_marsh}}) < 0)
                        bf_parse_err("failed to allocate a new bf_list for bf_matcher\n");

                    if (bf_list_add_tail(list, $1) < 0)
                        bf_parse_err("failed to insert matcher into bf_list\n");

                    TAKE_PTR($1);
                    $$ = TAKE_PTR(list);
                }
                | matchers matcher
                {
                    if (bf_list_add_tail($1, $2) < 0)
                        bf_parse_err("failed to insert matcher into bf_list\n");

                    TAKE_PTR($2);
                    $$ = TAKE_PTR($1);
                }
                ;
matcher         : matcher_type matcher_op MATCHER_META_IFINDEX
                {
                    _cleanup_bf_matcher_ struct bf_matcher *matcher = NULL;
                    unsigned long lifindex;
                    uint32_t ifindex;

                    errno = 0;
                    lifindex = strtoul($3, NULL, 0);
                    if (errno != 0)
                        bf_parse_err("failed to parse interface index '%s'", $3);

                    if (lifindex > UINT_MAX)
                        bf_parse_err("interface index is expected to be at most %u, but is %lu", UINT_MAX, lifindex);

                    ifindex = (uint32_t)lifindex;

                    free($3);

                    if (bf_matcher_new(&matcher, $1, $2, &ifindex, sizeof(ifindex)) < 0)
                        bf_parse_err("failed to create a new matcher\n");

                    $$ = TAKE_PTR(matcher);
                }
                | matcher_type matcher_op MATCHER_META_L3_PROTO
                {
                    _cleanup_bf_matcher_ struct bf_matcher *matcher = NULL;
                    uint16_t proto;

                    if (bf_streq($3, "ipv4"))
                        proto = ETH_P_IP;
                    else if (bf_streq($3, "ipv6"))
                        proto = ETH_P_IPV6;
                    else
                        bf_parse_err("unsupported L3 protocol to match '%s'\n", $3);

                    free($3);

                    if (bf_matcher_new(&matcher, $1, $2, &proto, sizeof(proto)) < 0)
                        bf_parse_err("failed to create a new matcher\n");

                    $$ = TAKE_PTR(matcher);
                }
                | matcher_type matcher_op MATCHER_META_L4_PROTO
                {
                    _cleanup_bf_matcher_ struct bf_matcher *matcher = NULL;
                    uint8_t proto;

                    if (bf_streq($3, "icmp"))
                        proto = IPPROTO_ICMP;
                    else if (bf_streq($3, "tcp"))
                        proto = IPPROTO_TCP;
                    else if (bf_streq($3, "udp"))
                        proto = IPPROTO_UDP;
                    else if (bf_streq($3, "icmp6"))
                        proto = IPPROTO_ICMPV6;
                    else
                        bf_parse_err("unsupported L4 protocol to match '%s'\n", $3);

                    free($3);

                    if (bf_matcher_new(&matcher, $1, $2, &proto, sizeof(proto)) < 0)
                        bf_parse_err("failed to create a new matcher\n");

                    $$ = TAKE_PTR(matcher);
                }
                | matcher_type matcher_op MATCHER_IP_PROTO
                {
                    _cleanup_bf_matcher_ struct bf_matcher *matcher = NULL;
                    uint8_t proto;

                    if (bf_streq($3, "icmp"))
                        proto = IPPROTO_ICMP;
                    else
                        bf_parse_err("unsupported ip4.proto value '%s'\n", $3);

                    free($3);

                    if (bf_matcher_new(&matcher, $1, $2, &proto, sizeof(proto)) < 0)
                        bf_parse_err("failed to create a new matcher\n");

                    $$ = TAKE_PTR(matcher);
                }
                | matcher_type matcher_op MATCHER_IPADDR
                {
                    _cleanup_bf_matcher_ struct bf_matcher *matcher = NULL;
                    struct bf_matcher_ip4_addr addr;
                    char *mask;
                    int r;

                    // If '/' is found, parse the mask, otherwise use /32.
                    mask = strchr($3, '/');
                    if (mask) {
                        *mask = '\0';
                        ++mask;

                        int m = atoi(mask);
                        if (m == 0)
                            bf_parse_err("failed to parse IPv4 mask: %s\n", mask);

                        addr.mask = ((uint32_t)~0) << (32 - m);
                    } else {
                        addr.mask = (uint32_t)~0;
                    }

                    // Convert the IPv4 from string to uint32_t.
                    r = inet_pton(AF_INET, $3, &addr.addr);
                    if (r != 1)
                        bf_parse_err("failed to parse IPv4 adddress: %s\n", $3);

                    free($3);

                    if (bf_matcher_new(&matcher, $1, $2, &addr, sizeof(addr)))
                        bf_parse_err("failed to create a new matcher\n");

                    $$ = TAKE_PTR(matcher);
                }
                | matcher_type matcher_op MATCHER_IP_ADDR_SET
                {
                    _cleanup_bf_matcher_ struct bf_matcher *matcher = NULL;
                    _cleanup_bf_set_ struct bf_set *set = NULL;
                    uint32_t set_id = bf_list_size(&ruleset->sets);
                    int r;

                    char *data = $3 + 1;
                    data[strlen(data) - 1] = '\0';

                    r = bf_set_new(&set, BF_SET_IP4);
                    if (r < 0)
                        bf_parse_err("failed to create a new set\n");

                    char *ip;
                    char *next = data;
                    do {
                        _cleanup_free_ uint32_t *value = malloc(sizeof(uint32_t));
                        if (!value)
                            bf_parse_err("failed to allocate memory for IPv4 address\n");

                        ip = next;
                        next = strchr(ip, ',');

                        if (next) {
                            *next = '\0';
                            ++next;

                            // Handle trailing comma
                            if (*next == '\0')
                                next = NULL;
                        }

                        r = inet_pton(AF_INET, ip, value);
                        if (r != 1)
                            bf_parse_err("failed to parse IPv4 address: %s\n", ip);

                        r = bf_set_add_elem(set, value);
                        if (r < 0)
                            bf_parse_err("failed to add element to set\n");
                    } while (next);

                    r = bf_list_add_tail(&ruleset->sets, set);
                    if (r < 0)
                        bf_parse_err("failed to add new set to list of sets\n");

                    TAKE_PTR(set);

                    free($3);

                    if (bf_matcher_new(&matcher, $1, $2, &set_id, sizeof(set_id)))
                        bf_parse_err("failed to create a new matcher\n");

                    $$ = TAKE_PTR(matcher);
                }
                | matcher_type matcher_op MATCHER_IP6_ADDR
                {
                    _cleanup_bf_matcher_ struct bf_matcher *matcher = NULL;
                    struct bf_matcher_ip6_addr addr = {};
                    char *mask_str;
                    int mask = 128;
                    int r;

                    // If '/' is found, parse the mask, otherwise use /128.
                    mask_str = strchr($3, '/');
                    if (mask_str) {
                        *mask_str = '\0';
                        ++mask_str;

                        mask = atoi(mask_str);
                        if (mask == 0)
                            bf_parse_err("failed to parse IPv6 mask: %s", mask_str);
                    }

                    for (int i = 0; i < mask / 8; ++i)
                        addr.mask[i] = (uint8_t)0xff;
                    
                    if (mask % 8)
                        addr.mask[mask / 8] = (uint8_t)0xff << (8 - mask % 8);

                    // Convert the IPv6 from string to uint64_t[2].
                    r = inet_pton(AF_INET6, $3, addr.addr);
                    if (r != 1)
                        bf_parse_err("failed to parse IPv6 adddress: %s\n", $3);

                    free($3);

                    if (bf_matcher_new(&matcher, $1, $2, &addr, sizeof(addr)))
                        bf_parse_err("failed to create a new matcher\n");

                    $$ = TAKE_PTR(matcher);
                }
                | matcher_type matcher_op MATCHER_PORT
                {
                    _cleanup_bf_matcher_ struct bf_matcher *matcher = NULL;
                    long raw_val;
                    uint16_t port;

                    raw_val = atol($3);
                    if (raw_val <= 0 || USHRT_MAX < raw_val)
                        bf_parse_err("invalid port value: %s\n", $3);

                    port = (uint16_t)raw_val;

                    free($3);

                    if (bf_matcher_new(&matcher, $1, $2, &port, sizeof(port)))
                        bf_parse_err("failed to create new matcher\n");

                    $$ = TAKE_PTR(matcher);
                }
                | matcher_type matcher_op MATCHER_PORT_RANGE
                {
                    _cleanup_bf_matcher_ struct bf_matcher *matcher = NULL;
                    long raw_val;
                    char *end_port_str;
                    uint16_t ports[2];

                    end_port_str = strchr($3, '-');
                    *end_port_str = '\0';
                    ++end_port_str;

                    raw_val = atol($3);
                    if (raw_val < 0 || USHRT_MAX < raw_val)
                        bf_parse_err("invalid port value: %s\n", $3);
                    ports[0] = (uint16_t)raw_val;

                    raw_val = atol(end_port_str);
                    if (raw_val < 0 || USHRT_MAX < raw_val)
                        bf_parse_err("invalid port value: %s\n", end_port_str);
                    ports[1] = (uint16_t)raw_val;

                    free($3);

                    if (bf_matcher_new(&matcher, $1, $2, ports, sizeof(ports)))
                        bf_parse_err("failed to create new matcher\n");

                    $$ = TAKE_PTR(matcher);
                }
                | matcher_type matcher_op MATCHER_TCP_FLAGS
                {
                    _cleanup_bf_matcher_ struct bf_matcher *matcher = NULL;
                    uint8_t flags = 0;
                    char *flags_str;
                    char *saveptr;
                    char *token;
                    int r;

                    for (flags_str = $3; ; flags_str = NULL) {
                        enum bf_matcher_tcp_flag flag;

                        token = strtok_r(flags_str, ",", &saveptr);
                        if (!token)
                            break;

                        r = bf_matcher_tcp_flag_from_str(token, &flag);
                        if (r) {
                            bf_parse_err("Unknown TCP flag '%s', ignoring\n", token);
                            continue;
                        }

                        flags |= 1 << flag;
                    }

                    free($3);

                    if (bf_matcher_new(&matcher, $1, $2, &flags, sizeof(flags)))
                        bf_parse_err("failed to create a new matcher\n");

                    $$ = TAKE_PTR(matcher);
                }
                ;
matcher_type    : MATCHER_TYPE
                {
                    enum bf_matcher_type type;

                    if (bf_matcher_type_from_str($1, &type) < 0)
                        bf_parse_err("unknown matcher type '%s'\n", $1);

                    free($1);
                    $$ = type;
                }
matcher_op      : %empty { $$ = BF_MATCHER_EQ; }
                | MATCHER_OP
                {
                    enum bf_matcher_op op;

                    if (bf_matcher_op_from_str($1, &op) < 0)
                        bf_parse_err("unknown matcher operator '%s'\n", $1);

                    free($1);
                    $$ = op;
                }
                ;

counter         : %empty    { $$ = false; }
                | COUNTER   { $$ = true; }
                ;
%%
