/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

%{
    #include <endian.h>
    #include <stdio.h>
    #include <stdlib.h>
    #include <stdbool.h>

    #include "core/list.h"
    #include "bfcli/ruleset.h"

    extern int yylex();
    extern int yyparse();
    extern FILE *yyin;

    void yyerror(struct bfc_ruleset *ruleset, const char *fmt, ...);
%}

%code requires {
    #include <linux/in.h>
    #include <linux/in6.h>
    #include <linux/if_ether.h>
    #include <limits.h>
    #include "bfcli/helper.h"
    #include "bpfilter/cgen/runtime.h"
    #include "core/verdict.h"
    #include "core/hook.h"
    #include "core/matcher.h"
    #include "core/list.h"
    #include "core/rule.h"
    #include "core/chain.h"
    #include "core/set.h"
    #include "core/runtime.h"

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
}

%define parse.error detailed
%parse-param {struct bfc_ruleset *ruleset}

%union {
    bool bval;
    uint8_t u8;
    char *sval;
    enum bf_verdict verdict;
    enum bf_hook hook;
    enum bf_matcher_type matcher_type;
    bf_list *list;
    struct bf_matcher *matcher;
    struct bf_rule *rule;
    struct bf_chain *chain;
    enum bf_matcher_op matcher_op;
    struct bf_hookopts *hookopts;
}

// Tokens
%token CHAIN
%token RULE
%token LOG COUNTER
%token <sval> LOG_HEADERS
%token <sval> MATCHER_IP_ADDR_SET
%token <sval> MATCHER_IP4_NET
%token <sval> MATCHER_IP6_NET
%token <sval> MATCHER_ICMP
%token <sval> STRING
%token <sval> HOOK VERDICT MATCHER_TYPE MATCHER_OP
%token <sval> RAW_HOOKOPT
%token <sval> RAW_PAYLOAD

// Grammar types
%type <u8> log
%type <bval> counter
%destructor { freep(&$$); } <sval>

%type <hook> hook
%type <hookopts> hookopts
%destructor { bf_hookopts_free(&$$); } hookopts

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
chains          : chain { UNUSED($1); }
                | chains chain { UNUSED($2); }
                ;

chain           : CHAIN STRING hook hookopts verdict rules
                {
                    _free_bf_chain_ struct bf_chain *chain = NULL;
                    _cleanup_free_ const char *name = $2;
                    _free_bf_hookopts_ struct bf_hookopts *hookopts = $4;
                    _free_bf_list_ bf_list *rules = $6;
                    int r;

                    if ($5 >= _BF_TERMINAL_VERDICT_MAX)
                        bf_parse_err("'%s' is not supported for chains\n", bf_verdict_to_str($5));

                    if (bf_chain_new(&chain, name, $3, $5, &ruleset->sets, rules) < 0)
                        bf_parse_err("failed to create a new bf_chain\n");

                    if (hookopts) {
                        r = bf_hookopts_validate(hookopts, chain->hook);
                        if (r)
                            bf_parse_err("invalid hook options used");
                    }

                    if (bf_list_add_tail(&ruleset->chains, chain) < 0)
                        bf_parse_err("failed to add chain into bf_list\n");
                    $$ = TAKE_PTR(chain);

                    if (bf_list_add_tail(&ruleset->hookopts, hookopts))
                        bf_parse_err("failed to insert hookopts to list of hookopts");
                    TAKE_PTR(hookopts);
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
                    enum bf_hook hook = bf_hook_from_str($1);
                    if (hook < 0)
                        bf_parse_err("unknown hook '%s'\n", $1);

                    free($1);
                    $$ = hook;
                }

hookopts        : %empty { $$ = NULL; }
                | hookopts RAW_HOOKOPT
                {
                    _free_bf_hookopts_ struct bf_hookopts *hookopts = $1;
                    _cleanup_free_ const char *raw_opt = $2;
                    int r;

                    if (!hookopts) {
                        r = bf_hookopts_new(&hookopts);
                        if (r)
                            bf_parse_err("failed to allocate a new bf_hookopts object");
                    }

                    r = bf_hookopts_parse_opt(hookopts, raw_opt);
                    if (r)
                        bf_parse_err("failed to parse hook option");

                    $$ = TAKE_PTR(hookopts);
                }
                ;

rules           : %empty { $$ = NULL; }
                | rules rule
                {
                    if (!$1) {
                        if (bf_list_new(&$1, (bf_list_ops[]){{.free = (bf_list_ops_free)bf_rule_free, .marsh = (bf_list_ops_marsh)bf_rule_marsh}}) < 0)
                            bf_parse_err("failed to allocate a new bf_list for bf_rule\n");
                    }

                    if (bf_list_add_tail($1, $2) < 0)
                        bf_parse_err("failed to insert rule into bf_list\n");

                    TAKE_PTR($2);
                    $$ = TAKE_PTR($1);
                }
                ;
rule            : RULE matchers log counter verdict
                {
                    _free_bf_rule_ struct bf_rule *rule = NULL;

                    if (bf_rule_new(&rule) < 0)
                        bf_parse_err("failed to create a new bf_rule\n");

                    rule->log = $3;
                    rule->counters = $4;
                    rule->verdict = $5;

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
                    _free_bf_list_ bf_list *list = NULL;

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
matcher         : matcher_type matcher_op RAW_PAYLOAD
                {
                    _free_bf_matcher_ struct bf_matcher *matcher = NULL;
                    _cleanup_free_ const char *payload = $3;
                    int r;

                    r = bf_matcher_new_from_raw(&matcher, $1, $2, payload);
                    if (r)
                        bf_parse_err("failed to create a new matcher\n");

                    $$ = TAKE_PTR(matcher);
                }
                | matcher_type matcher_op MATCHER_IP_ADDR_SET
                {
                    _free_bf_matcher_ struct bf_matcher *matcher = NULL;
                    _free_bf_set_ struct bf_set *set = NULL;
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
                | matcher_type matcher_op MATCHER_IP4_NET
                {
                    _free_bf_matcher_ struct bf_matcher *matcher = NULL;
                    _free_bf_set_ struct bf_set *set = NULL;
                    uint32_t set_id = bf_list_size(&ruleset->sets);
                    int r;

                    char *data = $3 + 1;
                    data[strlen(data) - 1] = '\0';

                    r = bf_set_new(&set, BF_SET_IP4_SUBNET);
                    if (r < 0)
                        bf_parse_err("failed to create a new set\n");

                    char *elem;
                    char *delim;
                    char *next = data;
                    do {
                        struct bf_ip4_lpm_key key;

                        elem = next;
                        next = strchr(elem, ',');
                        if (next) {
                            *next = '\0';
                            ++next;

                            // Handle trailing comma
                            if (*next == '\0')
                                next = NULL;
                        }

                        delim = strchr(elem, '/');
                        if (!delim)
                            bf_parse_err("no mask found in set element: %s", elem);

                        *delim = '\0';
                        ++delim;
                        key.prefixlen = strtol(delim, NULL, 10);
                        if (key.prefixlen == (unsigned int)LONG_MAX)
                            bf_parse_err("invalid subnet mask '%s'", delim);

                        r = inet_pton(AF_INET, elem, &key.data);
                        if (r != 1)
                            bf_parse_err("failed to parse IPv4 address: %s\n", elem);

                        r = bf_set_add_elem(set, &key);
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
                | matcher_type matcher_op MATCHER_IP6_NET
                {
                    _free_bf_matcher_ struct bf_matcher *matcher = NULL;
                    _free_bf_set_ struct bf_set *set = NULL;
                    uint32_t set_id = bf_list_size(&ruleset->sets);
                    int r;

                    char *data = $3 + 1;
                    data[strlen(data) - 1] = '\0';

                    r = bf_set_new(&set, BF_SET_IP6_SUBNET);
                    if (r < 0)
                        bf_parse_err("failed to create a new set\n");

                    char *elem;
                    char *delim;
                    char *next = data;
                    do {
                        struct bf_ip6_lpm_key key;

                        elem = next;
                        next = strchr(elem, ',');
                        if (next) {
                            *next = '\0';
                            ++next;

                            // Handle trailing comma
                            if (*next == '\0')
                                next = NULL;
                        }

                        delim = strchr(elem, '/');
                        if (!delim)
                            bf_parse_err("no mask found in set element: %s", elem);

                        *delim = '\0';
                        ++delim;
                        key.prefixlen = strtol(delim, NULL, 10);
                        if (key.prefixlen == (unsigned int)LONG_MAX)
                            bf_parse_err("invalid subnet mask '%s'", delim);

                        r = inet_pton(AF_INET6, elem, &key.data);
                        if (r != 1)
                            bf_parse_err("failed to parse IPv6 address: %s\n", elem);

                        r = bf_set_add_elem(set, &key);
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

log             : %empty    { $$ = 0; }
                | LOG LOG_HEADERS
                {
                    _cleanup_free_ char *in = $2;
                    char *tmp = in;
                    char *saveptr;
                    char *token;

                    $$ = 0;

                    while ((token = strtok_r(tmp, ",", &saveptr))) {
                        enum bf_pkthdr header;

                        if (bf_pkthdr_from_str(token, &header) < 0)
                            bf_parse_err("unknown packet header '%s'", token);

                        $$ |= BF_FLAG(header);

                        tmp = NULL;
                    }
                }
                ;

counter         : %empty    { $$ = false; }
                | COUNTER   { $$ = true; }
                ;
%%
