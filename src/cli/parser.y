%{
    #include <stdio.h>
    #include <stdlib.h>
    #include <stdbool.h>

    #include "core/list.h"

    extern int yylex();
    extern int yyparse();
    extern FILE *yyin;

    void yyerror(bf_list *chains, const char *fmt, ...);
%}

%code requires {
    #include <arpa/inet.h>
    #include <linux/in.h>
    #include "core/verdict.h"
    #include "core/hook.h"
    #include "core/matcher.h"
    #include "core/list.h"
    #include "core/rule.h"
    #include "core/chain.h"
}

%define parse.error detailed
%parse-param {bf_list *chains}

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
}

// Tokens
%token CHAIN
%token POLICY
%token RULE
%token COUNTER
%token <sval> MATCHER_IPPROTO MATCHER_IPADDR
%token <sval> STRING
%token <sval> HOOK VERDICT MATCHER_TYPE

// Grammar types
%type <bval> counter
%type <hook> hook
%type <verdict> verdict
%type <matcher_type> matcher_type
%type <list> matchers
%type <matcher> matcher
%type <list> rules
%type <rule> rule
%type <chain> chain

%%
chains          : chain
                {
                    if (bf_list_add_tail(chains, $1) < 0) {
                        yyerror(chains, "failed to add chain into bf_list\n");
                        YYABORT;
                    }

                    TAKE_PTR($1);
                }
                | chains chain
                {
                    if (bf_list_add_tail(chains, $2) < 0) {
                        yyerror(chains, "failed to insert chain into bf_list\n");
                        YYABORT;
                    }

                    TAKE_PTR($2);
                }
                ;

chain           : CHAIN hook POLICY verdict rules
                {
                    _cleanup_bf_chain_ struct bf_chain *chain = NULL;

                    if (bf_chain_new(&chain, $2, $4, $5) < 0) {
                        yyerror(chains, "failed to create a new bf_chain\n");
                        YYABORT;
                    }

                    bf_list_free(&$5);
                    $$ = TAKE_PTR(chain);
                }

verdict         : VERDICT
                {
                    enum bf_verdict verdict;

                    if (bf_verdict_from_str($1, &verdict) < 0) {
                        yyerror(chains, "unknown verdict '%s'\n", $1);
                        free($1);
                        YYABORT;
                    }
 
                    free($1);
                    $$ = verdict;
                }

hook            : HOOK
                {
                    enum bf_hook hook;

                    if (bf_hook_from_str($1, &hook) < 0) {
                        yyerror(chains, "unknown hook '%s'\n", $1);
                        free($1);
                        YYABORT;
                    }

                    free($1);
                    $$ = hook;
                }

rules           : rule
                {
                    _cleanup_bf_list_ bf_list *list = NULL;

                    if (bf_list_new(&list, (bf_list_ops[]){{.free = (bf_list_ops_free)bf_rule_free}}) < 0) {
                        yyerror(chains, "failed to allocate a new bf_list for bf_rule\n");
                        YYABORT;
                    }

                    if (bf_list_add_tail(list, $1) < 0) {
                        yyerror(chains, "failed to add rule into bf_list\n");
                        YYABORT;
                    }

                    TAKE_PTR($1);
                    $$ = TAKE_PTR(list);
                }
                | rules rule
                {
                    if (bf_list_add_tail($1, $2) < 0) {
                        yyerror(chains, "failed to insert rule into bf_list\n");
                        YYABORT;
                    }

                    TAKE_PTR($2);
                    $$ = TAKE_PTR($1);
                }
                ;
rule            : RULE matchers counter verdict
                {
                    _cleanup_bf_rule_ struct bf_rule *rule = NULL;

                    if (bf_rule_new(&rule) < 0) {
                        yyerror(chains, "failed to create a new bf_rule\n");
                        YYABORT;
                    }

                    rule->counters = $3;
                    rule->verdict = $4;

                    bf_list_foreach ($2, matcher_node) {
                        struct bf_matcher *matcher = bf_list_node_get_data(matcher_node);

                        if (bf_list_add_tail(&rule->matchers, matcher) < 0) {
                            yyerror(chains, "failed to add matcher to the rule\n");
                            YYABORT;
                        }

                        bf_list_node_take_data(matcher_node);
                    }

                    bf_list_free(&$2);
                    $$ = TAKE_PTR(rule);
                }
                ;

matchers        : matcher
                {
                    _cleanup_bf_list_ bf_list *list = NULL;

                    if (bf_list_new(&list, (bf_list_ops[]){{.free = (bf_list_ops_free)bf_matcher_free}}) < 0) {
                        yyerror(chains, "failed to allocate a new bf_list for bf_matcher\n");
                        YYABORT;
                    }

                    if (bf_list_add_tail(list, $1) < 0) {
                        yyerror(chains, "failed to insert matcher into bf_list\n");
                        YYABORT;
                    }

                    TAKE_PTR($1);
                    $$ = TAKE_PTR(list);         
                }
                | matchers matcher
                {
                    if (bf_list_add_tail($1, $2) < 0) {
                        yyerror(chains, "failed to insert matcher into bf_list\n");
                        YYABORT;
                    }

                    TAKE_PTR($2);
                    $$ = TAKE_PTR($1);
                }
                ;
matcher         : matcher_type MATCHER_IPPROTO
                {
                    _cleanup_bf_matcher_ struct bf_matcher *matcher = NULL;
                    uint16_t proto;

                    if (bf_streq($2, "icmp")) {
                        proto = IPPROTO_ICMP;
                    } else {
                        yyerror(chains, "unsupported IPPROTO to match '%s'\n", $2);
                        free($2);
                        YYABORT;
                    }
    
                    free($2);
                    
                    if (bf_matcher_new(&matcher, BF_MATCHER_IP_PROTO, BF_MATCHER_EQ, &proto, sizeof(proto)) < 0) {
                        yyerror(chains, "failed to create a new matcher\n");
                        YYABORT;
                    } 
                    
                    $$ = TAKE_PTR(matcher);
                }
                | matcher_type MATCHER_IPADDR
                {
                    _cleanup_bf_matcher_ struct bf_matcher *matcher = NULL;
                    struct bf_matcher_ip_addr addr;
                    char *ip = $2;
                    char *mask;
                    bool inv = false;
                    int r;

                    // If the payload starts with '!', it's an inverse match,
                    // and the IP starts at the next character.
                    if (*$2 == '!') {
                        inv = true;
                        ++ip;
                    }

                    // If '/' is found, parse the mask, otherwise use /32.
                    mask = strchr($2, '/');
                    if (mask) {
                        *mask = '\0';
                        ++mask;

                        int m = atoi(mask);
                        if (m == 0) {
                            yyerror(chains, "failed to parse IPv4 mask: %s\n", mask);
                            YYABORT;
                        }

                        addr.mask = ((uint32_t)~0) << (32 - m);
                    } else {
                        addr.mask = (uint32_t)~0;
                    }

                    // Convert the IPv4 from string to uint32_t.
                    r = inet_pton(AF_INET, ip, &addr.addr);
                    if (r != 1) {
                        yyerror(chains, "failed to parse IPv4 adddress: %s\n", ip);
                        YYABORT;
                    }

                    free($2);

                    if (bf_matcher_new(&matcher, $1, inv ? BF_MATCHER_NE : BF_MATCHER_EQ, &addr, sizeof(addr))) {
                        yyerror(chains, "failed to create a new matcher\n");
                        YYABORT;
                    }

                    $$ = TAKE_PTR(matcher);
                }
                ;
matcher_type    : MATCHER_TYPE
                {
                    enum bf_matcher_type type;

                    if (bf_matcher_type_from_str($1, &type) < 0) {
                        yyerror(chains, "unknown matcher type '%s'\n", $1);
                        free($1);
                        YYABORT;
                    }

                    free($1);
                    $$ = type;
                }

counter         : %empty    { $$ = false; }
                | COUNTER   { $$ = true; }
                ;
%%
