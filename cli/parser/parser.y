%{
    #include <stdio.h>
    #include <stdlib.h>
    #include <stdbool.h>

    extern int yylex();
    extern int yyparse();
    extern FILE *yyin;

    void yyerror(const char *fmt, ...);
%}

%code requires {
    #include "core/verdict.h"
    #include "core/hook.h"
    #include "core/matcher.h"
}

%define parse.error detailed

%union {
    bool bval;
    char *sval;
    enum bf_verdict verdict;
    enum bf_hook hook;
    enum bf_matcher_type matcher_type;
}

// Tokens
%token CHAIN
%token POLICY
%token RULE
%token COUNTER
%token <sval> STRING
%token <sval> HOOK VERDICT MATCHER_TYPE

// Grammar types
%type <bval> counter
%type <hook> hook
%type <verdict> verdict
%type <matcher_type> matcher_type

%%
ruleset: chain

chain: CHAIN hook POLICY verdict rules

verdict         : VERDICT
                {
                    enum bf_verdict verdict;

                    if (bf_verdict_from_str($1, &verdict) < 0) {
                        yyerror("unknown verdict '%s'\n", $1);
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
                        yyerror("unknown hook '%s'\n", $1);
                        free($1);
                        YYABORT;
                    }

                    free($1);
                    $$ = hook;
                }

rules           : rule
                | rules rule
                ;
rule            : RULE matchers counter verdict

matchers        : matcher
                | matchers matcher
                ;
matcher         : matcher_type STRING
                {
                    free($2);
                }
matcher_type    : MATCHER_TYPE
                {
                    enum bf_matcher_type type;

                    if (bf_matcher_type_from_str($1, &type) < 0) {
                        yyerror("unknown matcher type '%s'\n", $1);
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
