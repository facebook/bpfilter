%{
    #include <stdio.h>
    #include <stdbool.h>

    #include "parser/parser.h"
    #include "core/verdict.h"
    #include "core/hook.h"
    #include "core/matcher.h"
%}

%option noyywrap
%option noinput
%option nounput

%%

[ \t\n]         ;

chain           { return CHAIN; }
rule            { return RULE; }

    /* Keywords */
policy          { return POLICY; }
counter         { return COUNTER; }

    /* Hooks */
BF_HOOK_[A-Z_]+ { yylval.sval = strdup(yytext); return HOOK; }

    /* Verdicts */
(ACCEPT|DROP)   { yylval.sval = strdup(yytext); return VERDICT; }

    /* Matcher types */
ip\.proto       { yylval.sval = strdup(yytext); return MATCHER_TYPE; }

[a-zA-Z0-9_]+   { yylval.sval = strdup(yytext); return STRING; }

%%
