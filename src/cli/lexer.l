%{
    #include <stdio.h>
    #include <stdbool.h>

    #include "cli/parser.h"
    #include "core/verdict.h"
    #include "core/hook.h"
    #include "core/matcher.h"
%}

%option noyywrap
%option noinput
%option nounput

%s STATE_MATCHER_META_L3_PROTO
%s STATE_MATCHER_META_L4_PROTO
%s STATE_MATCHER_IP_PROTO
%s STATE_MATCHER_IPADDR
%s STATE_MATCHER_PORT
%s STATE_MATCHER_TCP_FLAGS

%%

[ \t\n]         ;
"#".*           ;

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
meta\.l3_proto  { BEGIN(STATE_MATCHER_META_L3_PROTO); yylval.sval = strdup(yytext); return MATCHER_TYPE; }
<STATE_MATCHER_META_L3_PROTO>{
    (eq) { yylval.sval = strdup(yytext); return MATCHER_OP; }
    [a-z0-9]+ {
        yylval.sval = strdup(yytext);
        return MATCHER_META_L3_PROTO;
    }
}

meta\.l4_proto  { BEGIN(STATE_MATCHER_META_L4_PROTO); yylval.sval = strdup(yytext); return MATCHER_TYPE; }
<STATE_MATCHER_META_L4_PROTO>{
    (eq) { yylval.sval = strdup(yytext); return MATCHER_OP; }
    [a-z0-9]+ {
        yylval.sval = strdup(yytext);
        return MATCHER_META_L4_PROTO;
    }
}

ip4\.proto      { BEGIN(STATE_MATCHER_IP_PROTO); yylval.sval = strdup(yytext); return MATCHER_TYPE; }
<STATE_MATCHER_IP_PROTO>{
    (eq|not) { yylval.sval = strdup(yytext); return MATCHER_OP; }
    [a-z]+ {
        yylval.sval = strdup(yytext);
        return MATCHER_IP_PROTO;
    }
}

ip4\.saddr       { BEGIN(STATE_MATCHER_IPADDR); yylval.sval = strdup(yytext); return MATCHER_TYPE; }
ip4\.daddr       { BEGIN(STATE_MATCHER_IPADDR); yylval.sval = strdup(yytext); return MATCHER_TYPE; }
<STATE_MATCHER_IPADDR>{
    (eq|not) { yylval.sval = strdup(yytext); return MATCHER_OP; }
    [0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}(\/[0-9]+)? {
        yylval.sval = strdup(yytext);
        return MATCHER_IPADDR;
    }
}

tcp\.(s|d)port  { BEGIN(STATE_MATCHER_PORT); yylval.sval = strdup(yytext); return MATCHER_TYPE; }
udp\.(s|d)port  { BEGIN(STATE_MATCHER_PORT); yylval.sval = strdup(yytext); return MATCHER_TYPE; }
<STATE_MATCHER_PORT>{
    (eq|not) { yylval.sval = strdup(yytext); return MATCHER_OP; }
    (\!)?[0-9]+ {
        yylval.sval = strdup(yytext);
        return MATCHER_PORT;
    }
}

tcp\.flags      { BEGIN(STATE_MATCHER_TCP_FLAGS); yylval.sval = strdup(yytext); return MATCHER_TYPE; }
<STATE_MATCHER_TCP_FLAGS>{
    (eq|not|any|all) { yylval.sval = strdup(yytext); return MATCHER_OP; }
    ([A-Z]+,?)+ {
        yylval.sval = strdup(yytext);
        return MATCHER_TCP_FLAGS;
    }
}

[a-zA-Z0-9_]+   { yylval.sval = strdup(yytext); return STRING; }

%%
