/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

%{
    #include <stdio.h>
    #include <stdbool.h>

    #include <bpfilter/verdict.h>
    #include <bpfilter/hook.h>
    #include <bpfilter/matcher.h>

    #include "parser.h"

    extern int yy_read_buf_size;
%}

%option noyywrap
%option noinput
%option nounput

%s STATE_HOOK_OPTS
%s STATE_LOG_OPTS
%s STATE_MATCHER_SET
%s STATE_MATCHER_META_IFACE
%s STATE_MATCHER_META_L3_PROTO
%s STATE_MATCHER_L4_PROTO
%s STATE_MATCHER_META_PROBA
%s STATE_MATCHER_IPV4_ADDR
%s STATE_MATCHER_IP4_NET
%s STATE_MATCHER_IP6_ADDR
%s STATE_MATCHER_IP6_NET
%s STATE_MATCHER_PORT
%s STATE_MATCHER_ICMP_TYPE
%s STATE_MATCHER_ICMP_CODE
%s STATE_MATCHER_TCP_FLAGS

int             (-|(0x))?[0-9a-zA-Z]+
%%

[ \t\n]         ;
"#".*           ;

chain           { return CHAIN; }
rule            { return RULE; }
set             { return SET; }

    /* Keywords */
counter         { return COUNTER; }

    /* Hooks */
BF_HOOK_[A-Z_]+ { BEGIN(STATE_HOOK_OPTS); yylval.sval = strdup(yytext); return HOOK; }
<STATE_HOOK_OPTS>{
    (\{|\}|,) /* Ignore */
    [a-zA-Z0-9_]+=[a-zA-Z0-9_\-\.\/]+ {
        yylval.sval = strdup(yytext);
        return RAW_HOOKOPT;
    }
}
    /* Verdicts */
(ACCEPT|DROP|CONTINUE)   { yylval.sval = strdup(yytext); return VERDICT; }

    /* Logs */
log             { BEGIN(STATE_LOG_OPTS); return LOG; }
<STATE_LOG_OPTS>{
    [0-9a-zA-Z]+(,[0-9a-zA-Z]+)* {
        yylval.sval = strdup(yytext);
        return LOG_HEADERS;
    }
}

    /* Sets */
\([ \t\n\r\f\v]*([a-zA-Z0-9_]+\.[a-zA-Z0-9_]+)([ \t\n\r\f\v]*,[ \t\n\r\f\v]*([a-zA-Z0-9_]+\.[a-zA-Z0-9_]+))*[ \t\n\r\f\v]*\) {
    BEGIN(STATE_MATCHER_SET);
    yylval.sval = strdup(yytext);
    return SET_TYPE;
}
<STATE_MATCHER_SET>{
    (in) { yylval.sval = strdup(yytext); return MATCHER_OP; }
    \{[^}]*\} {
        yylval.sval = strdup(yytext);
        return SET_RAW_PAYLOAD;
    }
}

    /* Matcher types */
meta\.iface  { BEGIN(STATE_MATCHER_META_IFACE); yylval.sval = strdup(yytext); return MATCHER_TYPE; }
<STATE_MATCHER_META_IFACE>{
    (eq) { yylval.sval = strdup(yytext); return MATCHER_OP; }
    {int}|[0-9a-zA-Z-]+ {
        yylval.sval = strdup(yytext);
        return RAW_PAYLOAD;
    }
}

meta\.l3_proto  { BEGIN(STATE_MATCHER_META_L3_PROTO); yylval.sval = strdup(yytext); return MATCHER_TYPE; }
<STATE_MATCHER_META_L3_PROTO>{
    (eq) { yylval.sval = strdup(yytext); return MATCHER_OP; }
    {int}|[0-9a-zA-Z-]+ {
        yylval.sval = strdup(yytext);
        return RAW_PAYLOAD;
    }
}

meta\.l4_proto  { BEGIN(STATE_MATCHER_L4_PROTO); yylval.sval = strdup(yytext); return MATCHER_TYPE; }
ip4\.proto      { BEGIN(STATE_MATCHER_L4_PROTO); yylval.sval = strdup(yytext); return MATCHER_TYPE; }
ip6\.nexthdr    { BEGIN(STATE_MATCHER_L4_PROTO); yylval.sval = strdup(yytext); return MATCHER_TYPE; }
<STATE_MATCHER_L4_PROTO>{
    (eq|not) { yylval.sval = strdup(yytext); return MATCHER_OP; }
    {int}|[0-9a-zA-Z-]+ {
        yylval.sval = strdup(yytext);
        return RAW_PAYLOAD;
    }
}

meta\.probability  { BEGIN(STATE_MATCHER_META_PROBA); yylval.sval = strdup(yytext); return MATCHER_TYPE; }
<STATE_MATCHER_META_PROBA>{
    (eq) { yylval.sval = strdup(yytext); return MATCHER_OP; }
    {int}% {
        yylval.sval = strdup(yytext);
        return RAW_PAYLOAD;
    }
}

ip4\.saddr       { BEGIN(STATE_MATCHER_IPV4_ADDR); yylval.sval = strdup(yytext); return MATCHER_TYPE; }
ip4\.daddr       { BEGIN(STATE_MATCHER_IPV4_ADDR); yylval.sval = strdup(yytext); return MATCHER_TYPE; }
<STATE_MATCHER_IPV4_ADDR>{
    (eq|not) { yylval.sval = strdup(yytext); return MATCHER_OP; }
    {int}\.{int}\.{int}\.{int} {
        yylval.sval = strdup(yytext);
        return RAW_PAYLOAD;
    }
}

ip4\.snet       { BEGIN(STATE_MATCHER_IP4_NET); yylval.sval = strdup(yytext); return MATCHER_TYPE; }
ip4\.dnet       { BEGIN(STATE_MATCHER_IP4_NET); yylval.sval = strdup(yytext); return MATCHER_TYPE; }
<STATE_MATCHER_IP4_NET>{
    (eq|not) { yylval.sval = strdup(yytext); return MATCHER_OP; }
    {int}\.{int}\.{int}\.{int}\/{int} {
        yylval.sval = strdup(yytext);
        return RAW_PAYLOAD;
    }
}

ip6\.(s|d)addr      { BEGIN(STATE_MATCHER_IP6_ADDR); yylval.sval = strdup(yytext); return MATCHER_TYPE; }
<STATE_MATCHER_IP6_ADDR>{
    (eq|not) { yylval.sval = strdup(yytext); return MATCHER_OP; }
    [a-zA-Z0-9:]+ {
        yylval.sval = strdup(yytext);
        return RAW_PAYLOAD;
    }
}

ip6\.(s|d)net       { BEGIN(STATE_MATCHER_IP6_NET); yylval.sval = strdup(yytext); return MATCHER_TYPE; }
<STATE_MATCHER_IP6_NET>{
    (eq|not) { yylval.sval = strdup(yytext); return MATCHER_OP; }
    [a-zA-Z0-9:\/]+ {
        yylval.sval = strdup(yytext);
        return RAW_PAYLOAD;
    }
}

meta\.(s|d)port { BEGIN(STATE_MATCHER_PORT); yylval.sval = strdup(yytext); return MATCHER_TYPE; }
tcp\.(s|d)port  { BEGIN(STATE_MATCHER_PORT); yylval.sval = strdup(yytext); return MATCHER_TYPE; }
udp\.(s|d)port  { BEGIN(STATE_MATCHER_PORT); yylval.sval = strdup(yytext); return MATCHER_TYPE; }
<STATE_MATCHER_PORT>{
    (eq|not|range) { yylval.sval = strdup(yytext); return MATCHER_OP; }
    {int}(-{int})? {
        yylval.sval = strdup(yytext);
        return RAW_PAYLOAD;
    }
}

icmp(v6)?\.type { BEGIN(STATE_MATCHER_ICMP_TYPE); yylval.sval = strdup(yytext); return MATCHER_TYPE; }
<STATE_MATCHER_ICMP_TYPE>{
    (eq|not) { yylval.sval = strdup(yytext); return MATCHER_OP; }
    {int}|[0-9a-zA-Z-]+ {
        yylval.sval = strdup(yytext);
        return RAW_PAYLOAD;
    }
}

icmp(v6)?\.code { BEGIN(STATE_MATCHER_ICMP_CODE); yylval.sval = strdup(yytext); return MATCHER_TYPE; }
<STATE_MATCHER_ICMP_CODE>{
    (eq|not) { yylval.sval = strdup(yytext); return MATCHER_OP; }
    {int} {
        yylval.sval = strdup(yytext);
        return RAW_PAYLOAD;
    }
}

tcp\.flags      { BEGIN(STATE_MATCHER_TCP_FLAGS); yylval.sval = strdup(yytext); return MATCHER_TYPE; }
<STATE_MATCHER_TCP_FLAGS>{
    (eq|not|any|all) { yylval.sval = strdup(yytext); return MATCHER_OP; }
    ([a-zA-Z]+,?)+ {
        yylval.sval = strdup(yytext);
        return RAW_PAYLOAD;
    }
}

[a-zA-Z0-9_]+   { yylval.sval = strdup(yytext); return STRING; }

%%
