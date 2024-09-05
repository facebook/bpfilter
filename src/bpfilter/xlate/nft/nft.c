/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2022 Meta Platforms, Inc. and affiliates.
 */

#include <linux/netfilter.h>
#include <linux/netfilter/nf_tables.h>

#include <endian.h>
#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>

#include "bpfilter/cgen/codegen.h"
#include "bpfilter/context.h"
#include "bpfilter/xlate/front.h"
#include "bpfilter/xlate/nft/nfgroup.h"
#include "bpfilter/xlate/nft/nfmsg.h"
#include "core/counter.h"
#include "core/dump.h"
#include "core/front.h"
#include "core/helper.h"
#include "core/hook.h"
#include "core/list.h"
#include "core/logger.h"
#include "core/marsh.h"
#include "core/matcher.h"
#include "core/request.h"
#include "core/response.h"
#include "core/rule.h"
#include "core/verdict.h"

struct bf_marsh;

enum
{
    BF_IP4HDR_PROTO_OFFSET = 9,
    BF_IP4HDR_SADDR_OFFSET = 12,
    BF_IP4HDR_DADDR_OFFSET = 16,
};

static const char *_bf_table_name = "bpfilter";
static const char *_bf_chain_name = "prerouting";

static int _bf_nft_setup(void);
static int _bf_nft_teardown(void);
static int _bf_nft_request_handler(struct bf_request *request,
                                   struct bf_response **response);
static int _bf_nft_marsh(struct bf_marsh **marsh);
static int _bf_nft_unmarsh(struct bf_marsh *marsh);

const struct bf_front_ops nft_front = {
    .setup = _bf_nft_setup,
    .teardown = _bf_nft_teardown,
    .request_handler = _bf_nft_request_handler,
    .marsh = _bf_nft_marsh,
    .unmarsh = _bf_nft_unmarsh,
};

static bf_list *_bf_nft_rules = NULL;

static int _bf_nft_setup(void)
{
    int r;

    // If the cache has been restored already, skip this.
    if (_bf_nft_rules)
        return 0;

    r = bf_list_new(
        &_bf_nft_rules,
        (bf_list_ops[]) {{.free = (bf_list_ops_free)bf_nfmsg_free}});
    if (r < 0)
        return bf_err_code(r, "failed to create bf_list");

    return 0;
}

static int _bf_nft_teardown(void)
{
    bf_list_free(&_bf_nft_rules);

    return 0;
}

static int _bf_nft_marsh(struct bf_marsh **marsh)
{
    bf_assert(marsh);

    int r = 0;

    bf_list_foreach (_bf_nft_rules, rule_node) {
        struct bf_nfmsg *msg = bf_list_node_get_data(rule_node);

        r = bf_marsh_add_child_raw(marsh, bf_nfmsg_hdr(msg), bf_nfmsg_len(msg));
        if (r < 0)
            return bf_err_code(r, "failed to add rule to marsh");
    }

    return 0;
}

static int _bf_nft_unmarsh(struct bf_marsh *marsh)
{
    bf_assert(marsh);

    _cleanup_bf_list_ bf_list *list = NULL;
    struct bf_marsh *child = NULL;
    int r;

    r = bf_list_new(
        &list, (bf_list_ops[]) {{.free = (bf_list_ops_free)bf_nfmsg_free}});
    if (r < 0)
        return bf_err_code(r, "failed to create bf_list");

    while ((child = bf_marsh_next_child(marsh, child))) {
        _cleanup_bf_nfmsg_ struct bf_nfmsg *msg = NULL;
        struct nlmsghdr *nlh = (struct nlmsghdr *)(child->data);

        r = bf_nfmsg_new_from_nlmsghdr(&msg, nlh);
        if (r < 0)
            return bf_err_code(r, "failed to create bf_nfmsg from marsh");

        r = bf_list_add_tail(list, msg);
        if (r < 0)
            return bf_err_code(r, "failed to add bf_nfmsg to bf_list");
        TAKE_PTR(msg);
    }

    _bf_nft_rules = TAKE_PTR(list);

    return 0;
}

static int _bf_nft_getgen_cb(const struct bf_nfmsg *req, struct bf_nfgroup *res)
{
    bf_assert(req);
    bf_assert(res);

    struct bf_nfmsg *msg = NULL;
    int r;

    r = bf_nfgroup_add_new_message(res, &msg, NFT_MSG_NEWGEN,
                                   bf_nfmsg_seqnr(req));
    if (r < 0)
        return bf_err_code(r, "failed to create bf_nfmsg");

    bf_nfmsg_push_u32_or_jmp(msg, NFTA_GEN_ID, 0);
    bf_nfmsg_push_u32_or_jmp(msg, NFTA_GEN_PROC_PID, getpid());
    bf_nfmsg_push_str_or_jmp(msg, NFTA_GEN_PROC_NAME, "nft");

    return 0;

bf_nfmsg_push_failure:
    return -EINVAL;
}

static int _bf_nft_gettable_cb(const struct bf_nfmsg *req,
                               struct bf_nfgroup *res)
{
    bf_assert(req);
    bf_assert(res);

    struct bf_nfmsg *msg = NULL;
    int r;

    r = bf_nfgroup_add_new_message(res, &msg, NFT_MSG_NEWTABLE,
                                   bf_nfmsg_seqnr(req));
    if (r < 0)
        return bf_err_code(r, "failed to create bf_nfmsg");

    bf_nfmsg_push_str_or_jmp(msg, NFTA_TABLE_NAME, _bf_table_name);
    bf_nfmsg_push_u32_or_jmp(msg, NFTA_TABLE_FLAGS, 0);
    bf_nfmsg_push_u64_or_jmp(msg, NFTA_TABLE_HANDLE, 0);
    bf_nfmsg_push_u32_or_jmp(msg, NFTA_TABLE_USE, 1);

    return 0;

bf_nfmsg_push_failure:
    return -EINVAL;
}

static int _bf_nft_newtable_cb(const struct bf_nfmsg *req)
{
    bf_assert(req);

    bf_nfattr *attrs[__NFTA_TABLE_MAX] = {};
    int r;

    r = bf_nfmsg_parse(req, attrs, __NFTA_TABLE_MAX, bf_nf_table_policy);
    if (r < 0)
        return bf_err_code(r, "failed to parse NFT_MSG_GETTABLE attributes");

    if (!attrs[NFTA_TABLE_NAME])
        return bf_warn_code(-EINVAL, "missing NFTA_TABLE_NAME attribute");

    if (!bf_streq(bf_nfattr_get_str(attrs[NFTA_TABLE_NAME]), _bf_table_name)) {
        return bf_warn_code(-EINVAL, "invalid table name '%s'",
                            bf_nfattr_get_str(attrs[NFTA_TABLE_NAME]));
    }

    return 0;
}

static int _bf_nft_newchain_cb(const struct bf_nfmsg *req)
{
    bf_assert(req);

    _cleanup_bf_codegen_ struct bf_codegen *codegen = NULL;
    bf_nfattr *chain_attrs[__NFTA_CHAIN_MAX] = {};
    bf_nfattr *hook_attrs[__NFTA_HOOK_MAX] = {};
    enum bf_verdict verdict;
    int r;

    r = bf_nfmsg_parse(req, chain_attrs, __NFTA_CHAIN_MAX, bf_nf_chain_policy);
    if (r < 0)
        return bf_err_code(r, "failed to parse NFT_MSG_NEWCHAIN attributes");

    if (!chain_attrs[NFTA_CHAIN_TABLE] ||
        !bf_streq(bf_nfattr_get_str(chain_attrs[NFTA_CHAIN_TABLE]),
                  _bf_table_name))
        return bf_err_code(-EINVAL, "invalid table name");

    if (!chain_attrs[NFTA_CHAIN_NAME] ||
        !bf_streq(bf_nfattr_get_str(chain_attrs[NFTA_CHAIN_NAME]),
                  _bf_chain_name))
        return bf_err_code(-EINVAL, "invalid table name");

    if (!chain_attrs[NFTA_CHAIN_POLICY])
        return bf_err_code(-EINVAL, "missing NFTA_CHAIN_POLICY attribute");

    if (!chain_attrs[NFTA_CHAIN_HOOK])
        return bf_err_code(-EINVAL, "missing NFTA_CHAIN_HOOK attribute");

    r = bf_nfattr_parse(chain_attrs[NFTA_CHAIN_HOOK], hook_attrs,
                        __NFTA_HOOK_MAX, bf_nf_hook_policy);
    if (r < 0)
        return bf_err_code(r, "failed to parse NFTA_CHAIN_HOOK attributes");

    if (!hook_attrs[NFTA_HOOK_HOOKNUM] ||
        NF_INET_PRE_ROUTING !=
            bf_nfattr_get_u32(hook_attrs[NFTA_HOOK_HOOKNUM])) {
        return bf_err_code(
            -EINVAL, "missing or invalid hook (NF_INET_PRE_ROUTING required)");
    }

    switch (be32toh(bf_nfattr_get_u32(chain_attrs[NFTA_CHAIN_POLICY]))) {
    case NF_ACCEPT:
        verdict = BF_VERDICT_ACCEPT;
        break;
    case NF_DROP:
        verdict = BF_VERDICT_DROP;
        break;
    default:
        return bf_err_code(
            -ENOTSUP, "unsupported policy %u",
            be32toh(bf_nfattr_get_u32(chain_attrs[NFTA_CHAIN_POLICY])));
    };

    codegen = bf_context_get_codegen(BF_HOOK_XDP, BF_FRONT_NFT);
    if (codegen && verdict != codegen->policy) {
        codegen->policy = verdict;
        r = bf_codegen_update(codegen);
        if (r < 0)
            return bf_err_code(r, "failed to update codegen");

        bf_info("existing codegen updated with new policy");
    } else if (!codegen) {
        r = bf_codegen_new(&codegen);
        if (r < 0)
            return bf_err_code(r, "failed to create bf_codegen");

        codegen->front = BF_FRONT_NFT;
        codegen->hook = BF_HOOK_XDP;
        codegen->policy = verdict;

        r = bf_codegen_up(codegen);
        if (r < 0)
            return bf_err_code(r, "failed to generate codegen");

        bf_context_set_codegen(BF_HOOK_XDP, BF_FRONT_NFT, codegen);

        bf_info("new codegen created and loaded");
    } else {
        bf_info("codegen already properly configured, skipping generation");
    }

    TAKE_PTR(codegen);

    return 0;
}

static int _bf_nft_getchain_cb(const struct bf_nfmsg *req,
                               struct bf_nfgroup *res)
{
    bf_assert(req);
    bf_assert(res);

    struct bf_nfmsg *msg;
    struct bf_codegen *codegen;
    uint32_t policy;
    int r;

    // Only BF_HOOK_XDP is supported.
    codegen = bf_context_get_codegen(BF_HOOK_XDP, BF_FRONT_NFT);
    if (!codegen) {
        /* If no codegen is found, do not fill the messages group and return
         * success. The response message will then contain only a DONE
         * message. */
        return 0;
    }

    r = bf_nfgroup_add_new_message(res, &msg, NFT_MSG_NEWCHAIN,
                                   bf_nfmsg_seqnr(req));
    if (r < 0)
        return bf_err_code(r, "failed to create bf_nfmsg");

    bf_codegen_dump(codegen, EMPTY_PREFIX);

    switch (codegen->policy) {
    case BF_VERDICT_ACCEPT:
        policy = NF_ACCEPT;
        break;
    case BF_VERDICT_DROP:
        policy = NF_DROP;
        break;
    default:
        return bf_err_code(-ENOTSUP, "unsupported codegen policy %u",
                           codegen->policy);
    };

    bf_nfmsg_push_str_or_jmp(msg, NFTA_CHAIN_TABLE, _bf_table_name);
    bf_nfmsg_push_str_or_jmp(msg, NFTA_CHAIN_NAME, _bf_chain_name);
    bf_nfmsg_push_u64_or_jmp(msg, NFTA_CHAIN_HANDLE, BF_HOOK_XDP);
    bf_nfmsg_push_u32_or_jmp(msg, NFTA_CHAIN_POLICY, htobe32(policy));
    bf_nfmsg_push_str_or_jmp(msg, NFTA_CHAIN_TYPE, "filter");
    bf_nfmsg_push_u32_or_jmp(msg, NFTA_CHAIN_FLAGS, NFT_CHAIN_BASE);
    bf_nfmsg_push_u32_or_jmp(msg, NFTA_CHAIN_USE,
                             htobe32(bf_list_size(&codegen->rules)));

    {
        _cleanup_bf_nfnest_ struct bf_nfnest _ =
            bf_nfnest_or_jmp(msg, NFTA_CHAIN_HOOK);

        bf_nfmsg_push_u32_or_jmp(msg, NFTA_HOOK_HOOKNUM,
                                 htobe32(NF_INET_PRE_ROUTING));
        bf_nfmsg_push_u32_or_jmp(msg, NFTA_HOOK_PRIORITY, htobe32(0));
    }

    return 0;

bf_nfmsg_push_failure:
    return bf_err_code(-EINVAL, "failed to add attribute to Netlink message");
}

static int _bf_nft_newrule_cb(const struct bf_nfmsg *req)
{
    bf_assert(req);

    _cleanup_bf_rule_ struct bf_rule *rule = NULL;
    _cleanup_bf_nfmsg_ struct bf_nfmsg *req_copy;
    struct bf_codegen *codegen;
    bf_nfattr *rule_attrs[__NFTA_RULE_MAX] = {};
    bf_nfattr *expr_attrs[__NFTA_EXPR_MAX] = {};
    bf_nfattr *payload_attrs[__NFTA_PAYLOAD_MAX] = {};
    bf_nfattr *cmp_attrs[__NFTA_CMP_MAX] = {};
    bf_nfattr *data_attrs[__NFTA_DATA_MAX] = {};
    bf_nfattr *immediate_attrs[__NFTA_IMMEDIATE_MAX] = {};
    bf_nfattr *verdict_attrs[__NFTA_VERDICT_MAX] = {};
    bf_nfattr *parent;
    bf_nfattr *attr;
    size_t rem;
    int r;

    r = bf_nfmsg_parse(req, rule_attrs, __NFTA_RULE_MAX, bf_nf_rule_policy);
    if (r < 0)
        return bf_err_code(r, "failed to parse NFT_MSG_NEWRULE attributes");

    if (!rule_attrs[NFTA_RULE_TABLE] ||
        !bf_streq(bf_nfattr_get_str(rule_attrs[NFTA_RULE_TABLE]),
                  _bf_table_name))
        return bf_err_code(-EINVAL, "invalid table name");

    if (!rule_attrs[NFTA_RULE_CHAIN] ||
        !bf_streq(bf_nfattr_get_str(rule_attrs[NFTA_RULE_CHAIN]),
                  _bf_chain_name))
        return bf_err_code(-EINVAL, "invalid chain name");

    parent = rule_attrs[NFTA_RULE_EXPRESSIONS];
    if (!parent)
        return bf_err_code(-EINVAL, "missing NFTA_RULE_EXPRESSIONS attribute");
    rem = bf_nfattr_data_len(parent);

    attr = (bf_nfattr *)bf_nfattr_data(parent);
    if (!bf_nfattr_is_ok(attr, rem))
        return bf_err_code(-EINVAL, "invalid NFTA_RULE_EXPRESSIONS attribute");

    r = bf_nfattr_parse(attr, expr_attrs, __NFTA_EXPR_MAX, bf_nf_expr_policy);
    if (r < 0) {
        return bf_err_code(r,
                           "failed to parse NFTA_RULE_EXPRESSIONS attributes");
    }

    if (!expr_attrs[NFTA_EXPR_NAME] ||
        !bf_streq(bf_nfattr_get_str(expr_attrs[NFTA_EXPR_NAME]), "payload"))
        return bf_err_code(-EINVAL, "expecting rule expression 'payload'");

    r = bf_nfattr_parse(expr_attrs[NFTA_EXPR_DATA], payload_attrs,
                        __NFTA_PAYLOAD_MAX, bf_nf_payload_policy);
    if (r < 0)
        return bf_err_code(r, "failed to parse NFTA_EXPR_DATA attributes");

    if (!payload_attrs[NFTA_PAYLOAD_BASE] ||
        be32toh(bf_nfattr_get_u32(payload_attrs[NFTA_PAYLOAD_BASE])) !=
            NFT_PAYLOAD_NETWORK_HEADER) {
        return bf_err_code(-EINVAL,
                           "expecting payload base NFT_PAYLOAD_NETWORK_HEADER");
    }

    uint32_t len = be32toh(bf_nfattr_get_u32(payload_attrs[NFTA_PAYLOAD_LEN]));
    uint32_t off =
        be32toh(bf_nfattr_get_u32(payload_attrs[NFTA_PAYLOAD_OFFSET]));

    attr = bf_nfattr_next(attr, &rem);
    if (!bf_nfattr_is_ok(attr, rem))
        return bf_err_code(-EINVAL, "invalid NFTA_RULE_EXPRESSIONS attribute");

    r = bf_nfattr_parse(attr, expr_attrs, __NFTA_EXPR_MAX, bf_nf_expr_policy);
    if (r < 0) {
        return bf_err_code(r,
                           "failed to parse NFTA_RULE_EXPRESSIONS attributes");
    }

    if (!expr_attrs[NFTA_EXPR_NAME] ||
        !bf_streq(bf_nfattr_get_str(expr_attrs[NFTA_EXPR_NAME]), "cmp"))
        return bf_err_code(-EINVAL, "expecting rule expression 'cmp'");

    r = bf_nfattr_parse(expr_attrs[NFTA_EXPR_DATA], cmp_attrs, __NFTA_CMP_MAX,
                        bf_nf_cmp_policy);
    if (r < 0)
        return bf_err_code(r, "failed to parse NFTA_EXPR_DATA attributes");

    uint32_t op = be32toh(bf_nfattr_get_u32(cmp_attrs[NFTA_CMP_OP]));
    if (op != NFT_CMP_EQ)
        return bf_err_code(-EINVAL, "only NFTA_CMP_OP is supported");

    r = bf_nfattr_parse(cmp_attrs[NFTA_CMP_DATA], data_attrs, __NFTA_DATA_MAX,
                        bf_nf_data_policy);
    if (r < 0)
        return bf_err_code(r, "failed to parse NFTA_CMP_DATA attributes");

    uint32_t cmp_value =
        be32toh(bf_nfattr_get_u32(data_attrs[NFTA_DATA_VALUE]));

    attr = bf_nfattr_next(attr, &rem);
    if (!bf_nfattr_is_ok(attr, rem))
        return bf_err_code(-EINVAL, "invalid NFTA_RULE_EXPRESSIONS attribute");

    r = bf_nfattr_parse(attr, expr_attrs, __NFTA_EXPR_MAX, bf_nf_expr_policy);
    if (r < 0) {
        return bf_err_code(r,
                           "failed to parse NFTA_RULE_EXPRESSIONS attributes");
    }

    bool counter = false;
    if (bf_streq(bf_nfattr_data(expr_attrs[NFTA_EXPR_NAME]), "counter")) {
        counter = true;

        attr = bf_nfattr_next(attr, &rem);
        if (!bf_nfattr_is_ok(attr, rem))
            return bf_err_code(-EINVAL, "expecting cmp, got invalid attribute");

        r = bf_nfattr_parse(attr, expr_attrs, __NFTA_EXPR_MAX,
                            bf_nf_expr_policy);
        if (r < 0) {
            return bf_err_code(
                r, "failed to parse NFTA_RULE_EXPRESSIONS attributes");
        }
    }

    if (!bf_streq(bf_nfattr_data(expr_attrs[NFTA_EXPR_NAME]), "immediate")) {
        return bf_err_code(
            r, "expected immediate attribute, but have '%s' instead",
            bf_nfattr_get_str(expr_attrs[NFTA_EXPR_NAME]));
    }

    r = bf_nfattr_parse(expr_attrs[NFTA_EXPR_DATA], immediate_attrs,
                        __NFTA_IMMEDIATE_MAX, bf_nf_immediate_policy);
    if (r < 0)
        return bf_err_code(r, "failed to parse NFTA_EXPR_DATA attributes");

    r = bf_nfattr_parse(immediate_attrs[NFTA_IMMEDIATE_DATA], data_attrs,
                        __NFTA_DATA_MAX, bf_nf_data_policy);
    if (r < 0)
        return bf_err_code(r, "failed to parse NFTA_IMMEDIATE_DATA attributes");

    if (!data_attrs[NFTA_DATA_VERDICT])
        return bf_err_code(-EINVAL, "missing NFTA_DATA_VERDICT attribute");

    r = bf_nfattr_parse(data_attrs[NFTA_DATA_VERDICT], verdict_attrs,
                        __NFTA_VERDICT_MAX, bf_nf_verdict_policy);
    if (r < 0)
        return bf_err_code(r, "failed to parse NFTA_DATA_VERDICT attributes");

    if (!verdict_attrs[NFTA_VERDICT_CODE])
        return bf_err_code(-EINVAL, "missing NFTA_VERDICT_CODE attribute");

    int32_t verdict =
        be32toh(bf_nfattr_get_s32(verdict_attrs[NFTA_VERDICT_CODE]));
    if (verdict < 0) {
        return bf_err_code(-EINVAL,
                           "only ACCEPT and DROP verdicts are supported");
    }

    // Add the rule to the relevant codegen
    codegen = bf_context_get_codegen(BF_HOOK_XDP, BF_FRONT_NFT);

    if (!codegen)
        return bf_err_code(-EINVAL, "no codegen found for hook");

    r = bf_rule_new(&rule);
    if (r < 0)
        return bf_err_code(r, "failed to create bf_rule");

    rule->counters = counter;
    switch (off) {
    case BF_IP4HDR_PROTO_OFFSET:
        r = bf_rule_add_matcher(rule, BF_MATCHER_IP4_PROTO, BF_MATCHER_EQ,
                                (uint16_t[]) {htobe32(cmp_value)},
                                sizeof(uint16_t));
        if (r)
            return r;
        break;
    case BF_IP4HDR_SADDR_OFFSET:
        r = bf_rule_add_matcher(
            rule, BF_MATCHER_IP4_SRC_ADDR, BF_MATCHER_EQ,
            (struct bf_matcher_ip4_addr[]) {
                {.addr = htobe32(cmp_value), .mask = ~0ULL >> (32 - len * 8)}},
            sizeof(struct bf_matcher_ip4_addr));
        if (r)
            return r;
        break;
    case BF_IP4HDR_DADDR_OFFSET:
        r = bf_rule_add_matcher(
            rule, BF_MATCHER_IP4_DST_ADDR, BF_MATCHER_EQ,
            (struct bf_matcher_ip4_addr[]) {
                {.addr = htobe32(cmp_value), .mask = ~0ULL >> (32 - len * 8)}},
            sizeof(struct bf_matcher_ip4_addr));
        if (r)
            return r;
        break;
    default:
        return bf_err_code(-EINVAL, "unknown IP header offset %d", off);
    };

    rule->verdict = verdict == 0 ? BF_VERDICT_DROP : BF_VERDICT_ACCEPT;
    rule->index = bf_list_size(&codegen->rules);

    r = bf_list_add_tail(&codegen->rules, rule);
    if (r < 0)
        return bf_err_code(r, "failed to add rule to codegen");
    TAKE_PTR(rule);

    r = bf_codegen_update(codegen);
    if (r < 0)
        return bf_err_code(r, "failed to update codegen");

    // Backup the rule in the front-end context
    r = bf_nfmsg_new_from_nlmsghdr(&req_copy, bf_nfmsg_hdr(req));
    if (r < 0)
        return bf_err_code(r, "failed to create bf_nfmsg from nlmsghdr");

    r = bf_list_add_tail(_bf_nft_rules, req_copy);
    if (r < 0)
        return bf_err_code(r, "failed to add rule to bf_list");
    TAKE_PTR(req_copy);

    return 0;
}

static int _bf_nft_getrule_cb(const struct bf_nfmsg *req,
                              struct bf_nfgroup *res)
{
    bf_assert(req);
    bf_assert(res);

    bf_nfattr *rule_attrs[__NFTA_RULE_MAX] = {};
    int i = 0;
    int r;

    bf_list_foreach (_bf_nft_rules, rule_node) {
        _cleanup_bf_nfmsg_ struct bf_nfmsg *msg = NULL;
        struct bf_nfmsg *cached_msg = bf_list_node_get_data(rule_node);

        r = bf_nfgroup_add_new_message(res, &msg, NFT_MSG_NEWRULE,
                                       bf_nfmsg_seqnr(req));
        if (r < 0)
            return bf_err_code(r, "failed to create bf_nfmsg");

        bf_nfmsg_push_str_or_jmp(msg, NFTA_RULE_TABLE, _bf_table_name);
        bf_nfmsg_push_str_or_jmp(msg, NFTA_RULE_CHAIN, _bf_chain_name);
        bf_nfmsg_push_u64_or_jmp(msg, NFTA_RULE_HANDLE, i);
        bf_nfmsg_push_u64_or_jmp(msg, NFTA_RULE_POSITION, i);

        r = bf_nfmsg_parse(cached_msg, rule_attrs, __NFTA_RULE_MAX,
                           bf_nf_rule_policy);
        if (r < 0)
            return bf_err_code(r, "failed to parse NFT_MSG_NEWRULE attributes");

        {
            _cleanup_bf_nfnest_ struct bf_nfnest _ =
                bf_nfnest_or_jmp(msg, NFTA_RULE_EXPRESSIONS);
            bf_nfattr *expr_attrs[__NFTA_EXPR_MAX] = {};
            bf_nfattr *expressions = rule_attrs[NFTA_RULE_EXPRESSIONS];
            bf_nfattr *expression;
            size_t remaining = bf_nfattr_data_len(expressions);

            expression = bf_nfattr_data(expressions);
            while (bf_nfattr_is_ok(expression, remaining)) {
                _cleanup_bf_nfnest_ struct bf_nfnest _ =
                    bf_nfnest_or_jmp(msg, NFTA_LIST_ELEM);

                r = bf_nfattr_parse(expression, expr_attrs, __NFTA_EXPR_MAX,
                                    bf_nf_expr_policy);
                if (r < 0) {
                    return bf_err_code(
                        r, "failed to parse NFTA_EXPR_* attributes");
                }

                bf_nfmsg_push_str_or_jmp(
                    msg, NFTA_EXPR_NAME,
                    bf_nfattr_get_str(expr_attrs[NFTA_EXPR_NAME]));
                if (bf_streq(bf_nfattr_data(expr_attrs[NFTA_EXPR_NAME]),
                             "counter")) {
                    _cleanup_bf_nfnest_ struct bf_nfnest _ =
                        bf_nfnest_or_jmp(msg, NFTA_EXPR_DATA);
                    struct bf_counter counter;

                    r = bf_codegen_get_counter(
                        bf_context_get_codegen(BF_HOOK_XDP, BF_FRONT_NFT), i,
                        &counter);
                    if (r < 0)
                        return bf_err_code(r, "failed to get counter");

                    bf_nfmsg_push_u64_or_jmp(msg, NFTA_COUNTER_BYTES,
                                             be64toh(counter.bytes));
                    bf_nfmsg_push_u64_or_jmp(msg, NFTA_COUNTER_PACKETS,
                                             be64toh(counter.packets));
                } else {
                    bf_nfmsg_attr_push_or_jmp(
                        msg, NFTA_EXPR_DATA,
                        bf_nfattr_data(expr_attrs[NFTA_EXPR_DATA]),
                        bf_nfattr_data_len(expr_attrs[NFTA_EXPR_DATA]));
                }

                expression = bf_nfattr_next(expression, &remaining);
            }
        }

        i++;
        TAKE_PTR(msg);
    }

    return 0;

bf_nfmsg_push_failure:
    return bf_err_code(-EINVAL, "failed to add attribute to Netlink message");
}

static int _bf_nft_request_handle(const struct bf_nfmsg *req,
                                  struct bf_nfgroup *res)
{
    bf_assert(req);
    bf_assert(res);

    int r = 0;

    switch (bf_nfmsg_command(req)) {
    case NFT_MSG_GETGEN:
        r = _bf_nft_getgen_cb(req, res);
        break;
    case NFT_MSG_GETTABLE:
        r = _bf_nft_gettable_cb(req, res);
        break;
    case NFT_MSG_NEWTABLE:
        r = _bf_nft_newtable_cb(req);
        break;
    case NFT_MSG_GETCHAIN:
        r = _bf_nft_getchain_cb(req, res);
        break;
    case NFT_MSG_NEWCHAIN:
        r = _bf_nft_newchain_cb(req);
        break;
    case NFT_MSG_GETRULE:
        r = _bf_nft_getrule_cb(req, res);
        break;
    case NFT_MSG_NEWRULE:
        r = _bf_nft_newrule_cb(req);
        break;
    case NFT_MSG_GETOBJ:
    case NFT_MSG_GETFLOWTABLE:
    case NFT_MSG_GETSET:
        break;
    default:
        r = bf_warn_code(-ENOTSUP, "unsupported nft command %hu",
                         bf_nfmsg_command(req));
        break;
    }

    return r;
}

static int _bf_nft_request_handler(struct bf_request *request,
                                   struct bf_response **response)
{
    bf_assert(request);
    bf_assert(response);

    _cleanup_bf_nfgroup_ struct bf_nfgroup *req = NULL;
    _cleanup_bf_nfgroup_ struct bf_nfgroup *res = NULL;
    int r;

    r = bf_nfgroup_new_from_stream(&req, (struct nlmsghdr *)request->data,
                                   request->data_len);
    if (r < 0)
        return bf_err_code(r, "failed to get bf_nfgroup from request");

    r = bf_nfgroup_new(&res);
    if (r < 0)
        return bf_err_code(r, "failed to create bf_nfgroup");

    bf_list_foreach (bf_nfgroup_messages(req), msg_node) {
        struct bf_nfmsg *msg = bf_list_node_get_data(msg_node);
        r = _bf_nft_request_handle(msg, res);
        if (r)
            return bf_err_code(r, "failed to handle nft request");
    }

    return bf_nfgroup_to_response(res, response);
}
