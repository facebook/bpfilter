/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2022 Meta Platforms, Inc. and affiliates.
 */

#include <arpa/inet.h>

#include <linux/netfilter.h>
#include <linux/netfilter/nf_tables.h>

#include "core/context.h"
#include "core/hook.h"
#include "core/logger.h"
#include "core/marsh.h"
#include "core/rule.h"
#include "core/verdict.h"
#include "generator/codegen.h"
#include "shared/request.h"
#include "shared/response.h"
#include "xlate/front.h"
#include "xlate/nft/nfgroup.h"
#include "xlate/nft/nfmsg.h"

struct bf_marsh;

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
    struct bf_marsh *child;
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

    switch (ntohl(bf_nfattr_get_u32(chain_attrs[NFTA_CHAIN_POLICY]))) {
    case NF_ACCEPT:
        verdict = BF_VERDICT_ACCEPT;
        break;
    case NF_DROP:
        verdict = BF_VERDICT_DROP;
        break;
    default:
        return bf_err_code(
            -ENOTSUP, "unsupported policy %u",
            ntohl(bf_nfattr_get_u32(chain_attrs[NFTA_CHAIN_POLICY])));
    };

    codegen = bf_context_get_codegen(BF_HOOK_NFT_INGRESS, BF_FRONT_NFT);
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
        codegen->hook = BF_HOOK_NFT_INGRESS;
        codegen->policy = verdict;

        r = bf_codegen_generate(codegen);
        if (r < 0)
            return bf_err_code(r, "failed to generate codegen");

        r = bf_codegen_load(codegen, NULL);
        if (r < 0)
            return bf_err_code(r, "failed to load codegen");

        bf_context_set_codegen(BF_HOOK_NFT_INGRESS, BF_FRONT_NFT, codegen);

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

    // Only BF_HOOK_NFT_INGRESS is supported.
    codegen = bf_context_get_codegen(BF_HOOK_NFT_INGRESS, BF_FRONT_NFT);
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

    bf_codegen_dump(codegen, NULL);

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
    bf_nfmsg_push_u64_or_jmp(msg, NFTA_CHAIN_HANDLE, BF_HOOK_NFT_INGRESS);
    bf_nfmsg_push_u64_or_jmp(msg, NFTA_CHAIN_HANDLE, BF_HOOK_NFT_INGRESS);
    bf_nfmsg_push_u32_or_jmp(msg, NFTA_CHAIN_POLICY, htonl(policy));
    bf_nfmsg_push_str_or_jmp(msg, NFTA_CHAIN_TYPE, "filter");
    bf_nfmsg_push_u32_or_jmp(msg, NFTA_CHAIN_FLAGS, NFT_CHAIN_BASE);
    bf_nfmsg_push_u32_or_jmp(msg, NFTA_CHAIN_USE,
                             htonl(bf_list_size(&codegen->rules)));

    {
        _cleanup_bf_nfnest_ struct bf_nfnest _ =
            bf_nfnest_or_jmp(msg, NFTA_CHAIN_HOOK);

        bf_nfmsg_push_u32_or_jmp(msg, NFTA_HOOK_HOOKNUM,
                                 htonl(NF_INET_PRE_ROUTING));
        bf_nfmsg_push_u32_or_jmp(msg, NFTA_HOOK_PRIORITY, htonl(0));
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
    case NFT_MSG_NEWRULE:
        break;
    case NFT_MSG_GETRULE:
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
