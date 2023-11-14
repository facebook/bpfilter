/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2022 Meta Platforms, Inc. and affiliates.
 */

#include "xlate/nft/nft.h"

#include <arpa/inet.h>

#include <linux/netfilter.h>
#include <linux/netfilter/nf_tables.h>
#include <linux/netfilter/nfnetlink.h>

#include <netlink/attr.h>
#include <stdlib.h>

#include "core/context.h"
#include "core/logger.h"
#include "core/rule.h"
#include "core/verdict.h"
#include "generator/codegen.h"
#include "shared/helper.h"
#include "shared/request.h"
#include "shared/response.h"
#include "xlate/front.h"
#include "xlate/nft/nlmsg.h"
#include "xlate/nft/nlpart.h"

struct bf_marsh;

static const char *_bf_table_name = "bpfilter";

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

static int _bf_nft_setup(void)
{
    return 0;
}

static int _bf_nft_teardown(void)
{
    return 0;
}

static int _bf_nft_marsh(struct bf_marsh **marsh)
{
    UNUSED(marsh);

    return 0;
}

static int _bf_nft_unmarsh(struct bf_marsh *marsh)
{
    UNUSED(marsh);

    return 0;
}

static int _nft_make_part(struct bf_nlpart **part, uint16_t command,
                          uint16_t seqnr)
{
    bf_assert(part);

    _cleanup_bf_nlpart_ struct bf_nlpart *_part = NULL;
    struct nfgenmsg extra_hdr = {
        .nfgen_family = AF_INET,
        .version = NFNETLINK_V0,
        .res_id = 0,
    };
    int r;

    r = bf_nlpart_new(&_part, NFNL_SUBSYS_NFTABLES, command, 0, seqnr);
    if (r < 0)
        return bf_err_code(r, "failed to create bf_nlpart");

    r = bf_nlpart_put_extra_header(_part, &extra_hdr, sizeof(extra_hdr));
    if (r < 0)
        return bf_err_code(r, "failed to add extra header to bf_nlpart");

    *part = TAKE_PTR(_part);

    return 0;
}

static int _bf_nft_getgen_cb(const struct bf_nlpart *req, struct bf_nlmsg *res)
{
    bf_assert(req);
    bf_assert(res);

    _cleanup_bf_nlpart_ struct bf_nlpart *part = NULL;
    int r;

    r = _nft_make_part(&part, NFT_MSG_NEWGEN, bf_nlpart_seqnr(req));
    if (r < 0)
        return bf_err_code(r, "failed to create bf_nlpart");

    bf_nlpart_put_u32_or_jmp(part, NFTA_GEN_ID, 0);
    bf_nlpart_put_u32_or_jmp(part, NFTA_GEN_PROC_PID, getpid());
    bf_nlpart_put_str_or_jmp(part, NFTA_GEN_PROC_NAME, "nft");

    r = bf_nlmsg_add_part(res, part);
    if (r < 0)
        return bf_err_code(r, "failed to add bf_nlpart to bf_nlmsg");

    TAKE_PTR(part);

    return 0;

bf_nlpart_put_failure:
    return -EINVAL;
}

static const struct nla_policy nft_table_policy[__NFTA_TABLE_MAX] = {
    [NFTA_TABLE_NAME] = {.type = NLA_STRING},
    [NFTA_TABLE_FLAGS] = {.type = NLA_U32},
    [NFTA_TABLE_HANDLE] = {.type = NLA_U64},
    [NFTA_TABLE_USERDATA] = {.type = NLA_BINARY},
};

static int _bf_nft_newtable_cb(const struct bf_nlpart *req)
{
    bf_assert(req);

    bf_nlattr *attrs[__NFTA_TABLE_MAX] = {};
    int r;

    r = bf_nlpart_parse(req, sizeof(struct nfgenmsg), attrs, __NFTA_TABLE_MAX,
                        nft_table_policy);
    if (r < 0)
        return bf_err_code(r, "failed to parse bf_nlpart");

    if (!attrs[NFTA_TABLE_NAME])
        return bf_err_code(-EINVAL, "missing NFTA_TABLE_NAME attribute");

    if (!bf_streq(_bf_table_name, bf_nlattr_data(attrs[NFTA_TABLE_NAME]))) {
        return bf_err_code(
            -EINVAL,
            "NFT_MSG_NEWTABLE tried to create a table named '%s', not 'bpfilter'",
            (char *)bf_nlattr_data(attrs[NFTA_TABLE_NAME]));
    }

    return 0;
}

static int _bf_nft_gettable_cb(const struct bf_nlpart *req,
                               struct bf_nlmsg *res)
{
    bf_assert(req);
    bf_assert(res);

    _cleanup_bf_nlpart_ struct bf_nlpart *_part = NULL;
    int r;

    r = _nft_make_part(&_part, NFT_MSG_NEWTABLE, bf_nlpart_seqnr(req));
    if (r < 0)
        return bf_err_code(r, "failed to create bf_nlpart");

    bf_nlpart_put_str_or_jmp(_part, NFTA_TABLE_NAME, _bf_table_name);
    bf_nlpart_put_u32_or_jmp(_part, NFTA_TABLE_FLAGS, 0);
    bf_nlpart_put_u64_or_jmp(_part, NFTA_TABLE_HANDLE, 0);
    bf_nlpart_put_u32_or_jmp(_part, NFTA_TABLE_USE, 0);

    r = bf_nlmsg_add_part(res, _part);
    if (r < 0)
        return bf_err_code(r, "failed to add bf_nlpart to bf_nlmsg");

    TAKE_PTR(_part);

    return 0;

bf_nlpart_put_failure:
    return -EINVAL;
}

static int _bf_nft_create_new_chain(enum bf_hook hook, enum bf_verdict verdict)
{
    _cleanup_bf_codegen_ struct bf_codegen *codegen = NULL;
    int r;

    r = bf_codegen_new(&codegen);
    if (r < 0)
        return bf_err_code(r, "failed to create codegen");

    codegen->front = BF_FRONT_NFT;
    codegen->hook = hook;
    codegen->policy = verdict;

    // Generate and dump codegen
    r = bf_codegen_generate(codegen);
    if (r < 0)
        return bf_err_code(r, "failed to generate codegen");

    bf_codegen_dump(codegen, NULL);

    r = bf_codegen_load(codegen, bf_context_get_codegen(hook, BF_FRONT_NFT));
    if (r)
        return bf_err_code(r, "failed to load codegen");

    bf_context_replace_codegen(hook, BF_FRONT_NFT, TAKE_PTR(codegen));

    return 0;
}

static const struct nla_policy nft_chain_policy[__NFTA_CHAIN_MAX] = {
    [NFTA_CHAIN_TABLE] = {.type = NLA_STRING},
    [NFTA_CHAIN_HANDLE] = {.type = NLA_U64},
    [NFTA_CHAIN_NAME] = {.type = NLA_STRING},
    [NFTA_CHAIN_HOOK] = {.type = NLA_NESTED},
    [NFTA_CHAIN_POLICY] = {.type = NLA_U32},
    [NFTA_CHAIN_TYPE] = {.type = NLA_STRING},
    [NFTA_CHAIN_COUNTERS] = {.type = NLA_NESTED},
    [NFTA_CHAIN_FLAGS] = {.type = NLA_U32},
    [NFTA_CHAIN_ID] = {.type = NLA_U32},
    [NFTA_CHAIN_USERDATA] = {.type = NLA_BINARY},
};

static const struct nla_policy nft_hook_policy[__NFTA_HOOK_MAX] = {
    [NFTA_HOOK_HOOKNUM] = {.type = NLA_U32},
    [NFTA_HOOK_PRIORITY] = {.type = NLA_U32},
    [NFTA_HOOK_DEV] = {.type = NLA_STRING},
};

static int _bf_nft_newchain_cb(const struct bf_nlpart *req)
{
    bf_assert(req);

    bf_nlattr *attrs[__NFTA_CHAIN_MAX] = {};
    bf_nlattr *hookattrs[__NFTA_HOOK_MAX] = {};
    uint32_t _verdict;
    enum bf_verdict verdict;
    uint32_t _hook;
    enum bf_hook hook;
    int r;

    r = bf_nlpart_parse(req, sizeof(struct nfgenmsg), attrs, __NFTA_CHAIN_MAX,
                        nft_chain_policy);
    if (r < 0)
        return bf_err_code(r, "failed to parse bf_nlpart");

    if (!attrs[NFTA_CHAIN_HOOK])
        return bf_err_code(r, "missing NFTA_CHAIN_HOOK attribute");

    r = bf_nlpart_parse_nested(attrs[NFTA_CHAIN_HOOK], hookattrs,
                               __NFTA_HOOK_MAX, nft_hook_policy);
    if (r < 0)
        return bf_err_code(r, "failed to parse nested bf_nlpart");

    if (!attrs[NFTA_CHAIN_TABLE] ||
        !bf_streq(bf_nlattr_data(attrs[NFTA_CHAIN_TABLE]), _bf_table_name))
        return bf_err_code(-EINVAL, "invalid table name");

    if (!attrs[NFTA_CHAIN_POLICY])
        return bf_err_code(-EINVAL, "missing NFTA_CHAIN_POLICY attribute");

    if (!hookattrs[NFTA_HOOK_HOOKNUM])
        return bf_err_code(-EINVAL, "missing NFTA_HOOK_HOOKNUM attribute");

    _verdict = ntohl(nla_get_u32(attrs[NFTA_CHAIN_POLICY]));
    switch (_verdict) {
    case NF_ACCEPT:
        verdict = BF_VERDICT_ACCEPT;
        break;
    case NF_DROP:
        verdict = BF_VERDICT_DROP;
        break;
    default:
        return bf_err_code(-ENOTSUP, "unsupported policy %u", _verdict);
    };

    _hook = nla_get_u32(hookattrs[NFTA_HOOK_HOOKNUM]);
    switch (_hook) {
    case NF_INET_PRE_ROUTING:
        hook = BF_HOOK_NFT_INGRESS;
        break;
    default:
        return bf_err_code(-ENOTSUP, "unsupported hook %u", _hook);
    };

    return _bf_nft_create_new_chain(hook, verdict);
}

static int _bf_nft_request_handle(struct bf_nlpart *req, struct bf_nlmsg *res)
{
    bf_assert(req);
    bf_assert(res);

    int r;

    switch (bf_nlpart_command(req)) {
    case NFT_MSG_GETGEN:
        r = _bf_nft_getgen_cb(req, res);
        break;
    case NFT_MSG_NEWTABLE:
        r = _bf_nft_newtable_cb(req);
        break;
    case NFT_MSG_GETTABLE:
        r = _bf_nft_gettable_cb(req, res);
        break;
    case NFT_MSG_NEWCHAIN:
        r = _bf_nft_newchain_cb(req);
        break;
    default:
        bf_warn("received unknown message (%hu)", bf_nlpart_command(req));
        r = -ENOTSUP;
        break;
    }

    return r;
}

static int _bf_nft_request_handler(struct bf_request *request,
                                   struct bf_response **response)
{
    bf_assert(request);
    bf_assert(response);

    _cleanup_bf_nlmsg_ struct bf_nlmsg *req = NULL;
    _cleanup_bf_nlmsg_ struct bf_nlmsg *res = NULL;
    int r;

    r = bf_nlmsg_new_from_stream(&req, (struct nlmsghdr *)request->data,
                                 request->data_len);
    if (r < 0)
        return bf_err_code(r, "failed to create bf_nlmsg from request");

    r = bf_nlmsg_new(&res);
    if (r < 0)
        return bf_err_code(r, "failed to create bf_nlmsg");

    bf_nlmsg_dump(req, sizeof(struct nfgenmsg), NULL);

    bf_list_foreach (bf_nlmsg_parts(req), part_node) {
        struct bf_nlpart *part = bf_list_node_get_data(part_node);
        r = _bf_nft_request_handle(part, res);
        if (r)
            return bf_err_code(r, "failed to handle request");
    }

    return bf_nlmsg_to_response(res, response);
}
