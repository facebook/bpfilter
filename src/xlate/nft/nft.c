/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2022 Meta Platforms, Inc. and affiliates.
 */

#include <linux/netfilter/nf_tables.h>

#include "core/logger.h"
#include "shared/request.h"
#include "shared/response.h"
#include "xlate/front.h"
#include "xlate/nft/nfgroup.h"
#include "xlate/nft/nfmsg.h"

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

static int _bf_nft_request_handle(const struct bf_nfmsg *req,
                                  struct bf_nfgroup *res)
{
    bf_assert(req);
    bf_assert(res);

    int r;

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
