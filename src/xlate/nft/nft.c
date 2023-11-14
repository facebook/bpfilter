/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2022 Meta Platforms, Inc. and affiliates.
 */

#include <linux/netfilter/nfnetlink.h>

#include <stdlib.h>

#include "core/logger.h"
#include "core/marsh.h"
#include "shared/request.h"
#include "shared/response.h"
#include "xlate/front.h"
#include "xlate/nft/nlmsg.h"
#include "xlate/nft/nlpart.h"

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

    bf_nlmsg_dump(req, sizeof(struct nfgenmsg), NULL);

    return -ENOTSUP;
}
