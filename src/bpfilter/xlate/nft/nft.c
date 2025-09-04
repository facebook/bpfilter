/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2022 Meta Platforms, Inc. and affiliates.
 */

#include <errno.h>

#include "bpfilter/xlate/front.h"
#include "core/helper.h"
#include "core/marsh.h"
#include "core/request.h"
#include "core/response.h"

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

static int _bf_nft_request_handler(const struct bf_request *request,
                                   struct bf_response **response)
{
    UNUSED(request);

    bf_assert(response);

    return bf_response_new_failure(response, -ENOTSUP);
}

const struct bf_front_ops nft_front = {
    .setup = _bf_nft_setup,
    .teardown = _bf_nft_teardown,
    .request_handler = _bf_nft_request_handler,
    .marsh = _bf_nft_marsh,
    .unmarsh = _bf_nft_unmarsh,
};
