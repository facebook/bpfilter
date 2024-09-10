/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2022 Meta Platforms, Inc. and affiliates.
 */

#include <errno.h>
#include <stdlib.h>

#include "bpfilter/cgen/cgen.h"
#include "bpfilter/context.h"
#include "bpfilter/xlate/front.h"
#include "core/chain.h"
#include "core/front.h"
#include "core/helper.h"
#include "core/logger.h"
#include "core/marsh.h"
#include "core/request.h"
#include "core/response.h"

static int _bf_cli_setup(void);
static int _bf_cli_teardown(void);
static int _bf_cli_request_handler(struct bf_request *request,
                                   struct bf_response **response);
static int _bf_cli_marsh(struct bf_marsh **marsh);
static int _bf_cli_unmarsh(struct bf_marsh *marsh);

const struct bf_front_ops cli_front = {
    .setup = _bf_cli_setup,
    .teardown = _bf_cli_teardown,
    .request_handler = _bf_cli_request_handler,
    .marsh = _bf_cli_marsh,
    .unmarsh = _bf_cli_unmarsh,
};

static int _bf_cli_setup(void)
{
    return 0;
}

static int _bf_cli_teardown(void)
{
    return 0;
}

int _bf_cli_set_rules(const struct bf_request *request,
                      struct bf_response **response)
{
    _cleanup_bf_chain_ struct bf_chain *chain = NULL;
    struct bf_cgen *cgen;
    int r;

    bf_assert(request);
    bf_assert(response);

    r = bf_chain_new_from_marsh(&chain, (void *)request->data);
    if (r)
        return bf_err_r(r, "failed to create chain from marsh");

    cgen = bf_context_get_cgen(chain->hook, BF_FRONT_CLI);
    if (!cgen) {
        r = bf_cgen_new(&cgen);
        if (r)
            return r;

        cgen->hook = chain->hook;
        cgen->front = BF_FRONT_CLI;
    }

    cgen->policy = chain->policy;
    bf_swap(cgen->rules, chain->rules);

    if (bf_context_get_cgen(chain->hook, BF_FRONT_CLI)) {
        r = bf_cgen_update(cgen);
        if (r)
            return bf_err_r(r, "failed to update codegen");
    } else {
        r = bf_cgen_up(cgen);
        if (r)
            return bf_err_r(r, "failed to load codegen");

        r = bf_context_set_cgen(chain->hook, BF_FRONT_CLI, cgen);
        if (r)
            return bf_err_r(r, "failed to set codegen in context");
    }

    return bf_response_new_success(response, NULL, 0);
}

static int _bf_cli_request_handler(struct bf_request *request,
                                   struct bf_response **response)
{
    int r;

    bf_assert(request);
    bf_assert(response);

    if (request->data_len < sizeof(struct bf_marsh))
        return bf_response_new_failure(response, -EINVAL);

    switch (request->cmd) {
    case BF_REQ_SET_RULES:
        r = _bf_cli_set_rules(request, response);
        break;
    default:
        r = bf_err_r(-EINVAL, "unsupported command %d for CLI front-end",
                     request->cmd);
        break;
    }

    return r;
}

static int _bf_cli_marsh(struct bf_marsh **marsh)
{
    UNUSED(marsh);

    return 0;
}

static int _bf_cli_unmarsh(struct bf_marsh *marsh)
{
    UNUSED(marsh);

    return 0;
}
