/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2022 Meta Platforms, Inc. and affiliates.
 */

#include <errno.h>
#include <stdlib.h>

#include "bpfilter/cgen/cgen.h"
#include "bpfilter/ctx.h"
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

int _bf_cli_ruleset_flush(const struct bf_request *request,
                          struct bf_response **response)
{
    int r;

    UNUSED(request);

    r = bf_ctx_flush();
    if (r)
        return bf_err_r(r, "failed to flush the context");

    return bf_response_new_success(response, NULL, 0);
}

int _bf_cli_set_rules(const struct bf_request *request,
                      struct bf_response **response)
{
    _cleanup_bf_chain_ struct bf_chain *chain = NULL;
    struct bf_cgen *cgen;
    int r;

    bf_assert(request);
    bf_assert(response);

    if (request->data_len < sizeof(struct bf_marsh))
        return bf_response_new_failure(response, -EINVAL);

    r = bf_chain_new_from_marsh(&chain, (void *)request->data);
    if (r)
        return bf_err_r(r, "failed to create chain from marsh");

    cgen = bf_ctx_get_cgen(chain->hook, &chain->hook_opts);
    if (!cgen) {
        r = bf_cgen_new(&cgen, BF_FRONT_CLI, &chain);
        if (r)
            return r;

        r = bf_cgen_up(cgen, request->ns);
        if (r < 0) {
            bf_cgen_free(&cgen);
            return bf_err_r(r, "failed to generate and load new program");
        }

        r = bf_ctx_set_cgen(cgen);
        if (r < 0) {
            bf_cgen_free(&cgen);
            return bf_err_r(r, "failed to store codegen in runtime context");
        }
    } else {
        r = bf_cgen_update(cgen, &chain, request->ns);
        if (r < 0)
            return bf_warn_r(r, "failed to update existing codegen");
    }

    return bf_response_new_success(response, NULL, 0);
}

static int _bf_cli_request_handler(struct bf_request *request,
                                   struct bf_response **response)
{
    int r;

    bf_assert(request);
    bf_assert(response);

    switch (request->cmd) {
    case BF_REQ_RULESET_FLUSH:
        r = _bf_cli_ruleset_flush(request, response);
        break;
    case BF_REQ_RULES_SET:
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
