/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2022 Meta Platforms, Inc. and affiliates.
 */

#include "core/marsh.h"
#include "shared/request.h"
#include "shared/response.h"
#include "xlate/front.h"

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

static int _bf_cli_request_handler(struct bf_request *request,
                                   struct bf_response **response)
{
    return 0;
}

static int _bf_cli_marsh(struct bf_marsh **marsh)
{
    return 0;
}

static int _bf_cli_unmarsh(struct bf_marsh *marsh)
{
    return 0;
}
