/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#include "frontend.h"

#include <stdlib.h>

#include "xlate/ipt/ipt.h"

static const struct bf_frontend *frontends[] = {
    [BF_REQ_IPT] = &ipt_frontend,
};

const struct bf_frontend *bf_frontend_get(enum bf_request_type type)
{
    if (type >= __BF_REQ_TYPE_MAX)
        return NULL;

    return frontends[type];
}
