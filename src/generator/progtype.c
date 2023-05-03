/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#include "progtype.h"

#include <stdlib.h>

#include "tc.h"

static const struct bf_progtype_ops *progtype_ops[] = {
    [BF_PROGTYPE_TC] = &bf_progtype_ops_tc,
};

const struct bf_progtype_ops *bf_progtype_ops_get(enum bf_progtype type)
{
    return progtype_ops[type];
}

const char *bf_progtype_to_str(enum bf_progtype type)
{
    switch (type) {
    case BF_PROGTYPE_TC:
        return "BF_PROGTYPE_TC";
    default:
        return NULL;
    }
}

enum bf_progtype bf_hook_to_progtype(enum bf_hooks hook)
{
    switch (hook) {
    case BF_HOOK_TC_INGRESS:
    case BF_HOOK_IPT_PRE_ROUTING:
    case BF_HOOK_IPT_LOCAL_IN:
    case BF_HOOK_IPT_FORWARD:
    case BF_HOOK_IPT_LOCAL_OUT:
    case BF_HOOK_IPT_POST_ROUTING:
    case BF_HOOK_TC_EGRESS:
        return BF_PROGTYPE_TC;
    default:
        return __BF_PROGTYPE_MAX;
    }
}
