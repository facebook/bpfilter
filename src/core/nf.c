/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#include "core/nf.h"

#include "core/helper.h"

enum nf_inet_hooks bf_hook_to_nf_hook(enum bf_hook hook)
{
    bf_assert(hook >= BF_HOOK_NF_PRE_ROUTING ||
              hook <= BF_HOOK_NF_POST_ROUTING);

    enum nf_inet_hooks hooks[] = {
        [BF_HOOK_NF_PRE_ROUTING] = NF_INET_PRE_ROUTING,
        [BF_HOOK_NF_LOCAL_IN] = NF_INET_LOCAL_IN,
        [BF_HOOK_NF_FORWARD] = NF_INET_FORWARD,
        [BF_HOOK_NF_LOCAL_OUT] = NF_INET_LOCAL_OUT,
        [BF_HOOK_NF_POST_ROUTING] = NF_INET_POST_ROUTING,
    };

    return hooks[hook];
}
