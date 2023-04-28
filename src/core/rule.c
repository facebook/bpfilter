/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2022 Meta Platforms, Inc. and affiliates.
 */

#include <errno.h>
#include <stdlib.h>

#include "chain.h"

int bf_rule_new(struct bf_rule **rule)
{
    struct bf_rule *_rule;

    _rule = calloc(1, sizeof(*_rule));
    if (!_rule)
        return -ENOMEM;

    bf_list_init(&_rule->matches,
                 (bf_list_ops[]) {{.free = (bf_list_ops_free)bf_match_free}});

    *rule = _rule;

    return 0;
}

void bf_rule_free(struct bf_rule **rule)
{
    if (!*rule)
        return;

    bf_list_clean(&(*rule)->matches);
    bf_target_free(&(*rule)->target);

    free(*rule);
    *rule = NULL;
}
