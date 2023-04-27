/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2022 Meta Platforms, Inc. and affiliates.
 */

#include "chain.h"

#include <errno.h>
#include <stdlib.h>

int bf_chain_new(struct bf_chain **chain)
{
    struct bf_chain *_chain;

    _chain = calloc(1, sizeof(*_chain));
    if (!_chain)
        return -ENOMEM;

    bf_list_init(&_chain->rules, NULL);

    *chain = _chain;

    return 0;
}

void bf_chain_free(struct bf_chain **chain)
{
    if (!*chain)
        return;

    bf_list_foreach (&(*chain)->rules, node) {
        struct bf_rule *rule = bf_list_node_get_data(node);
        bf_rule_free(&rule);
    }

    bf_list_clean(&(*chain)->rules);

    free(*chain);
    *chain = NULL;
}
