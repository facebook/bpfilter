
/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#include "bfcli/ruleset.h"

#include "core/helper.h"

void bfc_ruleset_clean(struct bfc_ruleset *ruleset)
{
    bf_assert(ruleset);

    bf_list_clean(&ruleset->chains);
    bf_list_clean(&ruleset->hookopts);
    bf_list_clean(&ruleset->sets);
}
