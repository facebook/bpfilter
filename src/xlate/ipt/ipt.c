/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2022 Meta Platforms, Inc. and affiliates.
 */

#include "xlate/ipt/ipt.h"

#include <linux/netfilter.h>

#include <stdio.h>

#include "core/chain.h"
#include "core/logger.h"
#include "core/match.h"
#include "core/rule.h"
#include "core/target.h"
#include "generator/codegen.h"
#include "shared/helper.h"
#include "shared/mem.h"
#include "xlate/ipt/dump.h"
#include "xlate/ipt/helpers.h"

const struct bf_frontend ipt_frontend = {
    .translate = (bf_fe_translate_fn)bf_ipt_translate,
    .generate = NULL,
    .dump = (bf_fe_dump_fn)bf_ipt_dump_replace,
};

static enum bf_hooks bf_ipt_hook_to_bf_hook(enum nf_inet_hooks ipt_hook)
{
    switch (ipt_hook) {
    case NF_INET_PRE_ROUTING:
        return BF_HOOK_IPT_PRE_ROUTING;
    case NF_INET_LOCAL_IN:
        return BF_HOOK_IPT_LOCAL_IN;
    case NF_INET_FORWARD:
        return BF_HOOK_IPT_FORWARD;
    case NF_INET_LOCAL_OUT:
        return BF_HOOK_IPT_LOCAL_OUT;
    case NF_INET_POST_ROUTING:
        return BF_HOOK_IPT_POST_ROUTING;
    default:
        return __BF_HOOK_MAX;
    }
}

static int bf_ipt_to_target(struct ipt_entry_target *ipt_target,
                            struct bf_target **target)
{
    __cleanup_bf_target__ struct bf_target *_target;
    int r;

    r = bf_target_new(&_target);
    if (r < 0)
        return r;

    *target = TAKE_PTR(_target);

    return 0;
}

static int bf_ipt_to_match(struct ipt_entry_match *ipt_match,
                           struct bf_match **match)
{
    __cleanup_bf_match__ struct bf_match *_match = NULL;
    int r;

    r = bf_match_new(&_match);
    if (r < 0)
        return r;

    *match = TAKE_PTR(_match);

    return 0;
}

static int bf_ipt_to_rule(struct ipt_entry *ipt_rule, struct bf_rule **rule)
{
    __cleanup_bf_rule__ struct bf_rule *_rule = NULL;
    __cleanup_bf_match__ struct bf_match *match = NULL;
    __cleanup_bf_target__ struct bf_target *target = NULL;
    size_t offset = sizeof(*ipt_rule);
    int r;

    r = bf_rule_new(&_rule);
    if (r < 0)
        return r;

    while (offset < ipt_rule->target_offset) {
        r = bf_ipt_to_match(ipt_get_match(ipt_rule, offset), &match);
        if (r < 0)
            return r;

        r = bf_list_add_tail(&(_rule->matches), match);
        if (r < 0)
            return r;

        /* Match has been added to the rule, so if anything goes wrong from
         * here, it will be freed by the rule directly. */
        TAKE_PTR(match);

        offset += ipt_get_match(ipt_rule, offset)->u.match_size;
    }

    r = bf_ipt_to_target(ipt_get_target(ipt_rule), &target);
    if (r < 0)
        return r;
    _rule->target = TAKE_PTR(target);

    *rule = TAKE_PTR(_rule);

    return 0;
}

static int bf_ipt_to_chain(struct ipt_entry *ipt_rule_first,
                           struct ipt_entry *ipt_rule_last,
                           struct bf_chain **chain)
{
    __cleanup_bf_chain__ struct bf_chain *_chain = NULL;
    __cleanup_bf_rule__ struct bf_rule *rule = NULL;
    int r;

    r = bf_chain_new(&_chain);
    if (r < 0)
        return r;

    while (ipt_rule_first <= ipt_rule_last) {
        r = bf_ipt_to_rule(ipt_rule_first, &rule);
        if (r < 0)
            return r;

        r = bf_list_add_tail(&_chain->rules, rule);
        if (r < 0)
            return r;

        /* Rule has been added to the chain, so if anything goes wrong from
         * here, it wil be freed by the chain directly. */
        TAKE_PTR(rule);

        ipt_rule_first = ipt_get_next_rule(ipt_rule_first);
    }

    *chain = TAKE_PTR(_chain);

    return 0;
}

int bf_ipt_translate(void *data, size_t data_size,
                     bf_list (*codegens)[__BF_HOOK_MAX])
{
    struct ipt_entry *first_rule, *last_rule;
    struct ipt_replace *ipt = data;
    int r;

    assert(data);
    assert(codegens);

    UNUSED(data_size);

    for (int i = 0; i < NF_INET_NUMHOOKS; ++i) {
        __cleanup_bf_chain__ struct bf_chain *chain = NULL;
        __cleanup_bf_codegen__ struct bf_codegen *codegen = NULL;

        if (!ipt_is_hook_enabled(ipt, i)) {
            bf_info("Hook %d is not enabled, skipping\n", i);
            continue;
        }

        enum bf_hooks bf_hook = bf_ipt_hook_to_bf_hook(i);

        first_rule = ipt_get_first_rule(ipt, i);
        last_rule = ipt_get_last_rule(ipt, i);

        r = bf_ipt_to_chain(first_rule, last_rule, &chain);
        if (r < 0)
            return r;

        r = bf_codegen_new(&codegen);
        if (r < 0)
            return r;

        codegen->chain = TAKE_PTR(chain);

        /**
         * @todo Copy the rulesets from the original iptables structure to the
         *  codegen structure.
         */

        r = bf_list_add_tail(&(*codegens)[bf_hook], codegen);
        if (r < 0)
            return r;

        /* Codegen has been added to the list, so if anything goes wrong from
         * here, it will be freed by the list directly. */
        TAKE_PTR(codegen);
    }

    return 0;
}
