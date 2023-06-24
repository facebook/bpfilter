/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2022 Meta Platforms, Inc. and affiliates.
 */

#include "shared/ipt.h"

#include <net/if.h>

#include <linux/in.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4/ip_tables.h>

#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "core/context.h"
#include "core/counter.h"
#include "core/flavor.h"
#include "core/hook.h"
#include "core/list.h"
#include "core/logger.h"
#include "core/marsh.h"
#include "core/match.h"
#include "core/rule.h"
#include "core/string.h"
#include "core/target.h"
#include "generator/codegen.h"
#include "generator/program.h"
#include "shared/front.h"
#include "shared/helper.h"
#include "shared/request.h"
#include "shared/response.h"
#include "xlate/front.h"
#include "xlate/ipt/dump.h"
#include "xlate/ipt/helpers.h"

/**
 * @file ipt.c
 *
 * @warning Only LOCAL_IN and LOCAL_OUT chains are currently supported, until
 * BPF_NETFILTER programs can be generated. To ensure only those rules are
 * processed, we store the index and length of the chains statically.
 */

struct ipt_rules_range
{
    size_t idx;
    size_t len;
};

struct bf_ipt_cache
{
    unsigned int valid_hooks;
    unsigned int hook_entry[NF_INET_NUMHOOKS];
    unsigned int underflow[NF_INET_NUMHOOKS];
    unsigned int num_entries;
    unsigned int size;
    struct ipt_entry *entries;
};

static struct ipt_rules_range _in_rules = {};
static struct ipt_rules_range _out_rules = {};

/**
 * @brief Check whether @p rule_idx is in @p range.
 *
 * Rule ranges are used to define which rules, from a sequence of rules, are
 * supported by bpfilter.
 *
 * @param rule_idx Rule index to check.
 * @param range Range to check.
 * @return True if @p rule_idx is in @p range, false otherwise.
 */
#define rule_idx_is_in_range(rule_idx, range)                                  \
    ({                                                                         \
        typeof(range) _range = (range);                                        \
        typeof(rule_idx) _idx = (rule_idx);                                    \
        (_range.idx <= _idx && _idx < (_range.idx + _range.len));              \
    })

static void _bf_ipt_cache_free(struct bf_ipt_cache **cache);

#define _cleanup_bf_ipt_cache_ __attribute__((cleanup(_bf_ipt_cache_free)))

static struct bf_ipt_cache *_cache = NULL;

/// Default iptables filter table. Required to initialize iptables.
static unsigned char _default_ipt_filter[] = {
    0x66, 0x69, 0x6c, 0x74, 0x65, 0x72, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0e, 0x00, 0x00, 0x00,
    0x04, 0x00, 0x00, 0x00, 0x78, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x98, 0x00, 0x00, 0x00, 0x30, 0x01, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x98, 0x00, 0x00, 0x00, 0x30, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x04, 0x00, 0x00, 0x00, 0x10, 0x32, 0x40, 0x36, 0x43, 0x56, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x70, 0x00, 0x98, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x28, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0xfe, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x70, 0x00, 0x98, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x28, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xfe, 0xff, 0xff, 0xff,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x70, 0x00, 0x98, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x28, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0xfe, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x70, 0x00, 0xb0, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x45, 0x52, 0x52, 0x4f, 0x52, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x45, 0x52, 0x52, 0x4f, 0x52, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
};

static int _bf_ipt_setup(void);
static int _bf_ipt_teardown(void);
static int _bf_ipt_request_handler(struct bf_request *request,
                                   struct bf_response **response);
static int _bf_ipt_marsh(struct bf_marsh **marsh);
static int _bf_ipt_unmarsh(struct bf_marsh *marsh);

const struct bf_front_ops ipt_front = {
    .setup = _bf_ipt_setup,
    .teardown = _bf_ipt_teardown,
    .request_handler = _bf_ipt_request_handler,
    .marsh = _bf_ipt_marsh,
    .unmarsh = _bf_ipt_unmarsh,
};

/**
 * @brief Convert an iptables hook to a bpfilter hook.
 *
 * @param ipt_hook iptables hook. Must be valid.
 * @return bpfilter hook.
 */
static enum bf_hook _bf_ipt_hook_to_bf_hook(enum nf_inet_hooks ipt_hook)
{
    assert(0 <= ipt_hook && ipt_hook <= NF_INET_NUMHOOKS);

    switch (ipt_hook) {
    case NF_INET_PRE_ROUTING:
    case NF_INET_LOCAL_IN:
    case NF_INET_FORWARD:
        return BF_HOOK_TC_INGRESS;
    case NF_INET_LOCAL_OUT:
    case NF_INET_POST_ROUTING:
        return BF_HOOK_TC_EGRESS;
    default:
        bf_abort("invalid ipt_hook: %d", ipt_hook);
    }
}

static enum bf_target_standard_verdict
_bf_ipt_std_verdict_to_verdict(int verdict)
{
    assert(verdict == NF_DROP || verdict == NF_ACCEPT);

    switch (verdict) {
    case NF_ACCEPT:
        return BF_TARGET_STANDARD_ACCEPT;
    case NF_DROP:
        return BF_TARGET_STANDARD_DROP;
    default:
        assert(0);
        return 0;
    };
}

static inline int _bf_ipt_convert_verdict(int verdict)
{
    return -verdict - 1;
}

static int _bf_ipt_cache_new(struct bf_ipt_cache **cache)
{
    _cleanup_bf_ipt_cache_ struct bf_ipt_cache *_cache = NULL;

    assert(cache);

    _cache = calloc(1, sizeof(*_cache));
    if (!_cache)
        return -ENOMEM;

    *cache = TAKE_PTR(_cache);

    return 0;
}

static void _bf_ipt_cache_free(struct bf_ipt_cache **cache)
{
    if (!*cache)
        return;

    free((*cache)->entries);
    free(*cache);

    *cache = NULL;
}

/**
 * @brief Convert an iptables target to a bpfilter target.
 *
 * @param ipt_target iptables target to convert.
 * @param target Target to store the conversion in.
 * @return 0 on success, negative error code on failure.
 */
static int _bf_ipt_to_target(struct ipt_entry_target *ipt_target,
                             struct bf_target **target)
{
    _cleanup_bf_target_ struct bf_target *_target;
    int r;

    r = bf_target_new(&_target);
    if (r < 0)
        return r;

    if (streq("", ipt_target->u.user.name)) {
        int verdict;
        struct ipt_standard_target *ipt_std_target =
            (struct xt_standard_target *)ipt_target;

        if (ipt_std_target->verdict >= 0) {
            return bf_err_code(
                -ENOTSUP,
                "target expects jump to a user-defined chain, this is not supported");
        }

        _target->type = BF_TARGET_TYPE_STANDARD;

        verdict = _bf_ipt_convert_verdict(ipt_std_target->verdict);
        _target->verdict = _bf_ipt_std_verdict_to_verdict(verdict);
    } else if (streq("ERROR", ipt_target->u.user.name)) {
        _target->type = BF_TARGET_TYPE_ERROR;
    } else {
        return bf_err_code(-EINVAL, "Unknown target: %s",
                           ipt_target->u.user.name);
    }

    *target = TAKE_PTR(_target);

    return 0;
}

/**
 * @brief Translate an iptables match into a bpfilter match.
 *
 * @todo Convert actual match content.
 *
 * @param ipt_match iptables match to translate.
 * @param match Match to store the translation in.
 * @return 0 on success, negative error code on failure.
 */
static int _bf_ipt_to_match(const struct ipt_entry_match *ipt_match,
                            struct bf_match **match)
{
    _cleanup_bf_match_ struct bf_match *_match = NULL;
    int r;

    r = bf_match_new(&_match);
    if (r < 0)
        return r;

    *match = TAKE_PTR(_match);

    return 0;
}

/**
 * @brief Translate an iptables rule into a bpfilter rule.
 *
 * @todo Bound check the target.
 *
 * @param ipt_rule iptables rule to translate.
 * @param rule Rule to store the translation in.
 * @return 0 on success, negative error code on failure.
 */
static int _bf_ipt_to_rule(const struct ipt_entry *ipt_rule,
                           struct bf_rule **rule)
{
    _cleanup_bf_rule_ struct bf_rule *_rule = NULL;
    _cleanup_bf_match_ struct bf_match *match = NULL;
    _cleanup_bf_target_ struct bf_target *target = NULL;
    size_t offset = sizeof(*ipt_rule);
    int r;

    r = bf_rule_new(&_rule);
    if (r < 0)
        return r;

    if (strlen(ipt_rule->ip.iniface)) {
        _rule->ifindex = if_nametoindex(ipt_rule->ip.iniface);
        if (!_rule->ifindex) {
            return bf_err_code(errno, "can't find index for interface %s",
                               ipt_rule->ip.iniface);
        }
    }

    _rule->invflags = ipt_rule->ip.invflags;
    _rule->src = ipt_rule->ip.src.s_addr;
    _rule->src_mask = ipt_rule->ip.smsk.s_addr;
    _rule->dst = ipt_rule->ip.dst.s_addr;
    _rule->dst_mask = ipt_rule->ip.dmsk.s_addr;
    _rule->protocol = ipt_rule->ip.proto;

    while (offset < ipt_rule->target_offset) {
        r = _bf_ipt_to_match(ipt_get_match(ipt_rule, offset), &match);
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

    r = _bf_ipt_to_target(ipt_get_target(ipt_rule), &target);
    if (r < 0)
        return r;
    _rule->target = TAKE_PTR(target);

    *rule = TAKE_PTR(_rule);

    return 0;
}

/**
 * @brief Translate iptables rules into bpfilter format.
 *
 * @param ipt iptables rules.
 * @param codegens Array of codegens, indexed by hook. At most one codegen per
 *  hook will be generated.
 * @return 0 on success, negative error code on failure.
 */
static int _ipt_xlate_set_rules(struct ipt_replace *ipt,
                                struct bf_codegen *(*codegens)[_BF_HOOK_MAX])
{
    struct ipt_entry *first_rule;
    struct ipt_entry *last_rule;
    size_t rule_idx = 0;
    int r;

    assert(ipt);
    assert(codegens);

    for (int i = 0; i < NF_INET_NUMHOOKS; ++i) {
        _cleanup_bf_codegen_ struct bf_codegen *codegen = NULL;
        enum bf_hook hook = _bf_ipt_hook_to_bf_hook(i);
        struct ipt_rules_range *rules_range;

        if (!ipt_is_hook_enabled(ipt, i)) {
            bf_dbg("ipt hook %d is not enabled, skipping", i);
            continue;
        }

        r = bf_codegen_new(&codegen);
        if (r < 0)
            return r;

        codegen->front = BF_FRONT_IPT;
        codegen->hook = hook;

        first_rule = ipt_get_first_rule(ipt, i);
        last_rule = ipt_get_last_rule(ipt, i);

        while (first_rule <= last_rule) {
            _cleanup_bf_rule_ struct bf_rule *rule = NULL;
            r = _bf_ipt_to_rule(first_rule, &rule);
            if (r < 0)
                return r;

            rule->index = rule_idx++;
            r = bf_list_add_tail(&codegen->rules, rule);
            if (r < 0)
                return r;

            /* Rule has been added to the chain, so if anything goes wrong from
             * here, it wil be freed by the chain directly. */
            TAKE_PTR(rule);

            first_rule = ipt_get_next_rule(first_rule);
        }

        if (i != NF_INET_LOCAL_IN && i != NF_INET_LOCAL_OUT) {
            bf_warn(
                "discarding all chains which are neither NF_INET_LOCAL_IN nor NF_INET_LOCAL_OUT");
            continue;
        }

        rules_range = i == NF_INET_LOCAL_IN ? &_in_rules : &_out_rules;
        rules_range->idx = rule_idx;
        rules_range->len = bf_list_size(&codegen->rules);
        rule_idx += rules_range->len;

        bf_dbg("created codegen for %s::%s", bf_front_to_str(codegen->front),
               bf_hook_to_str(codegen->hook));

        (*codegens)[hook] = TAKE_PTR(codegen);
    }

    return 0;
}

/**
 * @brief Modify existing iptables rules.
 *
 * @todo If processing for any codegen fails, all codegens should be unloaded
 * and/or discarded.
 *
 * @param replace New rules, in iptables format.
 * @param len Length of the new rules.
 * @return 0 on success, negative error code on failure.
 */
static int _bf_ipt_set_rules_handler(struct ipt_replace *replace, size_t len)
{
    _cleanup_free_ struct ipt_entry *entries = NULL;
    struct bf_codegen *codegens[_BF_HOOK_MAX] = {};
    int r;

    assert(replace);
    assert(bf_ipt_replace_size(replace) == len);

    bf_ipt_dump_replace(replace, NULL);

    r = _ipt_xlate_set_rules(replace, &codegens);
    if (r < 0)
        return bf_err_code(r, "failed to translate iptables rules");

    /* Copy entries now, so we don't have to unload the codegens if the copy
     * fails. */
    entries = bf_memdup(replace->entries, replace->size);
    if (!entries)
        return bf_err_code(-ENOMEM, "failed to duplicate iptables rules");

    for (int i = 0; i < _BF_HOOK_MAX; i++) {
        struct bf_codegen *prev_codegen;
        _cleanup_bf_codegen_ struct bf_codegen *codegen = codegens[i];

        /// @todo Fix TAKE_PTR() to work with arrays.
        codegens[i] = NULL;

        if (!codegen)
            continue;

        r = bf_codegen_generate(codegen);
        if (r) {
            return bf_err_code(
                r, "failed to generate bytecode for hook %d, skipping",
                codegen->hook);
        }

        // We don't care about the return value: we just want the codegen to be
        // deleted if it exists.
        prev_codegen = bf_context_get_codegen(i, BF_FRONT_IPT);
        if (prev_codegen) {
            bf_codegen_unload(prev_codegen);
            bf_context_delete_codegen(i, BF_FRONT_IPT);
        }

        r = bf_codegen_load(codegen);
        if (r)
            return bf_err_code(r, "failed to load codegen");

        r = bf_context_set_codegen(i, BF_FRONT_IPT, codegen);
        if (r)
            return bf_err_code(r, "failed to add codegen to context");

        TAKE_PTR(codegen);
    }

    _cache->valid_hooks = replace->valid_hooks;
    memcpy(_cache->hook_entry, replace->hook_entry, sizeof(_cache->hook_entry));
    memcpy(_cache->underflow, replace->underflow, sizeof(_cache->underflow));
    _cache->size = replace->size;
    _cache->entries = TAKE_PTR(entries);

    return 0;
}

/**
 * @brief Set counters for a rule.
 *
 * @todo Actually update the counters.
 *
 * @param counters iptables structure containing the counters and their value.
 * @param len Length of the counters structure.
 * @return 0 on success, negative error code on failure.
 */
static int _bf_ipt_set_counters_handler(struct xt_counters_info *counters,
                                        size_t len)
{
    size_t rule_idx = 0;

    assert(counters);
    assert(bf_xt_counters_info_size(counters) == len);

    bf_context_foreach_codegen_by_fe(codegen, BF_FRONT_IPT)
    {
        if (!rule_idx_is_in_range(rule_idx, _in_rules) &&
            !rule_idx_is_in_range(rule_idx, _out_rules)) {
            bf_warn("skipping counters for rule index %lu", rule_idx);
            continue;
        }

        ++rule_idx;
    }

    return 0;
}

int _bf_ipt_get_info_handler(struct bf_request *request,
                             struct bf_response **response)
{
    struct ipt_getinfo *info = (struct ipt_getinfo *)request->data;

    assert(request);
    assert(sizeof(*info) == request->data_len);

    if (!streq(info->name, "filter")) {
        return bf_err_code(
            -EINVAL, "can't process IPT_SO_GET_INFO for table %s", info->name);
    }

    info->valid_hooks = _cache->valid_hooks;
    memcpy(info->hook_entry, _cache->hook_entry, sizeof(_cache->hook_entry));
    memcpy(info->underflow, _cache->underflow, sizeof(_cache->underflow));
    info->num_entries = _cache->num_entries;
    info->size = _cache->size;

    return bf_response_new_success(response, (const char *)info,
                                   sizeof(struct ipt_getinfo));
}

/**
 * @brief Get the entries of a table, including counters.
 *
 * @param request
 * @param response
 * @return 0 on success, negative errno value on failure.
 */
int _bf_ipt_get_entries_handler(struct bf_request *request,
                                struct bf_response **response)
{
    struct ipt_get_entries *entries;
    int r;

    assert(request);
    assert(response);

    entries = (struct ipt_get_entries *)request->data;

    if (!streq(entries->name, "filter")) {
        return bf_err_code(-EINVAL,
                           "can't process IPT_SO_GET_INFO for table %s",
                           entries->name);
    }

    if (entries->size != _cache->size) {
        return bf_err_code(
            -EINVAL,
            "not enough space to store entries: %u available, %u required",
            entries->size, _cache->size);
    }

    memcpy(entries->entrytable, _cache->entries, _cache->size);

    for (int i = 0; i < NF_INET_NUMHOOKS; ++i) {
        struct ipt_entry *first_rule;
        struct ipt_entry *last_rule;
        struct ipt_entry *it;
        struct bf_codegen *codegen;
        struct bf_list_node *rule_node = NULL;
        enum bf_hook hook = _bf_ipt_hook_to_bf_hook(i);

        if (i != NF_INET_LOCAL_IN && i != NF_INET_LOCAL_OUT) {
            bf_warn(
                "skipping all chains which are neither NF_INET_LOCAL_IN nor NF_INET_LOCAL_OUT");
            continue;
        }

        first_rule = bf_ipt_entries_get_rule(entries, _cache->hook_entry[i]);
        last_rule = bf_ipt_entries_get_rule(entries, _cache->underflow[i]);
        codegen = bf_context_get_codegen(hook, BF_FRONT_IPT);

        size_t rules_count = 0;
        it = first_rule;
        while (it <= last_rule) {
            ++rules_count;
            it->counters.pcnt = 0;
            it->counters.bcnt = 0;
            it = ipt_get_next_rule(it);
        }

        if (rules_count != bf_list_size(&codegen->rules)) {
            bf_warn(
                "number of rules in chain %s::%s does not match: %lu vs %lu",
                bf_front_to_str(codegen->front), bf_hook_to_str(codegen->hook),
                rules_count, bf_list_size(&codegen->rules));
            continue;
        }

        bf_list_foreach (&codegen->programs, program_node) {
            struct bf_program *program = bf_list_node_get_data(program_node);
            rule_node = bf_list_get_head(&codegen->rules);

            it = first_rule;
            while (it <= last_rule) {
                struct bf_counter counters = {};
                struct bf_rule *rule = bf_list_node_get_data(rule_node);
                if (!rule) {
                    bf_warn("missing rule for codegen %s::%s",
                            bf_front_to_str(codegen->front),
                            bf_hook_to_str(codegen->hook));
                    break;
                }

                if (rule->ifindex != 0 && rule->ifindex != program->ifindex) {
                    rule_node = bf_list_node_next(rule_node);
                    it = ipt_get_next_rule(it);
                    continue;
                }

                r = bf_program_get_counters(program, rule, &counters);
                if (r < 0) {
                    return bf_err_code(
                        r, "failed to get counters for rule %s::%s::%u",
                        bf_front_to_str(codegen->front),
                        bf_hook_to_str(codegen->hook), rule->index);
                }

                it->counters.pcnt += counters.packets;
                it->counters.bcnt += counters.bytes;

                rule_node = bf_list_node_next(rule_node);
                it = ipt_get_next_rule(it);
            }
        }
    }

    return bf_response_new_success(response, (const char *)entries,
                                   sizeof(*entries) + entries->size);
}

static int _bf_ipt_setup(void)
{
    int r;

    if (_cache) {
        bf_info("cache already initialised, skipping initialisation");
        return 0;
    }

    r = _bf_ipt_cache_new(&_cache);
    if (r < 0)
        return r;

    return _bf_ipt_set_rules_handler((struct ipt_replace *)_default_ipt_filter,
                                     sizeof(_default_ipt_filter));
}

static int _bf_ipt_teardown(void)
{
    _cleanup_bf_ipt_cache_ struct bf_ipt_cache *cache = _cache;

    return 0;
}

/**
 * @brief
 *
 * @todo Wouldn't it be better to have a separate handler for each request type?
 *  In which case struct bf_front_ops would contain a handler for each request
 *  type, and the front would handle custom (BF_REQ_CUSTOM) requests itself.
 * @todo Document that request and responses are not const: they will be free
 *  by the daemon once the front is done with them. Hence, the front is free
 *  to modify the requests content.
 * @todo Check assertions: a malformed request could cause the daemon to crash.
 *
 * @param request
 * @param response
 * @return
 */
static int _bf_ipt_request_handler(struct bf_request *request,
                                   struct bf_response **response)
{
    int r;

    switch (request->cmd) {
    case BF_REQ_SET_RULES:
        r = _bf_ipt_set_rules_handler((struct ipt_replace *)request->data,
                                      request->data_len);
        if (r < 0)
            return r;

        return bf_response_new_success(response, request->data,
                                       request->data_len);
    case BF_REQ_SET_COUNTERS:
        r = _bf_ipt_set_counters_handler(
            (struct xt_counters_info *)request->data, request->data_len);
        if (r < 0)
            return r;

        return bf_response_new_success(response, request->data,
                                       request->data_len);
    case BF_REQ_CUSTOM:
        switch (request->ipt_cmd) {
        case IPT_SO_GET_INFO:
            return _bf_ipt_get_info_handler(request, response);
        case IPT_SO_GET_ENTRIES:
            return _bf_ipt_get_entries_handler(request, response);
        default:
            return bf_warn_code(-ENOTSUP,
                                "unsupported custom ipt request type: %d",
                                request->ipt_cmd);
        };
    default:
        return bf_warn_code(-ENOTSUP, "unsupported ipt request type: %d",
                            request->cmd);
    };

    return 0;
}

static int _bf_ipt_marsh(struct bf_marsh **marsh)
{
    _cleanup_bf_marsh_ struct bf_marsh *_marsh = NULL;
    int r;

    assert(marsh);

    r = bf_marsh_new(&_marsh, NULL, 0);
    if (r < 0)
        return r;

    r |= bf_marsh_add_child_raw(&_marsh, &_cache->valid_hooks,
                                sizeof(_cache->valid_hooks));
    r |= bf_marsh_add_child_raw(&_marsh, &_cache->hook_entry,
                                sizeof(_cache->hook_entry));
    r |= bf_marsh_add_child_raw(&_marsh, &_cache->underflow,
                                sizeof(_cache->underflow));
    r |= bf_marsh_add_child_raw(&_marsh, &_cache->num_entries,
                                sizeof(_cache->num_entries));
    r |= bf_marsh_add_child_raw(&_marsh, &_cache->size, sizeof(_cache->size));
    r |= bf_marsh_add_child_raw(&_marsh, _cache->entries, _cache->size);
    if (r)
        return r;

    *marsh = TAKE_PTR(_marsh);

    bf_dbg("Saved bf_ipt_cache at %p:", _cache);
    bf_dbg("  valid_hooks: %u", _cache->valid_hooks);
    bf_dbg("  num_entries: %u", _cache->num_entries);
    bf_dbg("  size: %u", _cache->size);

    return 0;
}

static int _bf_ipt_unmarsh(struct bf_marsh *marsh)
{
    _cleanup_bf_ipt_cache_ struct bf_ipt_cache *cache = NULL;
    struct bf_marsh *child = NULL;
    int r;

    assert(marsh);

    r = _bf_ipt_cache_new(&cache);
    if (r < 0)
        return -ENOMEM;

    if (!(child = bf_marsh_next_child(marsh, NULL)))
        return -EINVAL;
    memcpy(&cache->valid_hooks, child->data, sizeof(cache->valid_hooks));

    if (!(child = bf_marsh_next_child(marsh, child)))
        return -EINVAL;
    memcpy(&cache->hook_entry, child->data, sizeof(cache->hook_entry));

    if (!(child = bf_marsh_next_child(marsh, child)))
        return -EINVAL;
    memcpy(&cache->underflow, child->data, sizeof(cache->underflow));

    if (!(child = bf_marsh_next_child(marsh, child)))
        return -EINVAL;
    memcpy(&cache->num_entries, child->data, sizeof(cache->num_entries));

    if (!(child = bf_marsh_next_child(marsh, child)))
        return -EINVAL;
    memcpy(&cache->size, child->data, sizeof(cache->size));

    if (!(child = bf_marsh_next_child(marsh, child)))
        return -EINVAL;
    cache->entries = bf_memdup(child->data, child->data_len);
    if (!cache->entries)
        return -ENOMEM;

    if (bf_marsh_next_child(marsh, child))
        bf_warn("codegen marsh has more children than expected");

    _cache = TAKE_PTR(cache);

    bf_dbg("Restored bf_ipt_cache at %p:", _cache);
    bf_dbg("  valid_hooks: %u", _cache->valid_hooks);
    bf_dbg("  num_entries: %u", _cache->num_entries);
    bf_dbg("  size: %u", _cache->size);

    return 0;
}
