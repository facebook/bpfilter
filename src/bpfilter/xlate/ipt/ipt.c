/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2022 Meta Platforms, Inc. and affiliates.
 */

#include <linux/in.h>
#include <linux/netfilter.h>
#include <linux/netfilter/x_tables.h>
#include <linux/netfilter_ipv4/ip_tables.h>

#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "bpfilter/cgen/cgen.h"
#include "bpfilter/cgen/program.h"
#include "bpfilter/ctx.h"
#include "bpfilter/xlate/front.h"
#include "bpfilter/xlate/ipt/dump.h"
#include "bpfilter/xlate/ipt/helpers.h"
#include "core/chain.h"
#include "core/counter.h"
#include "core/dump.h"
#include "core/front.h"
#include "core/helper.h"
#include "core/hook.h"
#include "core/list.h"
#include "core/logger.h"
#include "core/marsh.h"
#include "core/matcher.h"
#include "core/opts.h"
#include "core/request.h"
#include "core/response.h"
#include "core/rule.h"
#include "core/verdict.h"

/**
 * @file ipt.c
 *
 * @c iptables front-end for @c bpfilter .
 *
 * This front-end provides support for @c iptables command to @c bpfilter .
 *
 * @c iptables requires the @c INPUT , @c FORWARD , and @c OUTPUT chains to
 * be defined with the @c ACCEPT policy by default, which mean they have no
 * effect except counting the packets. @c bpfilter doesn't define those chains
 * by default, even with this front-end enabled. Instead, it emulates then if
 * they are not defined when @c iptables request the ruleset.
 * See @ref _bf_ipt_gen_get_ruleset .
 *
 * Before running the requests command, @c iptables will send two requests to
 * @c bpfilter to populate a local cache:
 * - @c IPT_SO_GET_INFO : fetch the ruleset size, enabled hooks, number of
 *   rules, and offset of the rules.
 * - @c IPT_SO_GET_ENTRIES : same information as @c IPT_SO_GET_INFO plus the
 *   ruleset.
 * @c iptables always sends the whole ruleset to @c bpfilter , even if only a
 * single rule has changed.
 *
 * @c bpfilter will generate the ruleset in @c iptables format on demand, as
 * long as the rules have been defined by @c iptables previously. @c iptables
 * ruleset is defined as an @c ipt_replace structure with the following fields:
 * - @c name : name of the table, only "filter" is supported.
 * - @c valid_hooks : flags of the enabled hooks (hooks with a ruleset defined).
 * - @c num_entries : number of @c ipt_entry in the structure (hanging off the
 *   end in a flexible array member).
 * - @c size : total size of the @c ipt_entry structures.
 * - @c hook_entry : offset of each chain's first @c ipt_entry starting from
 *   @c ipt_replace.entries .
 * - @c underflow : offset of each chain's policy @c ipt_entry starting from
 *   @c ipt_replace.entries .
 * - @c num_counters : identical to @c ipt_replace.num_entries .
 * - @c counters : unused.
 * - @c entries : flexible array member of @c ipt_entry for the chains.
 *
 * The @ref bf_rule of each chain are translated into @c ipt_entry structures.
 * This structure is documented in the Linux kernel sources. All the
 * @c ipt_entry structures defined for @ref bf_rule will have the same size
 * because none of them will contain any matcher ( @c iptables matchers are not
 * supported by @c bpfilter ), however after each @c ipt_entry is located an
 * @c ipt_entry_target to define the rule's verdict. @c ipt_entry_target have
 * different sizes depending on the exact type of target (verdict, jump, ...):
 * @c bpfilter only supports verdict ( @c ipt_standard_target ).
 *
 * Then, a last @c ipt_entry is added for the error target, which is expected
 * by @c iptables .
 */

/**
 * Get size of an ipt_replace structure.
 *
 * @param ipt_replace_ptr Pointer to a valid ipt_replace structure.
 * @return Size of the structure, including variable length entries field.
 */
#define bf_ipt_replace_size(ipt_replace_ptr)                                   \
    (sizeof(struct ipt_replace) + (ipt_replace_ptr)->size)

/**
 * Convert an iptables target to a bpfilter verdict.
 *
 * Only the NF_ACCEPT and NF_DROP standard target are supported, other targets
 * and user-defined chains jumps will be rejected.
 *
 * @param ipt_tgt @c iptables target to convert.
 * @param verdict @c bpfilter verdict, corresponding to @p ipt_tgt .
 * @return 0 on success, or na egative errno value on error.
 */
static int _bf_ipt_target_to_verdict(struct ipt_entry_target *ipt_tgt,
                                     enum bf_verdict *verdict)
{
    bf_assert(ipt_tgt && verdict);

    if (bf_streq("", ipt_tgt->u.user.name)) {
        struct ipt_standard_target *std_tgt =
            (struct xt_standard_target *)ipt_tgt;

        if (std_tgt->verdict >= 0) {
            return bf_err_r(
                -ENOTSUP,
                "iptables user-defined chains are not supported, rejecting target");
        }

        switch (-std_tgt->verdict - 1) {
        case NF_ACCEPT:
            *verdict = BF_VERDICT_ACCEPT;
            break;
        case NF_DROP:
            *verdict = BF_VERDICT_DROP;
            break;
        default:
            return bf_err_r(-ENOTSUP, "unsupported iptables verdict: %d",
                            std_tgt->verdict);
        }
    } else {
        return bf_err_r(-ENOTSUP, "unsupported iptables target '%s', rejecting",
                        ipt_tgt->u.user.name);
    }

    return 0;
}

static int _bf_verdict_to_ipt_target(enum bf_verdict verdict,
                                     struct ipt_entry_target *ipt_tgt)
{
    struct ipt_standard_target *std_tgt = (struct xt_standard_target *)ipt_tgt;

    bf_assert(ipt_tgt);

    bf_info("target for verdict %d", verdict);
    switch (verdict) {
    case BF_VERDICT_ACCEPT:
        std_tgt->verdict = -2;
        break;
    case BF_VERDICT_DROP:
        std_tgt->verdict = -1;
        break;
    default:
        return bf_err_r(-ENOTSUP, "unsupported verdict %d", verdict);
    }

    ipt_tgt->u.target_size = sizeof(*std_tgt);

    return 0;
}

/**
 * Translate an @c iptables rule into a @c bpfilter rule.
 *
 * @param entry @c iptables rule. Can't be NULL.
 * @param rule @c bpfilter rule. Can't be NULL. On success, points to a
 *        valid rule.
 * @return 0 on success, or a negative errno value on error.
 */
static int _bf_ipt_entry_to_rule(const struct ipt_entry *entry,
                                 struct bf_rule **rule)
{
    _cleanup_bf_rule_ struct bf_rule *_rule = NULL;
    int r;

    bf_assert(entry && rule);

    if (sizeof(*entry) < entry->target_offset)
        return bf_err_r(-ENOTSUP, "iptables modules are not supported");

    r = bf_rule_new(&_rule);
    if (r)
        return r;

    if (entry->ip.iniface[0] != '\0' || entry->ip.outiface[0] != '\0') {
        return bf_err_r(
            -ENOTSUP,
            "filtering on input/output interface with iptables is not supported");
    }

    // iptables always has counters enabled
    _rule->counters = true;

    // Match on source IPv4 address
    if (entry->ip.src.s_addr || entry->ip.smsk.s_addr) {
        struct bf_matcher_ip4_addr addr = {
            .addr = entry->ip.src.s_addr,
            .mask = entry->ip.smsk.s_addr,
        };

        r = bf_rule_add_matcher(
            _rule, BF_MATCHER_IP4_SRC_ADDR,
            entry->ip.invflags & IPT_INV_SRCIP ? BF_MATCHER_NE : BF_MATCHER_EQ,
            &addr, sizeof(addr));
        if (r)
            return r;
    }

    // Match on destination IPv4 address
    if (entry->ip.dst.s_addr || entry->ip.dmsk.s_addr) {
        struct bf_matcher_ip4_addr addr = {
            .addr = entry->ip.dst.s_addr,
            .mask = entry->ip.dmsk.s_addr,
        };

        r = bf_rule_add_matcher(
            _rule, BF_MATCHER_IP4_DST_ADDR,
            entry->ip.invflags & IPT_INV_DSTIP ? BF_MATCHER_NE : BF_MATCHER_EQ,
            &addr, sizeof(addr));
        if (r)
            return r;
    }

    /* Match on the protocol field of the IPv4 packet (and not the L4 protocol,
     * as this implies L3 is IPv4). */
    if (entry->ip.proto) {
        uint8_t proto = entry->ip.proto;

        // Ensure we didn't cast away data, as we should not
        if (proto != entry->ip.proto) {
            return bf_err_r(
                -EINVAL,
                "protocol '%d' is an invalid protocol for IPv4's protocol field",
                entry->ip.proto);
        }

        r = bf_rule_add_matcher(_rule, BF_MATCHER_IP4_PROTO, BF_MATCHER_EQ,
                                &proto, sizeof(proto));
        if (r)
            return r;
    }

    r = _bf_ipt_target_to_verdict(ipt_get_target(entry), &_rule->verdict);
    if (r)
        return r;

    *rule = TAKE_PTR(_rule);

    return 0;
}

/**
 * Translates a @ref bf_rule object into an @c ipt_entry .
 *
 * @param rule @ref bf_rule to translate. Can't be NULL.
 * @param entry @c ipt_entry created from the @ref bf_rule . Can't be NULL.
 * @return 0 on success, or a negative errno value on error.
 */
static int _bf_rule_to_ipt_entry(const struct bf_rule *rule,
                                 struct ipt_entry *entry)
{
    struct bf_matcher_ip4_addr *addr;

    bf_assert(entry && rule);

    bf_list_foreach (&rule->matchers, matcher_node) {
        struct bf_matcher *matcher = bf_list_node_get_data(matcher_node);

        switch (matcher->type) {
        case BF_MATCHER_IP4_SRC_ADDR:
            if (matcher->op == BF_MATCHER_NE)
                entry->ip.invflags |= IPT_INV_SRCIP;
            addr = (void *)&matcher->payload;
            entry->ip.src.s_addr = addr->addr;
            entry->ip.smsk.s_addr = addr->mask;
            break;
        case BF_MATCHER_IP4_DST_ADDR:
            if (matcher->op == BF_MATCHER_NE)
                entry->ip.invflags |= IPT_INV_DSTIP;
            addr = (void *)&matcher->payload;
            entry->ip.dst.s_addr = addr->addr;
            entry->ip.dmsk.s_addr = addr->mask;
            break;
        case BF_MATCHER_IP4_PROTO:
            entry->ip.proto = *(uint8_t *)&matcher->payload;
            break;
        default:
            return bf_err_r(-ENOTSUP, "unsupported matcher %s for BF_FRONT_IPT",
                            bf_matcher_type_to_str(matcher->type));
        }
    }

    return _bf_verdict_to_ipt_target(rule->verdict, ipt_get_target(entry));
}

static int _bf_ipt_entries_to_chain(struct bf_chain **chain, int ipt_hook,
                                    struct ipt_entry *first,
                                    struct ipt_entry *last)
{
    _cleanup_bf_chain_ struct bf_chain *_chain = NULL;
    enum bf_verdict policy;
    int r;

    bf_assert(chain && first && last);

    // The last rule of the chain is the policy.
    r = _bf_ipt_target_to_verdict(ipt_get_target(last), &policy);
    if (r)
        return r;

    r = bf_chain_new(&_chain, bf_nf_hook_to_hook(ipt_hook), policy, NULL,
                     NULL);
    if (r)
        return r;

    _chain->hook_opts.used_opts = 1 << BF_HOOK_OPT_ATTACH;
    _chain->hook_opts.attach = true;

    while (first < last) {
        _cleanup_bf_rule_ struct bf_rule *rule = NULL;

        r = _bf_ipt_entry_to_rule(first, &rule);
        if (r)
            return bf_err_r(r, "failed to create rule from ipt_entry");

        r = bf_chain_add_rule(_chain, rule);
        if (r)
            return r;

        TAKE_PTR(rule);
        first = ipt_get_next_rule(first);
    }

    *chain = TAKE_PTR(_chain);

    return 0;
}

struct bf_ipt_gen_ruleset_entry
{
    struct bf_cgen *cgen;
    struct bf_chain *chain;
};

/**
 * Get the list of chains and codegens for @c BF_FRONT_IPT .
 *
 * @param ruleset Array of size @c NF_INET_NUMHOOKS to be filled with the
 *        codegen and chain for every hook (if defined). Mandatory chains will
 *        be allocated and their pointer added to this array if they are
 *        not yet defined. Can't be NULL.
 * @param nrules On success, contain the total number of rules associated with
 *        the @c BF_FRONT_IPT front-end. This is the number of rules from
 *        iptables' perspective: each chain has an extra rule for the policy.
 *        Can't be NULL.
 * @param dummy_chains On success, this list will contain pointers to the
 *        mandatory chains created to comply with iptables' behaviour. The
 *        caller will own this list and the pointers contained in it. Can't
 *        be NULL.
 * @return 0 on success, or a negative errno value on failure.
 */
static int _bf_ipt_gen_get_ruleset(struct bf_ipt_gen_ruleset_entry *ruleset,
                                   size_t *nrules, bf_list *dummy_chains)
{
    _clean_bf_list_ bf_list cgens;
    size_t _nrules = 0;
    int r;

    bf_assert(ruleset);

    r = bf_ctx_get_cgens_for_front(&cgens, BF_FRONT_IPT);
    if (r)
        return bf_err_r(r, "failed to collect codegens for BF_FRONT_IPT");

    bf_list_foreach (&cgens, cgen_node) {
        struct bf_cgen *cgen = bf_list_node_get_data(cgen_node);

        ruleset[bf_hook_to_nf_hook(cgen->chain->hook)].cgen = cgen;
        ruleset[bf_hook_to_nf_hook(cgen->chain->hook)].chain = cgen->chain;

        /* Add the number of rules of the chain to the total number of rules,
         * don't forget about the chain's policy, which is a rule from
         * iptables' point of view. */
        _nrules += bf_list_size(&cgen->chain->rules) + 1;
    }

    /* iptables requires at least the INPUT, FORWARD, and OUTPUT chains. If
     * those chains are not defined, we created dummy ones just to fill the
     * ipt_replace structure. */
    for (enum nf_inet_hooks hook = NF_INET_LOCAL_IN; hook <= NF_INET_LOCAL_OUT;
         ++hook) {
        _cleanup_bf_chain_ struct bf_chain *chain = NULL;

        if (ruleset[hook].cgen)
            continue;

        r = bf_chain_new(&chain, bf_nf_hook_to_hook(hook), BF_VERDICT_ACCEPT,
                         NULL, NULL);
        if (r)
            return bf_err_r(r,
                            "failed to create a dummy chain for BF_FRONT_IPT");

        r = bf_list_add_tail(dummy_chains, chain);
        if (r)
            return bf_err_r(r,
                            "failed to add BF_FRONT_IPT dummy chain to list");

        ruleset[hook].chain = TAKE_PTR(chain);

        // The dummy chains only contain the chain policy
        ++_nrules;
    }

    *nrules = _nrules;

    return 0;
}

/**
 * Generate the @c ipt_replace structure for the current ruleset.
 *
 * @param replace @c ipt_replace structure to allocate and fill. Can't be NULL.
 * @param with_counters If true, the rule counters in @p replace will be filled
 *        with the correct values. Otherwise, the counters will default to 0.
 * @return 0 on success, or a negative errno value on failure.
 */
static int _bf_ipt_gen_ipt_replace(struct ipt_replace **replace,
                                   bool with_counters)
{
    _cleanup_free_ struct ipt_replace *_replace = NULL;
    _clean_bf_list_ bf_list dummy_chains = bf_list_default(bf_chain_free, NULL);
    struct bf_ipt_gen_ruleset_entry ruleset[NF_INET_NUMHOOKS] = {};
    struct ipt_entry *entry;
    size_t next_chain_off = 0;
    size_t nrules;
    size_t rule_size =
        sizeof(struct ipt_entry) + sizeof(struct xt_standard_target);
    size_t err_size = sizeof(struct ipt_entry) + sizeof(struct xt_error_target);
    struct xt_error_target *err_tgt;
    int r;

    bf_assert(replace);

    r = _bf_ipt_gen_get_ruleset(ruleset, &nrules, &dummy_chains);
    if (r)
        return bf_err_r(r, "failed to collect the BF_FRONT_IPT ruleset");

    _replace = calloc(1, sizeof(*_replace) + (nrules * rule_size) + err_size);
    if (!_replace)
        return -ENOMEM;

    // Total number of rules, chain policies, and error entry
    _replace->num_entries = nrules + 1;
    _replace->num_counters = nrules + 1;
    _replace->size = nrules * rule_size + err_size;

    entry = (struct ipt_entry *)(_replace + 1);
    strncpy(_replace->name, "filter", XT_TABLE_MAXNAMELEN);

    for (int hook = 0; hook < NF_INET_NUMHOOKS; ++hook) {
        struct bf_chain *chain = ruleset[hook].chain;
        struct bf_cgen *cgen = ruleset[hook].cgen;

        if (!chain)
            continue;

        /* Rules (struct ipt_entry) always have the same size:
         *   sizeof(ipt_entry) + sizeof(ipt_standard_target)
         * Matchers and user-defined chains are not supported. */

        _replace->valid_hooks |= 1 << hook;
        _replace->hook_entry[hook] = next_chain_off;
        _replace->underflow[hook] =
            next_chain_off + bf_list_size(&chain->rules) * rule_size;

        bf_list_foreach (&chain->rules, rule_node) {
            struct bf_rule *rule = bf_list_node_get_data(rule_node);

            entry->target_offset = sizeof(struct ipt_entry);
            entry->next_offset = rule_size;

            r = _bf_rule_to_ipt_entry(rule, entry);
            if (r) {
                return bf_err_r(r,
                                "failed to translate bf_rule into ipt_entry");
            }

            if (with_counters && cgen) {
                struct bf_counter counters;

                r = bf_cgen_get_counter(cgen, rule->index, &counters);
                if (r) {
                    return bf_err_r(r,
                                    "failed to get counters for iptables rule");
                }

                entry->counters.bcnt = counters.bytes;
                entry->counters.pcnt = counters.packets;
            }

            entry = (void *)entry + rule_size;
        }

        // Fill the ipt_entry for the chain policy
        if (with_counters && cgen) {
            struct bf_counter counters;

            r = bf_cgen_get_counter(cgen, BF_COUNTER_POLICY, &counters);
            if (r) {
                return bf_err_r(
                    r, "failed to get policy counters for iptables chain");
            }

            entry->counters.bcnt = counters.bytes;
            entry->counters.pcnt = counters.packets;
        }

        entry->target_offset = sizeof(struct ipt_entry);
        entry->next_offset = rule_size;

        r = _bf_verdict_to_ipt_target(chain->policy, ipt_get_target(entry));
        if (r) {
            return bf_err_r(
                r, "failed to convert chain policy to iptables verdict");
        }

        entry = (void *)entry + rule_size;
        next_chain_off += (bf_list_size(&chain->rules) + 1) * rule_size;
    }

    // There is one last entry after the chains for the error target.
    entry->target_offset = sizeof(struct ipt_entry);
    entry->next_offset = err_size;

    err_tgt = (struct xt_error_target *)(entry + 1);
    strcpy(err_tgt->errorname, "ERROR");
    err_tgt->target.u.target_size = sizeof(struct xt_error_target);
    err_tgt->target.u.user.target_size = sizeof(struct xt_error_target);
    strcpy(err_tgt->target.u.user.name, "ERROR");

    *replace = TAKE_PTR(_replace);

    bf_ipt_dump_replace(*replace, EMPTY_PREFIX);

    return 0;
}

/**
 * Translate iptables rules into bpfilter format.
 *
 * @param ipt iptables rules.
 * @param chains Array of chains. The array is big enough to fit one chain per
 *        hook. Can't be NULL.
 * @return 0 on success, negative error code on failure.
 */
static int
_bf_ipt_xlate_ruleset_set(struct ipt_replace *ipt,
                          struct bf_chain *(*chains)[NF_INET_NUMHOOKS])
{
    int r;

    bf_assert(ipt && chains);

    for (int i = 0; i < NF_INET_NUMHOOKS; ++i) {
        _cleanup_bf_chain_ struct bf_chain *chain = NULL;

        if (!ipt_is_hook_enabled(ipt, i)) {
            bf_dbg("iptables hook %d is not enabled, skipping", i);
            continue;
        }

        r = _bf_ipt_entries_to_chain(&chain, i, ipt_get_first_rule(ipt, i),
                                     ipt_get_last_rule(ipt, i));
        if (r) {
            return bf_err_r(r, "failed to create chain for iptables hook %d",
                            i);
        }

        (*chains)[i] = TAKE_PTR(chain);
    }

    return 0;
}

/**
 * Modify existing iptables rules.
 *
 * @todo If processing for any codegen fails, all codegens should be unloaded
 * and/or discarded.
 *
 * @param replace New rules, in iptables format.
 * @param len Length of the new rules.
 * @return 0 on success, negative error code on failure.
 */
static int _bf_ipt_ruleset_set(struct ipt_replace *replace, size_t len)
{
    _cleanup_free_ struct ipt_entry *entries = NULL;
    struct bf_chain *chains[NF_INET_NUMHOOKS] = {};
    int r;

    bf_assert(replace);
    bf_assert(bf_ipt_replace_size(replace) == len);

    if (bf_opts_is_verbose(BF_VERBOSE_DEBUG))
        bf_ipt_dump_replace(replace, EMPTY_PREFIX);

    r = _bf_ipt_xlate_ruleset_set(replace, &chains);
    if (r)
        return bf_err_r(r, "failed to translate iptables ruleset");

    /* Copy entries now, so we don't have to unload the programs if the copy
     * fails later. */
    entries = bf_memdup(replace->entries, replace->size);
    if (!entries)
        return bf_err_r(-ENOMEM, "failed to duplicate iptables ruleset");

    for (int i = 0; i < NF_INET_NUMHOOKS; i++) {
        _cleanup_bf_cgen_ struct bf_cgen *cgen = NULL;
        _cleanup_bf_chain_ struct bf_chain *chain = TAKE_PTR(chains[i]);

        if (!chain)
            continue;

        cgen = bf_ctx_get_cgen(chain->hook, &chain->hook_opts);
        if (!cgen) {
            r = bf_cgen_new(&cgen, BF_FRONT_IPT, &chain);
            if (r)
                return r;

            r = bf_cgen_up(cgen);
            if (r) {
                bf_err(
                    "failed to generate and load program for iptables hook %d, skipping",
                    i);
                continue;
            }

            r = bf_ctx_set_cgen(cgen);
            if (r) {
                bf_err_r(
                    r, "failed to store codegen for iptables hook %d, skipping",
                    i);
                continue;
            }

            TAKE_PTR(cgen);
        } else {
            r = bf_cgen_update(cgen, &chain);
            if (r) {
                TAKE_PTR(cgen);
                bf_err_r(
                    r,
                    "failed to update codegen for iptables hook %d, skipping",
                    i);
                continue;
            }
            TAKE_PTR(cgen);
        }
    }

    return r;
}

/**
 * Set counters for a rule.
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
    bf_assert(counters);

    UNUSED(len);

    return 0;
}

int _bf_ipt_get_info_handler(struct bf_request *request,
                             struct bf_response **response)
{
    _cleanup_free_ struct ipt_replace *replace = NULL;
    struct ipt_getinfo *info = (struct ipt_getinfo *)request->data;
    int r;

    bf_assert(request);
    bf_assert(sizeof(*info) == request->data_len);

    if (!bf_streq(info->name, "filter")) {
        return bf_err_r(-EINVAL, "can't process IPT_SO_GET_INFO for table %s",
                        info->name);
    }

    r = _bf_ipt_gen_ipt_replace(&replace, false);
    if (r)
        return r;

    info->valid_hooks = replace->valid_hooks;
    memcpy(info->hook_entry, replace->hook_entry, sizeof(replace->hook_entry));
    memcpy(info->underflow, replace->underflow, sizeof(replace->underflow));
    info->num_entries = replace->num_entries;
    info->size = replace->size;

    return bf_response_new_success(response, (const char *)info,
                                   sizeof(struct ipt_getinfo));
}

/**
 * Get the entries of a table, including counters.
 *
 * @param request
 * @param response
 * @return 0 on success, negative errno value on failure.
 */
int _bf_ipt_get_entries_handler(struct bf_request *request,
                                struct bf_response **response)
{
    _cleanup_free_ struct ipt_replace *replace = NULL;
    struct ipt_get_entries *entries;
    int r;

    bf_assert(request);
    bf_assert(response);

    entries = (struct ipt_get_entries *)request->data;

    if (!bf_streq(entries->name, "filter")) {
        return bf_err_r(-EINVAL, "can't process IPT_SO_GET_INFO for table %s",
                        entries->name);
    }

    r = _bf_ipt_gen_ipt_replace(&replace, true);
    if (r)
        return r;

    if (entries->size != replace->size) {
        return bf_err_r(
            -EINVAL,
            "not enough space to store entries: %u available, %u required",
            entries->size, replace->size);
    }

    memcpy(entries->entrytable, replace->entries, replace->size);

    return bf_response_new_success(response, (const char *)entries,
                                   sizeof(*entries) + entries->size);
}

static int _bf_ipt_setup(void)
{
    return 0;
}

static int _bf_ipt_teardown(void)
{
    return 0;
}

/**
 * @todo Wouldn't it be better to have a separate handler for each request type?
 *  In which case struct bf_front_ops would contain a handler for each request
 *  type, and the front would handle custom (BF_REQ_CUSTOM) requests itself.
 * @todo Document that request and responses are not const: they will be free
 *  by the daemon once the front is done with them. Hence, the front is free
 *  to modify the requests content.
 * @todo Check bf_assertions: a malformed request could cause the daemon to
 * crash.
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
    case BF_REQ_RULES_SET:
        r = _bf_ipt_ruleset_set((struct ipt_replace *)request->data,
                                request->data_len);
        if (r < 0)
            return r;

        return bf_response_new_success(response, request->data,
                                       request->data_len);
    case BF_REQ_COUNTERS_SET:
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
            return bf_warn_r(-ENOTSUP,
                             "unsupported custom ipt request type: %d",
                             request->ipt_cmd);
        };
    default:
        return bf_warn_r(-ENOTSUP, "unsupported ipt request type: %d",
                         request->cmd);
    };

    return 0;
}

static int _bf_ipt_marsh(struct bf_marsh **marsh)
{
    UNUSED(marsh);

    return 0;
}

static int _bf_ipt_unmarsh(struct bf_marsh *marsh)
{
    UNUSED(marsh);

    return 0;
}

const struct bf_front_ops ipt_front = {
    .setup = _bf_ipt_setup,
    .teardown = _bf_ipt_teardown,
    .request_handler = _bf_ipt_request_handler,
    .marsh = _bf_ipt_marsh,
    .unmarsh = _bf_ipt_unmarsh,
};
