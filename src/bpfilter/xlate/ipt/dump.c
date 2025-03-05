/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2022 Meta Platforms, Inc. and affiliates.
 */

#include "dump.h"

#include <linux/netfilter.h>
#include <linux/netfilter/x_tables.h>
#include <linux/netfilter_ipv4/ip_tables.h>

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

#include "bpfilter/xlate/ipt/helpers.h"
#include "core/dump.h"
#include "core/helper.h"

/**
 * Map each hook to its name as a string.
 */
static const char *hook_name[] = {
    [NF_INET_PRE_ROUTING] = "PRE_ROUTING",   [NF_INET_LOCAL_IN] = "LOCAL_IN",
    [NF_INET_FORWARD] = "FORWARD",           [NF_INET_LOCAL_OUT] = "LOCAL_OUT",
    [NF_INET_POST_ROUTING] = "POST_ROUTING",
};

/**
 * Map each target to its name as a string.
 */
static const char *target_name[] = {
    [NF_DROP] = "DROP",   [NF_ACCEPT] = "ACCEPT", [NF_STOLEN] = "STOLEN",
    [NF_QUEUE] = "QUEUE", [NF_REPEAT] = "REPEAT", [NF_STOP] = "STOP",
};

/**
 * Dump content of @p ipt_counters structure.
 *
 * @param counters @p ipt_counters structure. Must be non-NULL.
 * @param prefix @p log_prefix structure.
 */
static inline void ipt_dump_counters(const struct ipt_counters *counters,
                                     prefix_t *prefix)
{
    bf_assert(counters && prefix);

    DUMP(prefix, "struct ipt_counters at %p", counters);
}

/**
 * Dump content of @p ipt_ip structure.
 *
 * @param ip @p ipt_ip structure. Must be non-NULL.
 * @param prefix @p log_prefix structure.
 */
static void ipt_dump_ip(const struct ipt_ip *ip, prefix_t *prefix)
{
    bf_assert(ip && prefix);

    DUMP(prefix, "struct ipt_ip at %p", ip);

    bf_dump_prefix_push(prefix);
    DUMP(prefix, "src: " IP4_FMT, IP4_SPLIT(ip->src));
    DUMP(prefix, "dst: " IP4_FMT, IP4_SPLIT(ip->dst));
    DUMP(prefix, "src_mask: " IP4_FMT, IP4_SPLIT(ip->smsk));
    DUMP(prefix, "dst_mask: " IP4_FMT, IP4_SPLIT(ip->dmsk));
    DUMP(prefix, "in_iface: %s", ip->iniface);
    DUMP(prefix, "out_iface: %s", ip->outiface);
    DUMP(prefix, "in_iface_mask: %s", ip->iniface_mask);
    DUMP(prefix, "out_iface_mask: %s", ip->outiface_mask);
    DUMP(prefix, "protocol: %d", ip->proto);
    DUMP(prefix, "flags: %d", ip->flags);
    DUMP(bf_dump_prefix_last(prefix), "invflags: %d", ip->invflags);
    bf_dump_prefix_pop(prefix);
}

/**
 * Dump content of @p ipt_entry_match structure.
 *
 * @param match @p ipt_entry_match structure. Must be non-NULL.
 * @param prefix @p log_prefix structure.
 */
static void ipt_dump_match(const struct ipt_entry_match *match,
                           prefix_t *prefix)
{
    bf_assert(match && prefix);

    DUMP(prefix, "struct ipt_entry_match at %p", match);

    bf_dump_prefix_push(prefix);
    DUMP(prefix, "user:");
    DUMP(prefix, "match_size: %d", match->u.user.match_size);
    DUMP(prefix, "name: %s", match->u.user.name);
    DUMP(prefix, "revision: %d", match->u.user.revision);
    DUMP(prefix, "kernel:");
    DUMP(prefix, "match_size: %d", match->u.kernel.match_size);
    DUMP(prefix, "match at %p", match->u.kernel.match);
    DUMP(bf_dump_prefix_last(prefix), "match_size: %d", match->u.match_size);
    bf_dump_prefix_pop(prefix);
}

static inline int _bf_ipt_convert_verdict(int verdict)
{
    return -verdict - 1;
}

/**
 * Dump content of @p ipt_entry_target structure.
 *
 * @param target @p ipt_entry_target structure. Must be non-NULL.
 * @param prefix @p log_prefix structure.
 */
static void ipt_dump_target(const struct ipt_entry_target *target,
                            prefix_t *prefix)
{
    bool is_standard;
    struct ipt_standard_target *std_target = (void *)target;

    bf_assert(target && prefix);

    is_standard = bf_streq(target->u.user.name, "");

    DUMP(prefix, "struct ipt_entry_target at %p", target);

    bf_dump_prefix_push(prefix);
    DUMP(prefix, "user:");

    bf_dump_prefix_push(prefix);
    DUMP(prefix, "target_size: %d", target->u.user.target_size);
    DUMP(prefix, "name: '%s'", target->u.user.name);
    DUMP(bf_dump_prefix_last(prefix), "revision: %d", target->u.user.revision);
    bf_dump_prefix_pop(prefix);

    DUMP(prefix, "kernel:");

    bf_dump_prefix_push(prefix);
    DUMP(prefix, "target_size: %d", target->u.kernel.target_size);
    DUMP(bf_dump_prefix_last(prefix), "target: %p", target->u.kernel.target);
    bf_dump_prefix_pop(prefix);

    DUMP((is_standard ? prefix : bf_dump_prefix_last(prefix)),
         "target_size: %d", target->u.target_size);
    if (is_standard) {
        DUMP(bf_dump_prefix_last(prefix), "verdict: %s",
             target_name[_bf_ipt_convert_verdict(std_target->verdict)]);
    }

    bf_dump_prefix_pop(prefix);
}

void bf_ipt_dump_replace(struct ipt_replace *ipt, prefix_t *prefix)
{
    int i;
    uint32_t offset;
    struct ipt_entry *first_rule;
    struct ipt_entry *last_rule;

    bf_assert(ipt && prefix);

    DUMP(prefix, "struct ipt_replace at %p", ipt);

    bf_dump_prefix_push(prefix);

    DUMP(prefix, "name: '%s'", ipt->name);
    DUMP(prefix, "valid_hooks: " BIN_FMT "", BIN_SPLIT(ipt->valid_hooks));
    DUMP(prefix, "num_entries: %d", ipt->num_entries);
    DUMP(prefix, "size: %d", ipt->size);
    DUMP(bf_dump_prefix_last(prefix), "struct ipt_entry at %p", ipt->entries);

    bf_dump_prefix_push(prefix);

    // Loop over each hook to print its rules (if defined).
    for (i = 0; i < NF_INET_NUMHOOKS; ++i) {
        if (i == NF_INET_POST_ROUTING)
            bf_dump_prefix_last(prefix);

        if (!ipt_is_hook_enabled(ipt, i)) {
            DUMP(prefix, "%s: no rule defined", hook_name[i]);
            continue;
        }

        DUMP(prefix, "%s (from %x to %x):", hook_name[i], ipt->hook_entry[i],
             ipt->underflow[i]);

        bf_dump_prefix_push(prefix);

        first_rule = ipt_get_first_rule(ipt, i);
        last_rule = ipt_get_last_rule(ipt, i);
        offset = sizeof(*first_rule);

        // Loop over the rules for the current hook.
        while (first_rule <= last_rule) {
            if (first_rule == last_rule)
                bf_dump_prefix_last(prefix);

            DUMP(prefix, "struct ipt_entry at %p", first_rule);

            bf_dump_prefix_push(prefix);

            ipt_dump_ip(&first_rule->ip, prefix);

            DUMP(prefix, "target_offset: %d", first_rule->target_offset);
            DUMP(prefix, "next_offset: %d", first_rule->next_offset);
            DUMP(prefix, "comefrom: %d", first_rule->comefrom);

            ipt_dump_counters(&first_rule->counters, prefix);

            // Loop over the matches for the current rule.
            while (offset < first_rule->target_offset) {
                ipt_dump_match(ipt_get_match(first_rule, offset), prefix);
                offset += ipt_get_match(first_rule, offset)->u.match_size;
            }

            ipt_dump_target(ipt_get_target(first_rule),
                            bf_dump_prefix_last(prefix));

            bf_dump_prefix_pop(prefix);

            if (!first_rule->next_offset)
                break;

            first_rule = ipt_get_next_rule(first_rule);
        }
        bf_dump_prefix_pop(prefix);
    }

    bf_dump_prefix_pop(prefix);

    // Force flush, otherwise output on stderr might appear.
    (void)fflush(stdout);
}
