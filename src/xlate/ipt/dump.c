/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2022 Meta Platforms, Inc. and affiliates.
 */

#include "dump.h"

#include <linux/netfilter.h>
#include <linux/netfilter/x_tables.h>
#include <linux/netfilter_ipv4/ip_tables.h>
#include <stdint.h>
#include <stdio.h>

#include "core/dump.h"
#include "core/string.h"
#include "core/target.h"
#include "helpers.h"

/**
 * @brief Map each hook to its name as a string.
 */
static const char *hook_name[] = {
        [NF_INET_PRE_ROUTING] = "PRE_ROUTING",
        [NF_INET_LOCAL_IN] = "LOCAL_IN",
        [NF_INET_FORWARD] = "FORWARD",
        [NF_INET_LOCAL_OUT] = "LOCAL_OUT",
        [NF_INET_POST_ROUTING] = "POST_ROUTING",
};

/**
 * @brief Map each target to its name as a string.
 */
static const char *target_name[] = {
        [NF_DROP] = "DROP",
        [NF_ACCEPT] = "ACCEPT",
        [NF_STOLEN] = "STOLEN",
        [NF_QUEUE] = "QUEUE",
        [NF_REPEAT] = "REPEAT",
        [NF_STOP] = "STOP",
};

/**
 * @brief  Dump content of @p ipt_counters structure.
 *
 * @param counters @p ipt_counters structure. Must be non-NULL.
 * @param p @p log_prefix structure.
 */
static inline void ipt_dump_counters(const struct ipt_counters *counters, char *p)
{
        DUMP_P(p, "struct ipt_counters at %p\n", counters);
}

/**
 * @brief Dump content of @p ipt_ip structure.
 *
 * @param ip @p ipt_ip structure. Must be non-NULL.
 * @param p @p log_prefix structure.
 */
static void ipt_dump_ip(const struct ipt_ip *ip, char *p)
{
        DUMP_P(p, "struct ipt_ip at %p\n", ip);

        bf_dump_prefix_push(p);
        DUMP_P(p, "src: %d.%d.%d.%d\n", IP4_SPLIT(ip->src));
        DUMP_P(p, "dst: %d.%d.%d.%d\n", IP4_SPLIT(ip->dst));
        DUMP_P(p, "src_mask: %d.%d.%d.%d\n", IP4_SPLIT(ip->smsk));
        DUMP_P(p, "dst_mask: %d.%d.%d.%d\n", IP4_SPLIT(ip->dmsk));
        DUMP_P(p, "in_iface: %s\n", ip->iniface);
        DUMP_P(p, "out_iface: %s\n", ip->outiface);
        DUMP_P(p, "in_iface_mask: %s\n", ip->iniface_mask);
        DUMP_P(p, "out_iface_mask: %s\n", ip->outiface_mask);
        DUMP_P(p, "protocol: %d\n", ip->proto);
        DUMP_P(p, "flags: %d\n", ip->flags);
        DUMP_P(bf_dump_prefix_last(p), "invflags: %d\n", ip->invflags);
        bf_dump_prefix_pop(p);
}

/**
 * @brief Dump content of @p ipt_entry_match structure.
 *
 * @param match @p ipt_entry_match structure. Must be non-NULL.
 * @param p @p log_prefix structure.
 */
static void ipt_dump_match(const struct ipt_entry_match *match, char *p)
{
        DUMP_P(p, "struct ipt_entry_match at %p\n", match);

        bf_dump_prefix_push(p);
        DUMP_P(p, "user:\n");
        DUMP_P(p, "match_size: %d\n", match->u.user.match_size);
        DUMP_P(p, "name: %s\n", match->u.user.name);
        DUMP_P(p, "revision: %d\n", match->u.user.revision);
        DUMP_P(p, "kernel:\n");
        DUMP_P(p, "match_size: %d\n", match->u.kernel.match_size);
        DUMP_P(p, "match at %p\n", match->u.kernel.match);
        DUMP_P(bf_dump_prefix_last(p), "match_size: %d\n", match->u.match_size);
        bf_dump_prefix_pop(p);
}

/**
 * @brief Dump content of @p ipt_entry_target structure.
 *
 * @param target @p ipt_entry_target structure. Must be non-NULL.
 * @param p @p log_prefix structure.
 */
static void ipt_dump_target(const struct ipt_entry_target *target, char *p)
{
        bool is_standard;
        struct ipt_standard_target *std_target = (void *)target;

        is_standard = streq(target->u.user.name, "");

        DUMP_P(p, "struct ipt_entry_target at %p\n", target);

        bf_dump_prefix_push(p);
        DUMP_P(p, "user:\n");

        bf_dump_prefix_push(p);
        DUMP_P(p, "target_size: %d\n", target->u.user.target_size);
        DUMP_P(p, "name: '%s'\n", target->u.user.name);
        DUMP_P(bf_dump_prefix_last(p), "revision: %d\n", target->u.user.revision);
        bf_dump_prefix_pop(p);

        DUMP_P(p, "kernel:\n");

        bf_dump_prefix_push(p);
        DUMP_P(p, "target_size: %d\n", target->u.kernel.target_size);
        DUMP_P(bf_dump_prefix_last(p), "target: %p\n", target->u.kernel.target);
        bf_dump_prefix_pop(p);

        DUMP_P((is_standard ? p : bf_dump_prefix_last(p)), "target_size: %d\n", target->u.target_size);
        if (is_standard)
                DUMP_P(bf_dump_prefix_last(p), "verdict: %s\n", target_name[convert_verdict(std_target->verdict)]);

        bf_dump_prefix_pop(p);
}

void bf_ipt_dump_replace(struct ipt_replace *ipt)
{
        int i;
        uint32_t offset;
        char p[DUMP_PREFIX_LEN] = {};
        struct ipt_entry *first_rule;
        struct ipt_entry *last_rule;

        DUMP_P(p, "struct ipt_replace at %p\n", ipt);

        bf_dump_prefix_push(p);

        DUMP_P(p, "name: '%s'\n", ipt->name);
        DUMP_P(p, "valid_hooks: " BIN_FMT "\n", BIN_SPLIT(ipt->valid_hooks));
        DUMP_P(p, "num_entries: %d\n", ipt->num_entries);
        DUMP_P(p, "size: %d\n", ipt->size);
        DUMP_P(bf_dump_prefix_last(p), "struct bpfilter_ipt_entry at %p\n", ipt->entries);

        bf_dump_prefix_push(p);

        // Loop over each hook to print its rules (if defined).
        for (i = 0; i < NF_INET_NUMHOOKS; ++i) {
                if (i == NF_INET_POST_ROUTING)
                        bf_dump_prefix_last(p);

                if (!ipt_is_hook_enabled(ipt, i)) {
                        DUMP_P(p, "%s: no rule defined\n", hook_name[i]);
                        continue;
                }

                DUMP_P(p, "%s (from %x to %x):\n", hook_name[i], ipt->hook_entry[i], ipt->underflow[i]);

                bf_dump_prefix_push(p);

                first_rule = ipt_get_first_rule(ipt, i);
                last_rule = ipt_get_last_rule(ipt, i);
                offset = sizeof(*first_rule);

                // Loop over the rules for the current hook.
                while (first_rule <= last_rule) {
                        DUMP_P((first_rule == last_rule ? bf_dump_prefix_last(p) : p), "struct bpfilter_ipt_entry at %p\n", first_rule);

                        bf_dump_prefix_push(p);

                        ipt_dump_ip(&first_rule->ip, p);

                        DUMP_P(p, "target_offset: %d\n", first_rule->target_offset);
                        DUMP_P(p, "next_offset: %d\n", first_rule->next_offset);
                        DUMP_P(p, "comefrom: %d\n", first_rule->comefrom);

                        ipt_dump_counters(&first_rule->counters, p);

                        // Loop over the matches for the current rule.
                        while (offset < first_rule->target_offset) {
                                ipt_dump_match(ipt_get_match(first_rule, offset), p);
                                offset += ipt_get_match(first_rule, offset)->u.match_size;
                        }

                        ipt_dump_target(ipt_get_target(first_rule), bf_dump_prefix_last(p));

                        bf_dump_prefix_pop(p);

                        if (!first_rule->next_offset)
                                break;

                        first_rule = ipt_get_next_rule(first_rule);
                }
                bf_dump_prefix_pop(p);
        }

        bf_dump_prefix_pop(p);
}
