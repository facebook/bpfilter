/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#include "harness/filter.h"

#include <regex.h>
#include <stdio.h>

#include "core/helper.h"

static void _bf_test_filter_regex_free(regex_t **regex)
{
    bf_assert(regex);

    if (!*regex)
        return;

    regfree(*regex);
    free(*regex);
    *regex = NULL;
}

int bf_test_filter_new(struct bf_test_filter **filter)
{
    bf_assert(filter);

    *filter = malloc(sizeof(struct bf_test_filter));
    if (!*filter)
        return -ENOMEM;

    bf_list_init(&(*filter)->patterns,
                 (bf_list_ops[]) {
                     {.free = (bf_list_ops_free)_bf_test_filter_regex_free}});

    return 0;
}

void bf_test_filter_free(struct bf_test_filter **filter)
{
    bf_assert(filter);

    if (!*filter)
        return;

    bf_list_clean(&(*filter)->patterns);
    free(*filter);
    *filter = NULL;
}

int bf_test_filter_add_pattern(struct bf_test_filter *filter,
                               const char *pattern)
{
    regex_t *regex;
    char errbuf[128];
    int r;

    regex = malloc(sizeof(*regex));
    if (!regex)
        return -ENOMEM;

    r = regcomp(regex, pattern, 0);
    if (r) {
        regerror(r, regex, errbuf, sizeof(errbuf));
        fprintf(stderr, "failed to compile regex '%s': %s\n", pattern, errbuf);
        free(regex);
        return -EINVAL;
    }

    r = bf_list_add_tail(&filter->patterns, regex);
    if (r) {
        regfree(regex);
        free(regex);
        return r;
    }

    return 0;
}

bool bf_test_filter_matches(struct bf_test_filter *filter, const char *str)
{
    char errbuf[128];
    int r;

    bf_assert(filter);

    // If the patterns list is empty: everything is allowed
    if (bf_list_is_empty(&filter->patterns))
        return true;

    bf_list_foreach (&filter->patterns, pattern_node) {
        regex_t *regex = bf_list_node_get_data(pattern_node);

        r = regexec(regex, str, 0, NULL, 0);
        if (r != REG_NOMATCH) {
            // If we match, return true.
            // If an error is returned (which is not REG_NOMATCH), log it and
            // assume the pattern matched.
            if (r) {
                regerror(r, regex, errbuf, sizeof(errbuf));
                fprintf(
                    stderr,
                    "failed to match '%s' against a regex, assuming pattern is allowed: %s\n",
                    str, errbuf);
            }
            return true;
        }
    }

    return false;
}
