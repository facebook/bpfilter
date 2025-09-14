/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#include "test.h"

#include <errno.h>
#include <regex.h>
#include <stdlib.h>
#include <string.h>

#include "bpfilter/dump.h"
#include "bpfilter/helper.h"
#include "bpfilter/list.h"
#include "bpfilter/logger.h"

void bf_test_dump(const bf_test *test, prefix_t *prefix)
{
    bf_assert(test && prefix);

    DUMP(prefix, "bf_test at %p", test);
    bf_dump_prefix_push(prefix);
    DUMP(prefix, "group_name: %s", test->group_name);
    DUMP(prefix, "test_name: %s", test->test_name);
    DUMP(bf_dump_prefix_last(prefix), "cb: %p", test->cb);
    bf_dump_prefix_pop(prefix);
}

static void bf_noop_free(void **data)
{
    UNUSED(data);
}

int bf_test_group_new(bf_test_group **group, const char *name)
{
    _free_bf_test_group_ bf_test_group *_group = NULL;

    bf_assert(group && name);

    _group = calloc(1, sizeof(*_group));
    if (!_group)
        return -ENOMEM;

    _group->name = strdup(name);
    if (!_group->name)
        return -ENOMEM;

    bf_list_init(&_group->tests,
                 (bf_list_ops[]) {{.free = (bf_list_ops_free)bf_noop_free}});

    *group = TAKE_PTR(_group);

    return 0;
}

void bf_test_group_free(bf_test_group **group)
{
    bf_assert(group);

    if (!*group)
        return;

    freep((void *)&(*group)->name);
    freep((void *)&(*group)->cmtests);
    bf_list_clean(&(*group)->tests);
    freep((void *)group);
}

void bf_test_group_dump(const bf_test_group *group, prefix_t *prefix)
{
    bf_assert(group && prefix);

    DUMP(prefix, "bf_test_group at %p", group);
    bf_dump_prefix_push(prefix);
    DUMP(prefix, "name: %s", group->name);

    DUMP(prefix, "tests: bf_list<bf_test>[%lu]", bf_list_size(&group->tests));
    bf_dump_prefix_push(prefix);
    bf_list_foreach (&group->tests, test_node) {
        bf_test *test = bf_list_node_get_data(test_node);

        if (bf_list_is_tail(&group->tests, test_node))
            bf_dump_prefix_last(prefix);

        bf_test_dump(test, prefix);
    }
    bf_dump_prefix_pop(prefix);

    DUMP(bf_dump_prefix_last(prefix), "cmtests: (struct CMUnitTest *)%p",
         group->cmtests);
    bf_dump_prefix_pop(prefix);
}

int bf_test_group_make_cmtests(bf_test_group *group)
{
    size_t index = 0;

    bf_assert(group);

    group->cmtests =
        calloc(bf_list_size(&group->tests), sizeof(struct CMUnitTest));
    if (!group->cmtests)
        return -ENOMEM;

    bf_list_foreach (&group->tests, test_node) {
        bf_test *test = bf_list_node_get_data(test_node);

        group->cmtests[index++] = (struct CMUnitTest) {
            .name = test->test_name,
            .test_func = test->cb,
        };
    }

    return 0;
}

int bf_test_suite_new(bf_test_suite **suite)
{
    _free_bf_test_suite_ bf_test_suite *_suite = NULL;

    bf_assert(suite);

    _suite = calloc(1, sizeof(*_suite));
    if (!_suite)
        return -ENOMEM;

    bf_list_init(
        &_suite->groups,
        (bf_list_ops[]) {{.free = (bf_list_ops_free)bf_test_group_free}});

    *suite = TAKE_PTR(_suite);

    return 0;
}

void bf_test_suite_free(bf_test_suite **suite)
{
    bf_assert(suite);

    if (!*suite)
        return;

    bf_list_clean(&(*suite)->groups);
    freep((void *)suite);
}

void bf_test_suite_dump(const bf_test_suite *suite, prefix_t *prefix)
{
    bf_assert(suite && prefix);

    DUMP(prefix, "bf_test_suite at %p", suite);
    bf_dump_prefix_push(prefix);
    DUMP(bf_dump_prefix_last(prefix), "groups: bf_list<bf_group>[%lu]",
         bf_list_size(&suite->groups));
    bf_dump_prefix_push(prefix);
    bf_list_foreach (&suite->groups, group_node) {
        bf_test_group *group = bf_list_node_get_data(group_node);

        if (bf_list_is_tail(&suite->groups, group_node))
            bf_dump_prefix_last(prefix);

        bf_test_group_dump(group, prefix);
    }
    bf_dump_prefix_pop(prefix);
    bf_dump_prefix_pop(prefix);
}

bf_test_group *bf_test_suite_get_group(bf_test_suite *suite,
                                       const char *group_name)
{
    bf_assert(suite && group_name);

    bf_list_foreach (&suite->groups, group_node) {
        bf_test_group *group = bf_list_node_get_data(group_node);
        if (bf_streq(group->name, group_name))
            return group;
    }

    return NULL;
}

int bf_test_suite_add_test(bf_test_suite *suite, const char *group_name,
                           bf_test *test)

{
    bf_test_group *group;
    int r;

    bf_assert(suite && group_name && test);

    group = bf_test_suite_get_group(suite, group_name);
    if (!group) {
        _free_bf_test_group_ bf_test_group *new_group = NULL;

        r = bf_test_group_new(&new_group, group_name);
        if (r)
            return r;

        r = bf_list_add_tail(&suite->groups, new_group);
        if (r)
            return r;

        group = TAKE_PTR(new_group);
    }

    r = bf_list_add_tail(&group->tests, test);
    if (r)
        return r;

    return 0;
}

int bf_test_discover_test_suite(bf_test_suite **suite, bf_test *tests,
                                void *sentinel)
{
    _free_bf_list_ bf_list *symbols = NULL;
    _free_bf_test_suite_ bf_test_suite *_suite = NULL;
    bf_test *test;
    int r;

    bf_assert(suite);

    r = bf_test_suite_new(&_suite);
    if (r < 0)
        return bf_err_r(r, "failed to create a bf_test_suite object");

    for (test = tests; test < (bf_test *)sentinel; ++test) {
        r = bf_test_suite_add_test(_suite, test->group_name, test);
        if (r)
            return r;
    }

    bf_list_foreach (&_suite->groups, group_node) {
        bf_test_group *group = bf_list_node_get_data(group_node);

        r = bf_test_group_make_cmtests(group);
        if (r) {
            bf_warn_r(r, "failed to make CMocka unit test for group '%s'",
                      group->name);
            continue;
        }
    }

    *suite = TAKE_PTR(_suite);

    return 0;
}

static void _bf_test_filter_regex_free(regex_t **regex)
{
    bf_assert(regex);

    if (!*regex)
        return;

    regfree(*regex);
    freep((void *)regex);
}

int bf_test_filter_new(bf_test_filter **filter)
{
    bf_assert(filter);

    *filter = malloc(sizeof(bf_test_filter));
    if (!*filter)
        return -ENOMEM;

    bf_list_init(&(*filter)->patterns,
                 (bf_list_ops[]) {
                     {.free = (bf_list_ops_free)_bf_test_filter_regex_free}});

    return 0;
}

void bf_test_filter_free(bf_test_filter **filter)
{
    bf_assert(filter);

    if (!*filter)
        return;

    bf_list_clean(&(*filter)->patterns);
    freep((void *)filter);
}

int bf_test_filter_add_pattern(bf_test_filter *filter, const char *pattern)
{
    _cleanup_free_ regex_t *regex = NULL;
    char errbuf[128];
    int r;

    regex = malloc(sizeof(*regex));
    if (!regex)
        return -ENOMEM;

    r = regcomp(regex, pattern, 0);
    if (r) {
        regerror(r, regex, errbuf, sizeof(errbuf));
        return bf_err_r(-EINVAL, "failed to compile regex '%s': %s", pattern,
                        errbuf);
    }

    r = bf_list_add_tail(&filter->patterns, regex);
    if (r)
        return bf_err_r(r, "failed to add regex to the patterns list");

    TAKE_PTR(regex);

    return 0;
}

bool bf_test_filter_matches(bf_test_filter *filter, const char *str)
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
                bf_warn(
                    "failed to match '%s' against a regex, assuming pattern is allowed: %s",
                    str, errbuf);
            }
            return true;
        }
    }

    return false;
}
