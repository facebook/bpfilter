/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#include "harness/test.h"

#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "harness/cmocka.h"
#include "shared/helper.h"

int bf_test_new(bf_test **test, const char *name, bf_test_func func)
{
    _cleanup_bf_test_ bf_test *_test = NULL;

    assert(test);
    assert(name);
    assert(func);

    _test = calloc(1, sizeof(*_test));
    if (!_test)
        return -ENOMEM;

    _test->name = strdup(name);
    if (!_test->name)
        return -ENOMEM;

    _test->fn = func;

    *test = TAKE_PTR(_test);

    return 0;
}

void bf_test_free(bf_test **test)
{
    assert(test);

    if (!*test)
        return;

    free((char *)(*test)->name);
    free(*test);
    *test = NULL;
}

int bf_test_group_new(bf_test_group **group, const char *name)
{
    _cleanup_bf_test_group_ bf_test_group *_group = NULL;

    assert(group);
    assert(name);

    _group = calloc(1, sizeof(*_group));
    if (!_group)
        return -ENOMEM;

    _group->name = strdup(name);
    if (!_group->name)
        return -ENOMEM;

    bf_list_init(&_group->tests,
                 (bf_list_ops[]) {{.free = (bf_list_ops_free)bf_test_free}});

    *group = TAKE_PTR(_group);

    return 0;
}

void bf_test_group_free(bf_test_group **group)
{
    assert(group);

    if (!*group)
        return;

    free((char *)(*group)->name);
    free((*group)->cmtests);
    bf_list_clean(&(*group)->tests);
    free(*group);
    *group = NULL;
}

bf_test *bf_test_group_get_test(bf_test_group *group, const char *test_name)
{
    assert(group);
    assert(test_name);

    bf_list_foreach (&group->tests, test_node) {
        bf_test *test = bf_list_node_get_data(test_node);
        if (bf_streq(test->name, test_name))
            return test;
    }

    return NULL;
}

int bf_test_group_add_test(bf_test_group *group, const char *test_name,
                           bf_test_func func)
{
    _cleanup_bf_test_ bf_test *test = NULL;
    int r;

    assert(group);
    assert(test_name);
    assert(func);

    if (bf_test_group_get_test(group, test_name))
        return -EEXIST;

    r = bf_test_new(&test, test_name, func);
    if (r)
        return r;

    r = bf_list_add_tail(&group->tests, test);
    if (r)
        return r;

    TAKE_PTR(test);

    return 0;
}

int bf_test_group_make_cmtests(bf_test_group *group)
{
    size_t index = 0;

    assert(group);

    group->cmtests =
        calloc(bf_list_size(&group->tests), sizeof(struct CMUnitTest));
    if (!group->cmtests)
        return -ENOMEM;

    bf_list_foreach (&group->tests, test_node) {
        bf_test *test = bf_list_node_get_data(test_node);

        group->cmtests[index++] = (struct CMUnitTest) {
            .name = test->name,
            .test_func = test->fn,
        };
    }

    return 0;
}

int bf_test_suite_new(bf_test_suite **suite)
{
    _cleanup_bf_test_suite_ bf_test_suite *_suite = NULL;

    assert(suite);

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
    assert(suite);

    if (!*suite)
        return;

    bf_list_clean(&(*suite)->groups);
    free(*suite);
    *suite = NULL;
}

bf_test_group *bf_test_suite_get_group(bf_test_suite *suite,
                                       const char *group_name)
{
    assert(suite);
    assert(group_name);

    bf_list_foreach (&suite->groups, group_node) {
        bf_test_group *group = bf_list_node_get_data(group_node);
        if (bf_streq(group->name, group_name))
            return group;
    }

    return NULL;
}

int bf_test_suite_add_test(bf_test_suite *suite, const char *group_name,
                           const char *test_name, bf_test_func func)

{
    bf_test_group *group;
    int r;

    assert(suite);
    assert(group_name);
    assert(test_name);
    assert(func);

    group = bf_test_suite_get_group(suite, group_name);
    if (!group) {
        _cleanup_bf_test_group_ bf_test_group *new_group = NULL;

        r = bf_test_group_new(&new_group, group_name);
        if (r)
            return r;

        r = bf_list_add_tail(&suite->groups, new_group);
        if (r)
            return r;

        group = TAKE_PTR(new_group);
    }

    r = bf_test_group_add_test(group, test_name, func);
    if (r)
        return r;

    return 0;
}

int bf_test_suite_add_symbol(bf_test_suite *suite, struct bf_elf_sym *sym)
{
    /**
     * Split symbol name into group and test name.
     * Add group
     * Add test to group, with function pointer
     */
    _cleanup_free_ char *group_name = NULL;
    _cleanup_free_ char *test_name = NULL;
    const char *group_name_end;
    const char *test_name_start;
    int r;

    assert(suite);
    assert(sym);

    group_name_end = strchr(sym->name, '_');
    if (!group_name_end || group_name_end - sym->name == 0)
        return -EINVAL;

    group_name = strndup(sym->name, group_name_end - sym->name);
    if (!group_name)
        return -ENOMEM;

    test_name_start = group_name_end + 2;
    if (!(sym->name <= test_name_start &&
          test_name_start < (sym->name + strlen(sym->name))))
        return -EINVAL;

    test_name = strdup(test_name_start);
    if (!test_name)
        return -ENOMEM;

    r = bf_test_suite_add_test(suite, group_name, test_name, sym->fn);
    if (r)
        return r;

    return 0;
}

int bf_test_suite_make_cmtests(const bf_test_suite *suite)
{
    int r;

    assert(suite);

    bf_list_foreach (&suite->groups, group_node) {
        bf_test_group *group = bf_list_node_get_data(group_node);

        r = bf_test_group_make_cmtests(group);
        if (r) {
            fprintf(stderr,
                    "WARNING: failed to make cmocka unit test for group '%s': "
                    "%s\n",
                    group->name, strerror(-r));
            continue;
        }
    }

    return 0;
}

void bf_test_suite_dump(const bf_test_suite *suite)
{
    assert(suite);

    printf("Test suite:\n");

    bf_list_foreach (&suite->groups, group_node) {
        bf_test_group *group = bf_list_node_get_data(group_node);
        printf("  Group: %s\n", group->name);

        bf_list_foreach (&group->tests, test_node) {
            bf_test *test = bf_list_node_get_data(test_node);
            printf("    Test: %s\n", test->name);
        }
    }
}
