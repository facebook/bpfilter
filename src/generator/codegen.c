/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#include "codegen.h"

#include <net/if.h>

#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include "core/dump.h"
#include "core/logger.h"
#include "core/marsh.h"
#include "core/rule.h"
#include "core/string.h"
#include "generator/dump.h"
#include "generator/program.h"
#include "shared/front.h"
#include "shared/helper.h"

int bf_codegen_new(struct bf_codegen **codegen)
{
    _cleanup_bf_codegen_ struct bf_codegen *_codegen = NULL;

    assert(codegen);

    _codegen = calloc(1, sizeof(*_codegen));
    if (!_codegen)
        return -ENOMEM;

    bf_list_init(&_codegen->rules,
                 (bf_list_ops[]) {{.free = (bf_list_ops_free)bf_rule_free}});

    bf_list_init(&_codegen->programs,
                 (bf_list_ops[]) {{.free = (bf_list_ops_free)bf_program_free}});

    *codegen = TAKE_PTR(_codegen);

    return 0;
}

void bf_codegen_free(struct bf_codegen **codegen)
{
    assert(codegen);

    if (!*codegen)
        return;

    bf_list_clean(&(*codegen)->rules);
    bf_list_clean(&(*codegen)->programs);

    free(*codegen);
    *codegen = NULL;
}

int bf_codegen_generate(struct bf_codegen *codegen)
{
    int r;
    struct if_nameindex *if_ni;
    struct if_nameindex *it;

    assert(codegen);

    if_ni = if_nameindex();
    if (!if_ni)
        return bf_err_code(errno, "failed to get local interfaces");

    for (it = if_ni; it->if_index != 0 || it->if_name != NULL; it++) {
        _cleanup_bf_program_ struct bf_program *program = NULL;
        if (streq("lo", it->if_name))
            continue;

        r = bf_program_new(&program, it->if_index, codegen->hook,
                           codegen->front);
        if (r)
            return r;

        r = bf_program_generate(program, &codegen->rules);
        if (r)
            return bf_err_code(r, "failed to generate program for %s",
                               it->if_name);

        r = bf_list_add_tail(&codegen->programs, program);
        if (r)
            return bf_err_code(r, "failed to add program to codegen");

        TAKE_PTR(program);
    }

    if_freenameindex(if_ni);

    return 0;
}

int bf_codegen_load(struct bf_codegen *codegen)
{
    int r;

    bf_list_foreach (&codegen->programs, program_node) {
        struct bf_program *program = bf_list_node_get_data(program_node);
        r = bf_program_load(program);
        if (r) {
            bf_program_dump(program, NULL);
            bf_program_dump_bytecode(program, false);
            return bf_err_code(r, "failed to load program");
        }
    }

    bf_codegen_dump(codegen, NULL);

    return 0;
}

int bf_codegen_unload(struct bf_codegen *codegen)
{
    int r;

    assert(codegen);

    bf_list_foreach (&codegen->programs, program_node) {
        struct bf_program *program = bf_list_node_get_data(program_node);
        r = bf_program_unload(program);
        if (r)
            return bf_err_code(r, "failed to unload program");
    }

    return 0;
}

int bf_codegen_marsh(const struct bf_codegen *codegen, struct bf_marsh **marsh)
{
    _cleanup_bf_marsh_ struct bf_marsh *_marsh = NULL;
    int r;

    r = bf_marsh_new(&_marsh, NULL, 0);
    if (r)
        return r;

    {
        _cleanup_bf_marsh_ struct bf_marsh *child = NULL;
        r = bf_marsh_new(&child, NULL, 0);
        if (r)
            return r;

        bf_list_foreach (&codegen->rules, rule_node) {
            _cleanup_bf_marsh_ struct bf_marsh *subchild = NULL;
            struct bf_rule *rule = bf_list_node_get_data(rule_node);

            r = bf_rule_marsh(rule, &subchild);
            if (r)
                return r;

            r = bf_marsh_add_child_obj(&child, subchild);
            if (r)
                return r;
        }

        r = bf_marsh_add_child_obj(&_marsh, child);
        if (r)
            return r;
    }

    {
        _cleanup_bf_marsh_ struct bf_marsh *child = NULL;
        r = bf_marsh_new(&child, NULL, 0);
        if (r)
            return r;

        bf_list_foreach (&codegen->programs, program_node) {
            _cleanup_bf_marsh_ struct bf_marsh *subchild = NULL;
            struct bf_program *program = bf_list_node_get_data(program_node);

            r = bf_program_marsh(program, &subchild);
            if (r)
                return r;

            r = bf_marsh_add_child_obj(&child, subchild);
            if (r)
                return r;
        }

        r = bf_marsh_add_child_obj(&_marsh, child);
        if (r)
            return r;
    }

    r |= bf_marsh_add_child_raw(&_marsh, &codegen->hook, sizeof(codegen->hook));
    r |= bf_marsh_add_child_raw(&_marsh, &codegen->front,
                                sizeof(codegen->front));

    if (r)
        return bf_err_code(r, "failed to serialize codegen");

    *marsh = TAKE_PTR(_marsh);

    return 0;
}

int bf_codegen_unmarsh(const struct bf_marsh *marsh,
                       struct bf_codegen **codegen)
{
    _cleanup_bf_codegen_ struct bf_codegen *_codegen = NULL;
    struct bf_marsh *child = NULL;
    int r;

    assert(marsh);
    assert(codegen);

    r = bf_codegen_new(&_codegen);
    if (r)
        return bf_err_code(r, "failed to allocate codegen object");

    child = bf_marsh_next_child(marsh, NULL);

    {
        struct bf_marsh *subchild = NULL;

        while ((subchild = bf_marsh_next_child(child, subchild))) {
            _cleanup_bf_rule_ struct bf_rule *rule = NULL;
            r = bf_rule_unmarsh(subchild, &rule);
            if (r)
                return r;

            r = bf_list_add_tail(&_codegen->rules, rule);
            if (r)
                return r;

            TAKE_PTR(rule);
        }
    }

    child = bf_marsh_next_child(marsh, child);
    {
        struct bf_marsh *subchild = NULL;
        while ((subchild = bf_marsh_next_child(child, subchild))) {
            _cleanup_bf_program_ struct bf_program *program = NULL;
            r = bf_program_unmarsh(subchild, &program);
            if (r)
                return r;

            r = bf_list_add_tail(&_codegen->programs, program);
            if (r)
                return r;

            TAKE_PTR(program);
        }
    }

    child = bf_marsh_next_child(marsh, child);

    memcpy(&_codegen->hook, child->data, sizeof(_codegen->hook));
    child = bf_marsh_next_child(marsh, child);

    memcpy(&_codegen->front, child->data, sizeof(_codegen->front));
    child = bf_marsh_next_child(marsh, child);

    if (bf_marsh_next_child(marsh, child))
        bf_warn("codegen marsh has more children than expected");

    *codegen = TAKE_PTR(_codegen);

    bf_info("restored new codegen at %p", *codegen);

    return 0;
}

void bf_codegen_dump(const struct bf_codegen *codegen, prefix_t *prefix)
{
    prefix_t _prefix = {};
    prefix = prefix ?: &_prefix;

    DUMP(prefix, "struct bf_codegen at %p", codegen);

    bf_dump_prefix_push(prefix);
    DUMP(prefix, "hook: %s", bf_hook_to_str(codegen->hook));
    DUMP(prefix, "front: %s", bf_front_to_str(codegen->front));

    // Rules
    DUMP(prefix, "rules: %lu", bf_list_size(&codegen->rules));
    bf_dump_prefix_push(prefix);
    bf_list_foreach (&codegen->rules, rule_node) {
        struct bf_rule *rule = bf_list_node_get_data(rule_node);

        if (bf_list_is_tail(&codegen->rules, rule_node))
            bf_dump_prefix_last(prefix);

        bf_rule_dump(rule, prefix);
    }
    bf_dump_prefix_pop(prefix);

    // Programs
    DUMP(bf_dump_prefix_last(prefix), "programs: %lu",
         bf_list_size(&codegen->programs));
    bf_dump_prefix_push(prefix);
    bf_list_foreach (&codegen->programs, program_node) {
        struct bf_program *program = bf_list_node_get_data(program_node);

        if (bf_list_is_tail(&codegen->programs, program_node))
            bf_dump_prefix_last(prefix);

        bf_program_dump(program, prefix);
    }
    bf_dump_prefix_pop(prefix);

    bf_dump_prefix_pop(prefix);
}
