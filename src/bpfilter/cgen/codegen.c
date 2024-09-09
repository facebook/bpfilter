/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#include "codegen.h"

#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

#include "bpfilter/cgen/dump.h"
#include "bpfilter/cgen/program.h"
#include "core/dump.h"
#include "core/front.h"
#include "core/helper.h"
#include "core/hook.h"
#include "core/if.h"
#include "core/list.h"
#include "core/logger.h"
#include "core/marsh.h"
#include "core/rule.h"
#include "core/verdict.h"

int bf_codegen_new(struct bf_codegen **codegen)
{
    _cleanup_bf_codegen_ struct bf_codegen *_codegen = NULL;

    bf_assert(codegen);

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
    bf_assert(codegen);

    if (!*codegen)
        return;

    bf_list_clean(&(*codegen)->rules);
    bf_list_clean(&(*codegen)->programs);

    free(*codegen);
    *codegen = NULL;
}

int bf_codegen_unload(struct bf_codegen *codegen)
{
    int r;

    bf_assert(codegen);

    bf_list_foreach (&codegen->programs, program_node) {
        struct bf_program *program = bf_list_node_get_data(program_node);
        r = bf_program_unload(program);
        if (r)
            return bf_err_r(r, "failed to unload program");
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
    r |= bf_marsh_add_child_raw(&_marsh, &codegen->policy,
                                sizeof(codegen->policy));

    if (r)
        return bf_err_r(r, "failed to serialize codegen");

    *marsh = TAKE_PTR(_marsh);

    return 0;
}

int bf_codegen_unmarsh(const struct bf_marsh *marsh,
                       struct bf_codegen **codegen)
{
    _cleanup_bf_codegen_ struct bf_codegen *_codegen = NULL;
    struct bf_marsh *marsh_elem = NULL;
    int r;

    bf_assert(marsh);
    bf_assert(codegen);

    r = bf_codegen_new(&_codegen);
    if (r)
        return bf_err_r(r, "failed to allocate codegen object");

    if (!(marsh_elem = bf_marsh_next_child(marsh, NULL)))
        return -EINVAL;

    {
        struct bf_marsh *rule_elem = NULL;

        while ((rule_elem = bf_marsh_next_child(marsh_elem, rule_elem))) {
            _cleanup_bf_rule_ struct bf_rule *rule = NULL;
            r = bf_rule_unmarsh(rule_elem, &rule);
            if (r)
                return r;

            r = bf_list_add_tail(&_codegen->rules, rule);
            if (r)
                return r;

            TAKE_PTR(rule);
        }
    }

    if (!(marsh_elem = bf_marsh_next_child(marsh, marsh_elem)))
        return -EINVAL;

    {
        struct bf_marsh *prog_elem = NULL;

        while ((prog_elem = bf_marsh_next_child(marsh_elem, prog_elem))) {
            _cleanup_bf_program_ struct bf_program *program = NULL;
            r = bf_program_unmarsh(prog_elem, &program);
            if (r)
                return r;

            r = bf_list_add_tail(&_codegen->programs, program);
            if (r)
                return r;

            TAKE_PTR(program);
        }
    }

    if (!(marsh_elem = bf_marsh_next_child(marsh, marsh_elem)))
        return -EINVAL;
    memcpy(&_codegen->hook, marsh_elem->data, sizeof(_codegen->hook));

    if (!(marsh_elem = bf_marsh_next_child(marsh, marsh_elem)))
        return -EINVAL;
    memcpy(&_codegen->front, marsh_elem->data, sizeof(_codegen->front));

    if (!(marsh_elem = bf_marsh_next_child(marsh, marsh_elem)))
        return -EINVAL;
    memcpy(&_codegen->policy, marsh_elem->data, sizeof(_codegen->policy));

    if (bf_marsh_next_child(marsh, marsh_elem))
        bf_warn("codegen marsh has more children than expected");

    *codegen = TAKE_PTR(_codegen);

    bf_info("restored new codegen at %p", *codegen);

    return 0;
}

void bf_codegen_dump(const struct bf_codegen *codegen, prefix_t *prefix)
{
    bf_assert(codegen);
    bf_assert(prefix);

    DUMP(prefix, "struct bf_codegen at %p", codegen);

    bf_dump_prefix_push(prefix);
    DUMP(prefix, "hook: %s", bf_hook_to_str(codegen->hook));
    DUMP(prefix, "front: %s", bf_front_to_str(codegen->front));
    DUMP(prefix, "policy: %s", bf_verdict_to_str(codegen->policy));

    // Rules
    DUMP(prefix, "rules: bf_list<bf_rule>[%lu]", bf_list_size(&codegen->rules));
    bf_dump_prefix_push(prefix);
    bf_list_foreach (&codegen->rules, rule_node) {
        struct bf_rule *rule = bf_list_node_get_data(rule_node);

        if (bf_list_is_tail(&codegen->rules, rule_node))
            bf_dump_prefix_last(prefix);

        bf_rule_dump(rule, prefix);
    }
    bf_dump_prefix_pop(prefix);

    // Programs
    DUMP(bf_dump_prefix_last(prefix), "programs: bf_list<bf_program>[%lu]",
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

struct bf_program *bf_codegen_get_program(const struct bf_codegen *codegen,
                                          uint32_t ifindex)
{
    bf_list_foreach (&codegen->programs, program_node) {
        struct bf_program *program = bf_list_node_get_data(program_node);
        if (program->ifindex == ifindex)
            return program;
    }

    return NULL;
}

int bf_codegen_get_counter(const struct bf_codegen *codegen,
                           uint32_t counter_idx, struct bf_counter *counter)
{
    bf_assert(codegen);
    bf_assert(counter);

    int r;

    /* There are 1 more counter than number of rules. The last counter is
     * dedicated to the policy. */
    if (counter_idx > bf_list_size(&codegen->rules))
        return -EINVAL;

    bf_list_foreach (&codegen->programs, program_node) {
        struct bf_program *program = bf_list_node_get_data(program_node);
        struct bf_counter _counter = {};

        r = bf_program_get_counter(program, counter_idx, &_counter);
        if (r)
            return -EINVAL;

        counter->packets += _counter.packets;
        counter->bytes += _counter.bytes;
    }

    return 0;
}

int bf_codegen_up(struct bf_codegen *codegen)
{
    _cleanup_free_ struct bf_if_iface *ifaces = NULL;
    ssize_t n_ifaces;
    int r = 0;

    bf_assert(codegen);

    n_ifaces = bf_if_get_ifaces(&ifaces);
    if (n_ifaces < 0) {
        return bf_err_r((int)n_ifaces,
                        "failed to fetch interfaces for codegen");
    }

    if (n_ifaces == 0)
        return bf_err_r(-ENOENT, "no interface found!");

    for (ssize_t i = 0; i < n_ifaces; ++i) {
        _cleanup_bf_program_ struct bf_program *prog = NULL;

        if (bf_streq("lo", ifaces[i].name))
            continue;

        r = bf_program_new(&prog, ifaces[i].index, codegen->hook,
                           codegen->front);
        if (r)
            return r;

        r = bf_program_generate(prog, &codegen->rules, codegen->policy);
        if (r) {
            return bf_err_r(r, "failed to generate bf_program for %s",
                            ifaces[i].name);
        }

        r = bf_program_load(prog, NULL);
        if (r)
            return r;

        r = bf_list_add_tail(&codegen->programs, prog);
        if (r)
            return r;

        TAKE_PTR(prog);
    }

    return r;
}

int bf_codegen_update(struct bf_codegen *codegen)
{
    int r;

    bf_assert(codegen);

    bf_list_foreach (&codegen->programs, program_node) {
        _cleanup_bf_program_ struct bf_program *new_prog = NULL;
        struct bf_program *old_prog = bf_list_node_get_data(program_node);

        r = bf_program_new(&new_prog, old_prog->ifindex, codegen->hook,
                           codegen->front);
        if (r)
            return bf_err_r(r, "failed to create a new bf_program");

        r = bf_program_generate(new_prog, &codegen->rules, codegen->policy);
        if (r) {
            {
                return bf_err_r(
                    r, "failed to generate the bytecode for a new bf_program");
            }
        }

        r = bf_program_load(new_prog, old_prog);
        if (r) {
            return bf_err_r(
                r, "failed to attach the new bf_program, keeping the old one");
        }

        program_node->data = TAKE_PTR(new_prog);
        bf_program_free(&old_prog);
    }

    return 0;
}
