/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#include "bpfilter/cgen/cgen.h"

#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

#include "bpfilter/cgen/dump.h"
#include "bpfilter/cgen/program.h"
#include "core/chain.h"
#include "core/dump.h"
#include "core/front.h"
#include "core/helper.h"
#include "core/if.h"
#include "core/list.h"
#include "core/logger.h"
#include "core/marsh.h"
#include "core/rule.h"

int bf_cgen_new(struct bf_cgen **cgen, enum bf_front front,
                struct bf_chain **chain)
{
    bf_assert(cgen);
    bf_assert(chain && *chain);

    (*cgen) = malloc(sizeof(struct bf_cgen));
    if (!(*cgen))
        return -ENOMEM;

    (*cgen)->front = front;
    (*cgen)->chain = TAKE_PTR(*chain);

    bf_list_init(&(*cgen)->programs,
                 (bf_list_ops[]) {{.free = (bf_list_ops_free)bf_program_free}});

    return 0;
}

void bf_cgen_free(struct bf_cgen **cgen)
{
    bf_assert(cgen);

    if (!*cgen)
        return;

    bf_chain_free(&(*cgen)->chain);
    bf_list_clean(&(*cgen)->programs);

    free(*cgen);
    *cgen = NULL;
}

int bf_cgen_unload(struct bf_cgen *cgen)
{
    int r;

    bf_assert(cgen);

    bf_list_foreach (&cgen->programs, program_node) {
        struct bf_program *program = bf_list_node_get_data(program_node);
        r = bf_program_unload(program);
        if (r)
            return bf_err_r(r, "failed to unload program");
    }

    return 0;
}

int bf_cgen_marsh(const struct bf_cgen *cgen, struct bf_marsh **marsh)
{
    _cleanup_bf_marsh_ struct bf_marsh *_marsh = NULL;
    int r;

    r = bf_marsh_new(&_marsh, NULL, 0);
    if (r)
        return r;

    r = bf_marsh_add_child_raw(&_marsh, &cgen->front, sizeof(cgen->front));
    if (r < 0)
        return bf_err_r(r, "failed to serialize codegen");

    {
        // Serialize cgen.chain
        _cleanup_bf_marsh_ struct bf_marsh *chain_elem = NULL;

        r = bf_chain_marsh(cgen->chain, &chain_elem);
        if (r < 0)
            return r;

        r = bf_marsh_add_child_obj(&_marsh, chain_elem);
        if (r < 0)
            return r;
    }

    {
        _cleanup_bf_marsh_ struct bf_marsh *child = NULL;
        r = bf_marsh_new(&child, NULL, 0);
        if (r)
            return r;

        bf_list_foreach (&cgen->programs, program_node) {
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

    *marsh = TAKE_PTR(_marsh);

    return 0;
}

int bf_cgen_unmarsh(const struct bf_marsh *marsh, struct bf_cgen **cgen)
{
    _cleanup_bf_cgen_ struct bf_cgen *_cgen = NULL;
    _cleanup_bf_chain_ struct bf_chain *chain = NULL;
    enum bf_front front;
    struct bf_marsh *marsh_elem = NULL;
    int r;

    bf_assert(marsh);
    bf_assert(cgen);

    if (!(marsh_elem = bf_marsh_next_child(marsh, marsh_elem)))
        return -EINVAL;
    memcpy(&front, marsh_elem->data, sizeof(front));

    if (!(marsh_elem = bf_marsh_next_child(marsh, NULL)))
        return -EINVAL;
    r = bf_chain_new_from_marsh(&chain, marsh_elem);
    if (r < 0)
        return r;

    r = bf_cgen_new(&_cgen, front, &chain);
    if (r)
        return bf_err_r(r, "failed to allocate codegen object");

    if (!(marsh_elem = bf_marsh_next_child(marsh, marsh_elem)))
        return -EINVAL;

    {
        struct bf_marsh *prog_elem = NULL;

        while ((prog_elem = bf_marsh_next_child(marsh_elem, prog_elem))) {
            _cleanup_bf_program_ struct bf_program *program = NULL;
            r = bf_program_unmarsh(prog_elem, &program);
            if (r)
                return r;

            r = bf_list_add_tail(&_cgen->programs, program);
            if (r)
                return r;

            TAKE_PTR(program);
        }
    }

    if (bf_marsh_next_child(marsh, marsh_elem))
        bf_warn("codegen marsh has more children than expected");

    *cgen = TAKE_PTR(_cgen);

    bf_info("restored new codegen at %p", *cgen);

    return 0;
}

void bf_cgen_dump(const struct bf_cgen *cgen, prefix_t *prefix)
{
    bf_assert(cgen);
    bf_assert(prefix);

    DUMP(prefix, "struct bf_cgen at %p", cgen);

    bf_dump_prefix_push(prefix);
    DUMP(prefix, "front: %s", bf_front_to_str(cgen->front));

    // Chain
    DUMP(prefix, "chain: struct bf_chain *");
    bf_dump_prefix_push(prefix);
    bf_chain_dump(cgen->chain, bf_dump_prefix_last(prefix));
    bf_dump_prefix_pop(prefix);

    // Programs
    DUMP(bf_dump_prefix_last(prefix), "programs: bf_list<bf_program>[%lu]",
         bf_list_size(&cgen->programs));
    bf_dump_prefix_push(prefix);
    bf_list_foreach (&cgen->programs, program_node) {
        struct bf_program *program = bf_list_node_get_data(program_node);

        if (bf_list_is_tail(&cgen->programs, program_node))
            bf_dump_prefix_last(prefix);

        bf_program_dump(program, prefix);
    }
    bf_dump_prefix_pop(prefix);

    bf_dump_prefix_pop(prefix);
}

struct bf_program *bf_cgen_get_program(const struct bf_cgen *cgen,
                                       uint32_t ifindex)
{
    bf_list_foreach (&cgen->programs, program_node) {
        struct bf_program *program = bf_list_node_get_data(program_node);
        if (program->ifindex == ifindex)
            return program;
    }

    return NULL;
}

int bf_cgen_get_counter(const struct bf_cgen *cgen, uint32_t counter_idx,
                        struct bf_counter *counter)
{
    bf_assert(cgen);
    bf_assert(counter);

    int r;

    /* There are 1 more counter than number of rules. The last counter is
     * dedicated to the policy. */
    if (counter_idx > bf_list_size(&cgen->chain->rules))
        return -EINVAL;

    bf_list_foreach (&cgen->programs, program_node) {
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

int bf_cgen_up(struct bf_cgen *cgen)
{
    _cleanup_free_ struct bf_if_iface *ifaces = NULL;
    ssize_t n_ifaces;
    int r = 0;

    bf_assert(cgen);

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

        r = bf_program_new(&prog, ifaces[i].index, cgen->chain->hook,
                           cgen->front);
        if (r)
            return r;

        r = bf_program_generate(prog, cgen->chain);
        if (r) {
            return bf_err_r(r, "failed to generate bf_program for %s",
                            ifaces[i].name);
        }

        r = bf_program_load(prog, NULL);
        if (r)
            return r;

        r = bf_list_add_tail(&cgen->programs, prog);
        if (r)
            return r;

        TAKE_PTR(prog);
    }

    return r;
}

int bf_cgen_update(struct bf_cgen *cgen, struct bf_chain **new_chain)
{
    int r;

    bf_assert(cgen);
    bf_assert(new_chain);

    bf_list_foreach (&cgen->programs, program_node) {
        _cleanup_bf_program_ struct bf_program *new_prog = NULL;
        struct bf_program *old_prog = bf_list_node_get_data(program_node);

        r = bf_program_new(&new_prog, old_prog->ifindex, (*new_chain)->hook,
                           cgen->front);
        if (r < 0)
            return bf_err_r(r, "failed to create a new bf_program");

        r = bf_program_generate(new_prog, *new_chain);
        if (r < 0) {
            return bf_err_r(
                r, "failed to generate the bytecode for a new bf_program");
        }

        r = bf_program_load(new_prog, old_prog);
        if (r < 0) {
            return bf_err_r(
                r, "failed to attach the new bf_program, keeping the old one");
        }

        program_node->data = TAKE_PTR(new_prog);
        bf_program_free(&old_prog);
    }

    bf_swap(cgen->chain, *new_chain);

    return 0;
}
