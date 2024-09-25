/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#include "bpfilter/cgen/cgen.h"

#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "bpfilter/cgen/dump.h"
#include "bpfilter/cgen/program.h"
#include "core/chain.h"
#include "core/dump.h"
#include "core/front.h"
#include "core/helper.h"
#include "core/hook.h"
#include "core/list.h"
#include "core/logger.h"
#include "core/marsh.h"
#include "core/rule.h"

int bf_cgen_new(struct bf_cgen **cgen, enum bf_front front,
                struct bf_chain **chain)
{
    bf_assert(cgen && chain && *chain);

    *cgen = malloc(sizeof(struct bf_cgen));
    if (!*cgen)
        return -ENOMEM;

    (*cgen)->front = front;
    (*cgen)->program = NULL;
    (*cgen)->chain = TAKE_PTR(*chain);

    return 0;
}

int bf_cgen_new_from_marsh(struct bf_cgen **cgen, const struct bf_marsh *marsh)
{
    _cleanup_bf_cgen_ struct bf_cgen *_cgen = NULL;
    _cleanup_bf_program_ struct bf_program *program = NULL;
    _cleanup_bf_chain_ struct bf_chain *chain = NULL;
    struct bf_marsh *marsh_elem = NULL;
    enum bf_front front;
    int r;

    bf_assert(cgen);
    bf_assert(marsh);

    if (!(marsh_elem = bf_marsh_next_child(marsh, marsh_elem)))
        return -EINVAL;
    memcpy(&front, marsh_elem->data, sizeof(front));

    if (!(marsh_elem = bf_marsh_next_child(marsh, marsh_elem)))
        return -EINVAL;

    bf_info("Adding marsh of size %lu", marsh_elem->data_len);
    r = bf_chain_new_from_marsh(&chain, marsh_elem);
    if (r < 0)
        return r;

    r = bf_cgen_new(&_cgen, front, &chain);
    if (r)
        return bf_err_r(r, "failed to allocate codegen object");

    if (!(marsh_elem = bf_marsh_next_child(marsh, marsh_elem)))
        return -EINVAL;
    if (!bf_marsh_is_empty(marsh_elem)) {
        r = bf_program_unmarsh(marsh_elem, &_cgen->program, _cgen->chain);
        if (r < 0)
            return r;
    }

    if (bf_marsh_next_child(marsh, marsh_elem))
        bf_warn("codegen marsh has more children than expected");

    *cgen = TAKE_PTR(_cgen);

    return 0;
}

void bf_cgen_free(struct bf_cgen **cgen)
{
    bf_assert(cgen);

    if (!*cgen)
        return;

    bf_program_free(&(*cgen)->program);
    bf_chain_free(&(*cgen)->chain);

    free(*cgen);
    *cgen = NULL;
}

int bf_cgen_marsh(const struct bf_cgen *cgen, struct bf_marsh **marsh)
{
    _cleanup_bf_marsh_ struct bf_marsh *_marsh = NULL;
    int r;

    bf_assert(cgen);
    bf_assert(marsh);

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
        _cleanup_bf_marsh_ struct bf_marsh *prog_elem = NULL;

        if (cgen->program) {
            r = bf_program_marsh(cgen->program, &prog_elem);
            if (r < 0)
                return r;
        } else {
            r = bf_marsh_new(&prog_elem, NULL, 0);
            if (r < 0)
                return r;
        }

        r = bf_marsh_add_child_obj(&_marsh, prog_elem);
        if (r)
            return r;
    }

    *marsh = TAKE_PTR(_marsh);

    return 0;
}

int bf_cgen_unload(struct bf_cgen *cgen)
{
    bf_assert(cgen);

    return bf_program_unload(cgen->program);
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
    if (cgen->program) {
        DUMP(bf_dump_prefix_last(prefix), "program: struct bf_program *");
        bf_dump_prefix_push(prefix);
        bf_program_dump(cgen->program, bf_dump_prefix_last(prefix));
        bf_dump_prefix_pop(prefix);
    } else {
        DUMP(bf_dump_prefix_last(prefix), "program: (struct bf_program *)NULL");
    }

    bf_dump_prefix_pop(prefix);
}

int bf_cgen_get_counter(const struct bf_cgen *cgen, uint32_t counter_idx,
                        struct bf_counter *counter)
{
    bf_assert(cgen && counter);

    /* There are 1 more counter than number of rules. The last counter is
     * dedicated to the policy. */
    if (counter_idx > bf_list_size(&cgen->chain->rules))
        return -EINVAL;

    return bf_program_get_counter(cgen->program, counter_idx, counter);
}

int bf_cgen_up(struct bf_cgen *cgen)
{
    _cleanup_bf_program_ struct bf_program *prog = NULL;
    int r;

    bf_assert(cgen);

    bf_cgen_dump(cgen, EMPTY_PREFIX);

    r = bf_program_new(&prog, cgen->chain->hook, cgen->front, cgen->chain);
    if (r < 0)
        return r;

    r = bf_program_generate(prog);
    if (r < 0) {
        return bf_err_r(r, "failed to generate bf_program for %s",
                        bf_hook_to_str(cgen->chain->hook));
    }

    r = bf_program_load(prog, NULL);
    if (r < 0)
        return r;

    cgen->program = TAKE_PTR(prog);

    return r;
}

int bf_cgen_update(struct bf_cgen *cgen, struct bf_chain **new_chain)
{
    _cleanup_bf_program_ struct bf_program *new_prog = NULL;
    int r;

    bf_assert(cgen && new_chain);

    r = bf_program_new(&new_prog, (*new_chain)->hook, cgen->front, *new_chain);
    if (r < 0)
        return bf_err_r(r, "failed to create a new bf_program");

    r = bf_program_generate(new_prog);
    if (r < 0) {
        return bf_err_r(r,
                        "failed to generate the bytecode for a new bf_program");
    }

    r = bf_program_load(new_prog, cgen->program);
    if (r < 0) {
        return bf_err_r(
            r, "failed to attach the new bf_program, keeping the old one");
    }

    bf_swap(cgen->program, new_prog);
    bf_swap(cgen->chain, *new_chain);

    return 0;
}
