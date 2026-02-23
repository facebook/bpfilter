/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#include "cgen/cgen.h"

#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

#include <bpfilter/chain.h>
#include <bpfilter/counter.h>
#include <bpfilter/dump.h>
#include <bpfilter/front.h>
#include <bpfilter/helper.h>
#include <bpfilter/hook.h>
#include <bpfilter/io.h>
#include <bpfilter/list.h>
#include <bpfilter/logger.h>
#include <bpfilter/ns.h>
#include <bpfilter/pack.h>

#include "cgen/dump.h"
#include "cgen/handle.h"
#include "cgen/prog/link.h"
#include "cgen/prog/map.h"
#include "cgen/program.h"
#include "ctx.h"
#include "opts.h"

#define _BF_PROG_NAME "bf_prog"

static int _bf_cgen_get_chain_pindir_fd(const char *name)
{
    _cleanup_close_ int bf_fd = -1;
    _cleanup_close_ int chain_fd = -1;

    assert(name);

    bf_fd = bf_ctx_get_pindir_fd();
    if (bf_fd < 0)
        return bf_fd;

    chain_fd = bf_opendir_at(bf_fd, name, true);
    if (chain_fd < 0)
        return chain_fd;

    return TAKE_FD(chain_fd);
}

int bf_cgen_new(struct bf_cgen **cgen, enum bf_front front,
                struct bf_chain **chain)
{
    _free_bf_cgen_ struct bf_cgen *_cgen = NULL;
    int r;

    assert(cgen);
    assert(chain);

    _cgen = calloc(1, sizeof(*_cgen));
    if (!_cgen)
        return -ENOMEM;

    _cgen->front = front;
    _cgen->chain = TAKE_PTR(*chain);

    r = bf_handle_new(&_cgen->handle, _BF_PROG_NAME);
    if (r)
        return r;

    *cgen = TAKE_PTR(_cgen);

    return 0;
}

int bf_cgen_new_from_pack(struct bf_cgen **cgen, bf_rpack_node_t node)
{
    _free_bf_cgen_ struct bf_cgen *_cgen = NULL;
    _cleanup_close_ int dir_fd = -1;
    bf_rpack_node_t child;
    int r;

    assert(cgen);

    _cgen = calloc(1, sizeof(*_cgen));
    if (!_cgen)
        return -ENOMEM;

    r = bf_rpack_kv_enum(node, "front", &_cgen->front, 0, _BF_FRONT_MAX);
    if (r)
        return bf_rpack_key_err(r, "bf_cgen.front");

    r = bf_rpack_kv_obj(node, "chain", &child);
    if (r)
        return bf_rpack_key_err(r, "bf_cgen.chain");

    r = bf_chain_new_from_pack(&_cgen->chain, child);
    if (r)
        return bf_rpack_key_err(r, "bf_cgen.chain");

    r = bf_rpack_kv_node(node, "handle", &child);
    if (r)
        return bf_rpack_key_err(r, "bf_cgen.handle");

    if ((dir_fd = _bf_cgen_get_chain_pindir_fd(_cgen->chain->name)) < 0) {
        return bf_err_r(dir_fd, "failed to open chain pin directory for '%s'",
                        _cgen->chain->name);
    }

    r = bf_handle_new_from_pack(&_cgen->handle, dir_fd, child);
    if (r)
        return r;

    *cgen = TAKE_PTR(_cgen);

    return 0;
}

void bf_cgen_free(struct bf_cgen **cgen)
{
    _cleanup_close_ int pin_fd = -1;

    assert(cgen);

    if (!*cgen)
        return;

    /* Perform a non-recursive removal of the chain's pin directory: if
     * the chain hasn't been pinned (e.g. due to a failure), the pin directory
     * will be empty and will be removed. If the chain is valid and pinned, then
     * the removal of the pin directory will fail, but that's alright. */
    if (bf_opts_persist() && (pin_fd = bf_ctx_get_pindir_fd()) >= 0)
        bf_rmdir_at(pin_fd, (*cgen)->chain->name, false);

    bf_handle_free(&(*cgen)->handle);
    bf_chain_free(&(*cgen)->chain);

    free(*cgen);
    *cgen = NULL;
}

int bf_cgen_pack(const struct bf_cgen *cgen, bf_wpack_t *pack)
{
    assert(cgen);
    assert(pack);

    bf_wpack_kv_enum(pack, "front", cgen->front);

    bf_wpack_open_object(pack, "chain");
    bf_chain_pack(cgen->chain, pack);
    bf_wpack_close_object(pack);

    bf_wpack_open_object(pack, "handle");
    bf_handle_pack(cgen->handle, pack);
    bf_wpack_close_object(pack);

    return bf_wpack_is_valid(pack) ? 0 : -EINVAL;
}

void bf_cgen_dump(const struct bf_cgen *cgen, prefix_t *prefix)
{
    assert(cgen);
    assert(prefix);

    DUMP(prefix, "struct bf_cgen at %p", cgen);

    bf_dump_prefix_push(prefix);
    DUMP(prefix, "front: %s", bf_front_to_str(cgen->front));

    // Chain
    DUMP(prefix, "chain: struct bf_chain *");
    bf_dump_prefix_push(prefix);
    bf_chain_dump(cgen->chain, bf_dump_prefix_last(prefix));
    bf_dump_prefix_pop(prefix);

    DUMP(bf_dump_prefix_last(prefix), "handle: struct bf_handle *");
    bf_dump_prefix_push(prefix);
    bf_handle_dump(cgen->handle, bf_dump_prefix_last(prefix));
    bf_dump_prefix_pop(prefix);

    bf_dump_prefix_pop(prefix);
}

int bf_cgen_get_counter(const struct bf_cgen *cgen,
                        enum bf_counter_type counter_idx,
                        struct bf_counter *counter)
{
    assert(cgen);
    assert(counter);

    /* There are two more counter than rules. The special counters must
     * be accessed via the specific values, to avoid confusion. */
    enum bf_counter_type rule_count = bf_list_size(&cgen->chain->rules);
    if (counter_idx == BF_COUNTER_POLICY) {
        counter_idx = rule_count;
    } else if (counter_idx == BF_COUNTER_ERRORS) {
        counter_idx = rule_count + 1;
    } else if (counter_idx < 0 || counter_idx >= rule_count) {
        return -EINVAL;
    }

    return bf_handle_get_counter(cgen->handle, counter_idx, counter);
}

int bf_cgen_set(struct bf_cgen *cgen, const struct bf_ns *ns,
                struct bf_hookopts **hookopts)
{
    _free_bf_program_ struct bf_program *prog = NULL;
    _cleanup_close_ int pindir_fd = -1;
    int r;

    assert(cgen);

    if (bf_opts_persist()) {
        pindir_fd = _bf_cgen_get_chain_pindir_fd(cgen->chain->name);
        if (pindir_fd < 0)
            return pindir_fd;
    }

    r = bf_program_new(&prog, cgen->chain, cgen->handle);
    if (r < 0)
        return r;

    r = bf_program_generate(prog);
    if (r < 0)
        return bf_err_r(r, "failed to generate bf_program");

    r = bf_program_load(prog);
    if (r < 0)
        return bf_err_r(r, "failed to load the chain");

    if (hookopts) {
        r = bf_ns_set(ns, bf_ctx_get_ns());
        if (r)
            return bf_err_r(r, "failed to switch to the client's namespaces");

        r = bf_handle_attach(cgen->handle, cgen->chain->hook, hookopts);
        if (r < 0)
            return bf_err_r(r, "failed to load and attach the chain");

        if (bf_ns_set(bf_ctx_get_ns(), ns))
            bf_abort("failed to restore previous namespaces, aborting");
    }

    if (bf_opts_persist()) {
        r = bf_handle_pin(cgen->handle, pindir_fd);
        if (r)
            return r;
    }

    return 0;
}

int bf_cgen_load(struct bf_cgen *cgen)
{
    _free_bf_program_ struct bf_program *prog = NULL;
    _cleanup_close_ int pindir_fd = -1;
    int r;

    assert(cgen);

    if (bf_opts_persist()) {
        pindir_fd = _bf_cgen_get_chain_pindir_fd(cgen->chain->name);
        if (pindir_fd < 0)
            return pindir_fd;
    }

    r = bf_program_new(&prog, cgen->chain, cgen->handle);
    if (r < 0)
        return r;

    r = bf_program_generate(prog);
    if (r < 0)
        return bf_err_r(r, "failed to generate bf_program");

    r = bf_program_load(prog);
    if (r < 0)
        return bf_err_r(r, "failed to load the chain");

    if (bf_opts_persist()) {
        r = bf_handle_pin(cgen->handle, pindir_fd);
        if (r)
            return r;
    }

    bf_info("load %s", cgen->chain->name);
    bf_cgen_dump(cgen, EMPTY_PREFIX);

    return 0;
}

int bf_cgen_attach(struct bf_cgen *cgen, const struct bf_ns *ns,
                   struct bf_hookopts **hookopts)
{
    _cleanup_close_ int pindir_fd = -1;
    int r;

    assert(cgen);
    assert(ns);
    assert(hookopts);

    bf_info("attaching %s to %s", cgen->chain->name,
            bf_hook_to_str(cgen->chain->hook));
    bf_hookopts_dump(*hookopts, EMPTY_PREFIX);

    if (bf_opts_persist()) {
        pindir_fd = _bf_cgen_get_chain_pindir_fd(cgen->chain->name);
        if (pindir_fd < 0)
            return pindir_fd;
    }

    r = bf_ns_set(ns, bf_ctx_get_ns());
    if (r)
        return bf_err_r(r, "failed to switch to the client's namespaces");

    r = bf_handle_attach(cgen->handle, cgen->chain->hook, hookopts);
    if (r < 0)
        return bf_err_r(r, "failed to attach chain '%s'", cgen->chain->name);

    if (bf_ns_set(bf_ctx_get_ns(), ns))
        bf_abort("failed to restore previous namespaces, aborting");

    if (bf_opts_persist()) {
        r = bf_link_pin(cgen->handle->link, pindir_fd);
        if (r) {
            bf_handle_detach(cgen->handle);
            return r;
        }
    }

    return r;
}

/**
 * @brief Transfer all counters from old handle to new handle.
 *
 * Copies counter values 1:1 for all rule counters plus policy and error
 * counters. The old and new chains must have the same number of rules.
 * Both handles must be loaded.
 *
 * @param old_handle Handle with the source counter map. Can't be NULL.
 * @param new_handle Handle with the destination counter map. Can't be NULL.
 * @param n_rules Number of rules in the chain.
 * @return 0 on success, or a negative errno value on failure.
 */
static int _bf_cgen_transfer_counters(const struct bf_handle *old_handle,
                                      struct bf_handle *new_handle,
                                      size_t n_rules)
{
    int r;

    assert(old_handle);
    assert(new_handle);

    if (!old_handle->cmap || !new_handle->cmap)
        return bf_err_r(-ENOENT, "missing counter map for counter transfer");

    // n_rules entries for rules, +1 for policy, +1 for errors.
    for (uint32_t i = 0; i < n_rules + 2; ++i) {
        struct bf_counter counter;

        r = bf_handle_get_counter(old_handle, i, &counter);
        if (r)
            return bf_err_r(r, "failed to read counter %u", i);

        if (!counter.count && !counter.size)
            continue;

        r = bf_map_set_elem(new_handle->cmap, &i, &counter);
        if (r)
            return bf_err_r(r, "failed to write counter %u", i);
    }

    return 0;
}

int bf_cgen_update(struct bf_cgen *cgen, struct bf_chain **new_chain,
                   uint32_t flags)
{
    _free_bf_program_ struct bf_program *new_prog = NULL;
    _free_bf_handle_ struct bf_handle *new_handle = NULL;
    _cleanup_close_ int pindir_fd = -1;
    struct bf_handle *old_handle;
    int r;

    assert(cgen);
    assert(new_chain);

    if (flags & ~BF_FLAGS_MASK(_BF_CGEN_UPDATE_MAX))
        return bf_err_r(-EINVAL, "unknown update flags: 0x%x", flags);

    old_handle = cgen->handle;

    if (bf_opts_persist()) {
        pindir_fd = _bf_cgen_get_chain_pindir_fd((*new_chain)->name);
        if (pindir_fd < 0)
            return pindir_fd;
    }

    r = bf_handle_new(&new_handle, _BF_PROG_NAME);
    if (r)
        return r;

    r = bf_program_new(&new_prog, *new_chain, new_handle);
    if (r < 0)
        return bf_err_r(r, "failed to create a new bf_program");

    r = bf_program_generate(new_prog);
    if (r < 0) {
        return bf_err_r(r,
                        "failed to generate the bytecode for a new bf_program");
    }

    r = bf_program_load(new_prog);
    if (r)
        return bf_err_r(r, "failed to load new program");

    if (flags & BF_FLAG(BF_CGEN_UPDATE_PRESERVE_COUNTERS)) {
        if (bf_list_size(&cgen->chain->rules) !=
            bf_list_size(&(*new_chain)->rules)) {
            return bf_err_r(-EINVAL,
                            "rule count mismatch for counter transfer");
        }

        r = _bf_cgen_transfer_counters(old_handle, new_handle,
                                       bf_list_size(&(*new_chain)->rules));
        if (r)
            return bf_err_r(r, "failed to transfer counters");
    }

    if (bf_opts_persist())
        bf_handle_unpin(old_handle, pindir_fd);

    if (old_handle->link) {
        r = bf_link_update(old_handle->link, new_handle->prog_fd);
        if (r) {
            bf_err_r(r, "failed to update bf_link object with new program");
            if (bf_opts_persist() && bf_handle_pin(old_handle, pindir_fd) < 0)
                bf_err("failed to repin old handle, ignoring");
            return r;
        }

        // We updated the old link, we need to store it in the new handle
        bf_swap(new_handle->link, old_handle->link);
    }

    if (bf_opts_persist()) {
        r = bf_handle_pin(new_handle, pindir_fd);
        if (r)
            bf_warn_r(r, "failed to pin new handle, ignoring");
    }

    bf_swap(cgen->handle, new_handle);

    bf_chain_free(&cgen->chain);
    cgen->chain = TAKE_PTR(*new_chain);

    return 0;
}

void bf_cgen_detach(struct bf_cgen *cgen)
{
    assert(cgen);

    bf_handle_detach(cgen->handle);
}

void bf_cgen_unload(struct bf_cgen *cgen)
{
    _cleanup_close_ int chain_fd = -1;

    assert(cgen);

    chain_fd = _bf_cgen_get_chain_pindir_fd(cgen->chain->name);
    if (chain_fd < 0) {
        bf_err_r(chain_fd, "failed to open pin directory for '%s'",
                 cgen->chain->name);
        return;
    }

    // The chain's pin directory will be removed in bf_cgen_free()
    bf_handle_unpin(cgen->handle, chain_fd);
    bf_handle_unload(cgen->handle);
}

int bf_cgen_get_counters(const struct bf_cgen *cgen, bf_list *counters)
{
    bf_list _counters;
    int r;

    assert(cgen);
    assert(counters);

    _counters = bf_list_default_from(*counters);

    /* Iterate over all the rules, then the policy counter (size(rules)) and
     * the errors counters (sizeof(rules) + 1)*/
    for (size_t i = 0; i < bf_list_size(&cgen->chain->rules) + 2; ++i) {
        _free_bf_counter_ struct bf_counter *counter = NULL;
        ssize_t idx = (ssize_t)i;

        if (i == bf_list_size(&cgen->chain->rules))
            idx = BF_COUNTER_POLICY;
        else if (i == bf_list_size(&cgen->chain->rules) + 1)
            idx = BF_COUNTER_ERRORS;

        r = bf_counter_new(&counter, 0, 0);
        if (r)
            return r;

        r = bf_cgen_get_counter(cgen, idx, counter);
        if (r)
            return r;

        r = bf_list_add_tail(&_counters, counter);
        if (r)
            return r;

        TAKE_PTR(counter);
    }

    *counters = bf_list_move(_counters);

    return 0;
}
