/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#include "cgen/cgen.h"

#include <linux/bpf.h>

#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

#include <bpfilter/bpf.h>
#include <bpfilter/chain.h>
#include <bpfilter/core/hashset.h>
#include <bpfilter/core/list.h>
#include <bpfilter/counter.h>
#include <bpfilter/dump.h>
#include <bpfilter/helper.h>
#include <bpfilter/hook.h>
#include <bpfilter/logger.h>
#include <bpfilter/pack.h>
#include <bpfilter/rule.h>
#include <bpfilter/set.h>

#include "cgen/dump.h"
#include "cgen/handle.h"
#include "cgen/prog/link.h"
#include "cgen/prog/map.h"
#include "cgen/program.h"
#include "cgen/set_group.h"
#include "core/lock.h"

#define _BF_PROG_NAME "bf_prog"
#define _BF_CTX_PIN_NAME "bf_ctx"
#define _BF_CTX_TMP_PIN_NAME "bf_ctx_tmp"

/**
 * @brief Persist the codegen state to a BPF context map in bpffs.
 *
 * Serializes the cgen, creates a `BPF_MAP_TYPE_ARRAY` map with 1 entry
 * containing the serialized data, pins it as `bf_ctx_tmp`, then atomically
 * renames to `bf_ctx`. The map fd is closed after pinning - this is a
 * one-shot operation.
 *
 * @param cgen Codegen to persist. Can't be NULL.
 * @param dir_fd File descriptor of the chain's bpffs pin directory. Must be
 *        valid.
 * @return 0 on success, or negative errno value on failure.
 */
static int _bf_cgen_persist(const struct bf_cgen *cgen, int dir_fd)
{
    _free_bf_wpack_ bf_wpack_t *pack = NULL;
    _free_bf_map_ struct bf_map *map = NULL;
    const void *data;
    size_t data_len;
    uint32_t key = 0;
    int r;

    assert(cgen);

    r = bf_wpack_new(&pack);
    if (r)
        return bf_err_r(r, "failed to create wpack for bf_cgen");

    r = bf_cgen_pack(cgen, pack);
    if (r)
        return bf_err_r(r, "failed to pack bf_cgen");

    r = bf_wpack_get_data(pack, &data, &data_len);
    if (r)
        return bf_err_r(r, "failed to get data from bf_cgen wpack");

    r = bf_map_new(&map, _BF_CTX_PIN_NAME, BF_MAP_TYPE_CTX, sizeof(uint32_t),
                   data_len, 1);
    if (r)
        return bf_err_r(r, "failed to create context map");

    r = bf_map_set_elem(map, &key, (void *)data);
    if (r)
        return bf_err_r(r, "failed to write context to map");

    // Remove stale temporary pin if present.
    unlinkat(dir_fd, _BF_CTX_TMP_PIN_NAME, 0);

    r = bf_bpf_obj_pin(_BF_CTX_TMP_PIN_NAME, map->fd, dir_fd);
    if (r)
        return bf_err_r(r, "failed to pin context map");

    r = renameat(dir_fd, _BF_CTX_TMP_PIN_NAME, dir_fd, _BF_CTX_PIN_NAME);
    if (r) {
        r = -errno;
        unlinkat(dir_fd, _BF_CTX_TMP_PIN_NAME, 0);
        return bf_err_r(r, "failed to atomically replace context map pin");
    }

    return 0;
}

static int _bf_cgen_new_from_pack(struct bf_cgen **cgen, struct bf_lock *lock,
                                  bf_rpack_node_t node)
{
    _free_bf_cgen_ struct bf_cgen *_cgen = NULL;
    bf_rpack_node_t child;
    int r;

    assert(cgen);
    assert(lock);

    _cgen = calloc(1, sizeof(*_cgen));
    if (!_cgen)
        return -ENOMEM;

    r = bf_rpack_kv_obj(node, "chain", &child);
    if (r)
        return bf_rpack_key_err(r, "bf_cgen.chain");

    r = bf_chain_new_from_pack(&_cgen->chain, child);
    if (r)
        return bf_rpack_key_err(r, "bf_cgen.chain");

    r = bf_rpack_kv_node(node, "handle", &child);
    if (r)
        return bf_rpack_key_err(r, "bf_cgen.handle");

    r = bf_handle_new_from_pack(&_cgen->handle, lock, child);
    if (r)
        return r;

    *cgen = TAKE_PTR(_cgen);

    return 0;
}

int bf_cgen_new_from_dir_fd(struct bf_cgen **cgen, struct bf_lock *lock)
{
    _free_bf_rpack_ bf_rpack_t *pack = NULL;
    _cleanup_close_ int map_fd = -1;
    _cleanup_free_ void *data = NULL;
    struct bpf_map_info info;
    uint32_t key = 0;
    int r;

    assert(cgen);
    assert(lock);

    r = bf_bpf_obj_get(_BF_CTX_PIN_NAME, lock->chain_fd, &map_fd);
    if (r < 0)
        return bf_err_r(r, "failed to open pinned context map");

    r = bf_bpf_map_get_info(map_fd, &info);
    if (r)
        return bf_err_r(r, "failed to get context map info");

    if (info.value_size == 0)
        return bf_err_r(-EINVAL, "invalid serialized context size");

    data = malloc(info.value_size);
    if (!data)
        return -ENOMEM;

    r = bf_bpf_map_lookup_elem(map_fd, &key, data);
    if (r)
        return bf_err_r(r, "failed to read context from map");

    r = bf_rpack_new(&pack, data, info.value_size);
    if (r)
        return bf_err_r(r, "failed to create rpack for bf_cgen");

    r = _bf_cgen_new_from_pack(cgen, lock, bf_rpack_root(pack));
    if (r)
        return bf_err_r(r, "failed to deserialize cgen from context map");

    return 0;
}

int bf_cgen_new(struct bf_cgen **cgen, struct bf_chain **chain)
{
    _free_bf_cgen_ struct bf_cgen *_cgen = NULL;
    int r;

    assert(cgen);
    assert(chain);

    _cgen = calloc(1, sizeof(*_cgen));
    if (!_cgen)
        return -ENOMEM;

    _cgen->chain = TAKE_PTR(*chain);

    r = bf_handle_new(&_cgen->handle, _BF_PROG_NAME);
    if (r)
        return r;

    *cgen = TAKE_PTR(_cgen);

    return 0;
}

void bf_cgen_free(struct bf_cgen **cgen)
{
    assert(cgen);

    if (!*cgen)
        return;

    bf_handle_free(&(*cgen)->handle);
    bf_chain_free(&(*cgen)->chain);

    free(*cgen);
    *cgen = NULL;
}

int bf_cgen_pack(const struct bf_cgen *cgen, bf_wpack_t *pack)
{
    assert(cgen);
    assert(pack);

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

int bf_cgen_load_counters(struct bf_cgen *cgen)
{
    int r;

    assert(cgen);

    bf_list_foreach (&cgen->chain->rules, rule_node) {
        struct bf_rule *rule = bf_list_node_get_data(rule_node);

        if (!rule->has_counters)
            continue;

        r = bf_cgen_get_counter(cgen, rule->index, &rule->counters);
        if (r) {
            return bf_err_r(r, "failed to load counter for rule %u",
                            rule->index);
        }
    }

    r = bf_cgen_get_counter(cgen, BF_COUNTER_POLICY,
                            &cgen->chain->policy_counters);
    if (r) {
        return bf_err_r(r, "failed to load policy counters for '%s'",
                        cgen->chain->name);
    }

    r = bf_cgen_get_counter(cgen, BF_COUNTER_ERRORS,
                            &cgen->chain->error_counters);
    if (r) {
        return bf_err_r(r, "failed to load error counters for '%s'",
                        cgen->chain->name);
    }

    return 0;
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

int bf_cgen_set(struct bf_cgen *cgen, struct bf_hookopts **hookopts,
                struct bf_lock *lock)
{
    _free_bf_program_ struct bf_program *prog = NULL;
    int r;

    assert(cgen);
    assert(lock);

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
        r = bf_handle_attach(cgen->handle, cgen->chain->hook, hookopts);
        if (r < 0)
            return bf_err_r(r, "failed to load and attach the chain");
    }

    r = bf_handle_pin(cgen->handle, lock);
    if (r)
        return r;

    r = _bf_cgen_persist(cgen, lock->chain_fd);
    if (r) {
        bf_handle_unpin(cgen->handle, lock);
        return bf_err_r(r, "failed to persist cgen for '%s'",
                        cgen->chain->name);
    }

    return 0;
}

int bf_cgen_load(struct bf_cgen *cgen, struct bf_lock *lock)
{
    _free_bf_program_ struct bf_program *prog = NULL;
    int r;

    assert(cgen);
    assert(lock);

    r = bf_program_new(&prog, cgen->chain, cgen->handle);
    if (r < 0)
        return r;

    r = bf_program_generate(prog);
    if (r < 0)
        return bf_err_r(r, "failed to generate bf_program");

    r = bf_program_load(prog);
    if (r < 0)
        return bf_err_r(r, "failed to load the chain");

    r = bf_handle_pin(cgen->handle, lock);
    if (r)
        return r;

    r = _bf_cgen_persist(cgen, lock->chain_fd);
    if (r) {
        bf_handle_unpin(cgen->handle, lock);
        return bf_err_r(r, "failed to persist cgen for '%s'",
                        cgen->chain->name);
    }

    bf_info("load %s", cgen->chain->name);
    bf_cgen_dump(cgen, EMPTY_PREFIX);

    return 0;
}

int bf_cgen_attach(struct bf_cgen *cgen, struct bf_hookopts **hookopts,
                   struct bf_lock *lock)
{
    int r;

    assert(cgen);
    assert(hookopts);
    assert(lock);

    bf_info("attaching %s to %s", cgen->chain->name,
            bf_hook_to_str(cgen->chain->hook));
    bf_hookopts_dump(*hookopts, EMPTY_PREFIX);

    r = bf_handle_attach(cgen->handle, cgen->chain->hook, hookopts);
    if (r < 0)
        return bf_err_r(r, "failed to attach chain '%s'", cgen->chain->name);

    r = bf_link_pin(cgen->handle->link, lock);
    if (r) {
        bf_handle_detach(cgen->handle);
        return r;
    }

    r = _bf_cgen_persist(cgen, lock->chain_fd);
    if (r) {
        bf_link_unpin(cgen->handle->link, lock);
        bf_handle_detach(cgen->handle);
        return bf_err_r(r, "failed to persist cgen for '%s'",
                        cgen->chain->name);
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

        r = bf_handle_set_counter(new_handle, i, &counter);
        if (r)
            return bf_err_r(r, "failed to write counter %u", i);
    }

    return 0;
}

int bf_cgen_update(struct bf_cgen *cgen, struct bf_chain **new_chain,
                   uint32_t flags, struct bf_lock *lock)
{
    _free_bf_program_ struct bf_program *new_prog = NULL;
    _free_bf_handle_ struct bf_handle *new_handle = NULL;
    struct bf_handle *old_handle;
    int r;

    assert(cgen);
    assert(new_chain);
    assert(lock);

    if (flags & ~BF_FLAGS_MASK(_BF_CGEN_UPDATE_MAX))
        return bf_err_r(-EINVAL, "unknown update flags: 0x%x", flags);

    old_handle = cgen->handle;

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

    bf_handle_unpin(old_handle, lock);

    if (old_handle->link) {
        r = bf_link_update(old_handle->link, new_handle->prog_fd);
        if (r) {
            bf_err_r(r, "failed to update bf_link object with new program");
            if (bf_handle_pin(old_handle, lock) < 0)
                bf_err("failed to repin old handle, ignoring");
            return r;
        }

        // We updated the old link, we need to store it in the new handle
        bf_swap(new_handle->link, old_handle->link);
    }

    bf_swap(cgen->handle, new_handle);

    r = bf_handle_pin(cgen->handle, lock);
    if (r)
        return bf_err_r(r, "failed to pin new handle");

    r = _bf_cgen_persist(cgen, lock->chain_fd);
    if (r) {
        bf_handle_unpin(cgen->handle, lock);
        return bf_err_r(r, "failed to persist cgen for '%s'",
                        cgen->chain->name);
    }

    bf_chain_free(&cgen->chain);
    cgen->chain = TAKE_PTR(*new_chain);

    r = _bf_cgen_persist(cgen, lock->chain_fd);
    if (r) {
        bf_handle_unpin(cgen->handle, lock);
        return bf_err_r(r, "failed to persist cgen for '%s'",
                        cgen->chain->name);
    }

    return 0;
}

/**
 * @brief Compute the elements a set update actually adds and removes.
 *
 * `added` receives the elements of `to_add` that are neither in `set` nor in
 * `to_remove`, and `removed` the elements of `to_remove` that are in `set`.
 * Applying `added` then `removed` to `set` has the same effect as applying
 * `to_add` then `to_remove`, and applying `removed` then `added` reverts it.
 *
 * @param set Set to update. Can't be NULL.
 * @param to_add Elements to add to `set`. Can't be NULL.
 * @param to_remove Elements to remove from `set`. Can't be NULL.
 * @param added On success, set to the elements the update adds to `set`.
 *        Can't be NULL.
 * @param removed On success, set to the elements the update removes from
 *        `set`. Can't be NULL.
 * @return 0 on success, or a negative errno value on failure.
 */
static int _bf_cgen_get_set_changes(const struct bf_set *set,
                                    const struct bf_set *to_add,
                                    const struct bf_set *to_remove,
                                    struct bf_set **added,
                                    struct bf_set **removed)
{
    _free_bf_set_ struct bf_set *_added = NULL;
    _free_bf_set_ struct bf_set *_removed = NULL;
    int r;

    assert(set);
    assert(to_add);
    assert(to_remove);
    assert(added);
    assert(removed);

    r = bf_set_new(&_added, NULL, set->key, set->n_comps);
    if (r)
        return r;

    r = bf_set_new(&_removed, NULL, set->key, set->n_comps);
    if (r)
        return r;

    bf_hashset_foreach (&to_add->elems, elem) {
        if (bf_hashset_contains(&set->elems, elem->data) ||
            bf_hashset_contains(&to_remove->elems, elem->data))
            continue;

        r = bf_set_add_elem(_added, elem->data);
        if (r)
            return r;
    }

    bf_hashset_foreach (&to_remove->elems, elem) {
        if (!bf_hashset_contains(&set->elems, elem->data))
            continue;

        r = bf_set_add_elem(_removed, elem->data);
        if (r)
            return r;
    }

    *added = TAKE_PTR(_added);
    *removed = TAKE_PTR(_removed);

    return 0;
}

/**
 * @brief Get the loaded map backing a set, to update the set in place.
 *
 * The groups built from the chain are the groups of the loaded program, as
 * long as the sets that need a map didn't change: the set's group is then
 * backed by the map at the same index in the handle.
 *
 * @param cgen Codegen of the loaded program. Can't be NULL.
 * @param groups Set groups built from the codegen's chain. Can't be NULL.
 * @param set Set to find the map of, from the codegen's chain. Can't be NULL.
 * @param group On success, set to the group of `set`. Can't be NULL.
 * @return The map backing `set`, or NULL if no loaded map matches the set's
 *         group.
 */
static const struct bf_map *
_bf_cgen_get_set_map(const struct bf_cgen *cgen, const bf_list *groups,
                     const struct bf_set *set,
                     const struct bf_set_group **group)
{
    const struct bf_set_group *_group;
    const struct bf_map *map;
    size_t group_idx;

    assert(cgen);
    assert(groups);
    assert(set);
    assert(group);

    if (bf_list_size(groups) != bf_list_size(&cgen->handle->sets))
        return NULL;

    _group = bf_set_group_find(groups, set, &group_idx, NULL);
    if (!_group)
        return NULL;

    map = bf_list_get_at(&cgen->handle->sets, group_idx);
    if (!map || map->key_size != set->elem_size ||
        map->value_size != bf_set_group_value_size(_group))
        return NULL;

    *group = _group;

    return map;
}

/**
 * @brief Write the elements of a set update to the set's map.
 *
 * The value of each element is computed from the sets of `group`, which must
 * contain the updated set. Elements no set of the group contains anymore are
 * deleted from the map first, so the map never holds more elements than
 * before or after the update. The other elements are then written.
 *
 * @param map Map backing `group`. Can't be NULL.
 * @param group Group of the updated set. Can't be NULL.
 * @param added Elements added to the set. Can't be NULL.
 * @param removed Elements removed from the set. Can't be NULL.
 * @return 0 on success, or a negative errno value on failure. On failure, the
 *         map can be partially updated.
 */
static int _bf_cgen_write_set_changes(const struct bf_map *map,
                                      const struct bf_set_group *group,
                                      const struct bf_set *added,
                                      const struct bf_set *removed)
{
    const struct bf_set *changes[] = {added, removed};
    _cleanup_free_ uint8_t *value = NULL;
    int r;

    assert(map);
    assert(group);
    assert(added);
    assert(removed);

    value = malloc(bf_set_group_value_size(group));
    if (!value)
        return -ENOMEM;

    for (size_t i = 0; i < ARRAY_SIZE(changes); ++i) {
        bf_hashset_foreach (&changes[i]->elems, elem) {
            if (bf_set_group_elem_value(group, elem->data, value))
                continue;

            r = bf_bpf_map_delete_elem(map->fd, elem->data);
            if (r && r != -ENOENT)
                return bf_err_r(r, "failed to delete element from set map");
        }
    }

    for (size_t i = 0; i < ARRAY_SIZE(changes); ++i) {
        bf_hashset_foreach (&changes[i]->elems, elem) {
            if (!bf_set_group_elem_value(group, elem->data, value))
                continue;

            r = bf_bpf_map_update_elem(map->fd, elem->data, value, BPF_ANY);
            if (r)
                return bf_err_r(r, "failed to write element to set map");
        }
    }

    return 0;
}

/**
 * @brief Revert a set update written in place.
 *
 * The set is restored in the codegen's chain, then the elements of the update
 * are written back to the set's map.
 *
 * @param cgen Codegen containing the set. Can't be NULL.
 * @param set_name Name of the updated set. Can't be NULL.
 * @param map Map backing `group`. Can't be NULL.
 * @param group Group of the updated set. Can't be NULL.
 * @param added Elements the update added to the set. Can't be NULL.
 * @param removed Elements the update removed from the set. Can't be NULL.
 */
static void _bf_cgen_revert_set_changes(struct bf_cgen *cgen,
                                        const char *set_name,
                                        const struct bf_map *map,
                                        const struct bf_set_group *group,
                                        const struct bf_set *added,
                                        const struct bf_set *removed)
{
    int r;

    assert(cgen);
    assert(set_name);

    r = bf_chain_apply_set_delta(cgen->chain, set_name, removed, added);
    if (!r)
        r = _bf_cgen_write_set_changes(map, group, removed, added);
    if (r)
        bf_err_r(r, "failed to restore the map of set '%s'", set_name);
}

/**
 * @brief Update a set by regenerating the program.
 *
 * @param cgen Codegen to update. Can't be NULL.
 * @param to_add Elements to add to the set. Its name identifies the updated
 *        set. Can't be NULL.
 * @param to_remove Elements to remove from the set. Can't be NULL.
 * @param lock Lock providing the chain directory file descriptor. Can't be
 *        NULL.
 * @return 0 on success, or a negative errno value on failure.
 */
static int _bf_cgen_regen_set(struct bf_cgen *cgen, const struct bf_set *to_add,
                              const struct bf_set *to_remove,
                              struct bf_lock *lock)
{
    _free_bf_chain_ struct bf_chain *new_chain = NULL;
    int r;

    assert(cgen);
    assert(to_add);
    assert(to_remove);
    assert(lock);

    r = bf_chain_new_from_copy(&new_chain, cgen->chain);
    if (r)
        return r;

    r = bf_chain_apply_set_delta(new_chain, to_add->name, to_add, to_remove);
    if (r)
        return r;

    return bf_cgen_update(cgen, &new_chain,
                          BF_FLAG(BF_CGEN_UPDATE_PRESERVE_COUNTERS), lock);
}

int bf_cgen_update_set(struct bf_cgen *cgen, const struct bf_set *to_add,
                       const struct bf_set *to_remove, struct bf_lock *lock)
{
    _free_bf_set_ struct bf_set *added = NULL;
    _free_bf_set_ struct bf_set *removed = NULL;
    _clean_bf_list_ bf_list groups = bf_list_default(NULL, NULL);
    const struct bf_set_group *group = NULL;
    const struct bf_map *map = NULL;
    const struct bf_set *set;
    size_t n_elems;
    int r;

    assert(cgen);
    assert(to_add);
    assert(to_add->name);
    assert(to_remove);
    assert(lock);

    set = bf_chain_get_set_by_name(cgen->chain, to_add->name);
    if (!set)
        return bf_err_r(-ENOENT, "set '%s' does not exist", to_add->name);

    if (!bf_set_same_key(set, to_add) || !bf_set_same_key(set, to_remove))
        return bf_err_r(-EINVAL, "set key format mismatch");

    r = _bf_cgen_get_set_changes(set, to_add, to_remove, &added, &removed);
    if (r)
        return bf_err_r(r, "failed to compute the changes to set '%s'",
                        set->name);

    n_elems = bf_hashset_size(&set->elems) - bf_hashset_size(&removed->elems) +
              bf_hashset_size(&added->elems);

    /* Sets with a minimum size are always backed by a map, which has room for
     * at least `min_size` elements of the set, whatever the content of the
     * other sets of its group (see `_bf_program_load_sets_maps()`). */
    if (set->min_size && n_elems <= set->min_size) {
        r = bf_set_group_build(&groups, cgen->chain);
        if (r)
            return bf_err_r(r, "failed to build set groups");

        map = _bf_cgen_get_set_map(cgen, &groups, set, &group);
    }

    if (!map) {
        bf_dbg("set '%s' can't be updated in place, regenerating the program",
               set->name);
        return _bf_cgen_regen_set(cgen, to_add, to_remove, lock);
    }

    r = bf_chain_apply_set_delta(cgen->chain, set->name, added, removed);
    if (r)
        return bf_err_r(r, "failed to update set '%s'", set->name);

    r = _bf_cgen_write_set_changes(map, group, added, removed);
    if (r) {
        _bf_cgen_revert_set_changes(cgen, set->name, map, group, added,
                                    removed);
        return bf_err_r(r, "failed to update set '%s' in place", set->name);
    }

    r = _bf_cgen_persist(cgen, lock->chain_fd);
    if (r) {
        _bf_cgen_revert_set_changes(cgen, set->name, map, group, added,
                                    removed);
        return bf_err_r(r, "failed to persist cgen for '%s'",
                        cgen->chain->name);
    }

    bf_dbg("updated set '%s' in place", set->name);

    return 0;
}

void bf_cgen_detach(struct bf_cgen *cgen)
{
    assert(cgen);

    bf_handle_detach(cgen->handle);
}

void bf_cgen_unload(struct bf_cgen *cgen, struct bf_lock *lock)
{
    assert(cgen);
    assert(lock);

    /* The chain's pin directory will be removed by bf_lock_release_chain()
     * if a `BF_LOCK_WRITE` lock is held. */
    unlinkat(lock->chain_fd, _BF_CTX_PIN_NAME, 0);
    bf_handle_unpin(cgen->handle, lock);
    bf_handle_unload(cgen->handle);
}
