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

#include <bpfilter/bpf.h>
#include <bpfilter/chain.h>
#include <bpfilter/counter.h>
#include <bpfilter/dump.h>
#include <bpfilter/front.h>
#include <bpfilter/helper.h>
#include <bpfilter/hook.h>
#include <bpfilter/io.h>
#include <bpfilter/list.h>
#include <bpfilter/logger.h>
#include <bpfilter/matcher.h>
#include <bpfilter/ns.h>
#include <bpfilter/pack.h>
#include <bpfilter/rule.h>
#include <bpfilter/set.h>

#include "cgen/dump.h"
#include "cgen/prog/link.h"
#include "cgen/prog/map.h"
#include "cgen/program.h"
#include "ctx.h"
#include "opts.h"

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
    assert(cgen);
    assert(chain);

    *cgen = malloc(sizeof(struct bf_cgen));
    if (!*cgen)
        return -ENOMEM;

    (*cgen)->front = front;
    (*cgen)->program = NULL;
    (*cgen)->chain = NULL;
    (*cgen)->chain = TAKE_PTR(*chain);

    return 0;
}

int bf_cgen_new_from_pack(struct bf_cgen **cgen, bf_rpack_node_t node)
{
    _free_bf_cgen_ struct bf_cgen *_cgen = NULL;
    bf_rpack_node_t child;
    int r;

    assert(cgen);

    _cgen = malloc(sizeof(*_cgen));
    if (!_cgen)
        return -ENOMEM;

    _cgen->program = NULL;

    r = bf_rpack_kv_enum(node, "front", &_cgen->front, 0, _BF_FRONT_MAX);
    if (r)
        return bf_rpack_key_err(r, "bf_cgen.front");

    r = bf_rpack_kv_obj(node, "chain", &child);
    if (r)
        return bf_rpack_key_err(r, "bf_cgen.chain");

    r = bf_chain_new_from_pack(&_cgen->chain, child);
    if (r)
        return bf_rpack_key_err(r, "bf_cgen.chain");

    r = bf_rpack_kv_node(node, "program", &child);
    if (r)
        return bf_rpack_key_err(r, "bf_cgen.program");
    if (!bf_rpack_is_nil(child)) {
        _cleanup_close_ int dir_fd = -1;

        if ((dir_fd = _bf_cgen_get_chain_pindir_fd(_cgen->chain->name)) < 0) {
            return bf_err_r(dir_fd,
                            "failed to open chain pin directory for '%s'",
                            _cgen->chain->name);
        }

        r = bf_program_new_from_pack(&_cgen->program, _cgen->chain, dir_fd,
                                     child);
        if (r)
            return r;
    }

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

    bf_program_free(&(*cgen)->program);
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

    if (cgen->program) {
        bf_wpack_open_object(pack, "program");
        bf_program_pack(cgen->program, pack);
        bf_wpack_close_object(pack);
    } else {
        bf_wpack_kv_nil(pack, "program");
    }

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

    return bf_program_get_counter(cgen->program, counter_idx, counter);
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

    r = bf_program_new(&prog, cgen->chain);
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

        r = bf_program_attach(prog, hookopts);
        if (r < 0)
            return bf_err_r(r, "failed to load and attach the chain");

        if (bf_ns_set(bf_ctx_get_ns(), ns))
            bf_abort("failed to restore previous namespaces, aborting");
    }

    if (bf_opts_persist()) {
        r = bf_program_pin(prog, pindir_fd);
        if (r)
            return r;
    }

    cgen->program = TAKE_PTR(prog);

    return r;
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

    r = bf_program_new(&prog, cgen->chain);
    if (r < 0)
        return r;

    r = bf_program_generate(prog);
    if (r < 0)
        return bf_err_r(r, "failed to generate bf_program");

    r = bf_program_load(prog);
    if (r < 0)
        return bf_err_r(r, "failed to load the chain");

    if (bf_opts_persist()) {
        r = bf_program_pin(prog, pindir_fd);
        if (r)
            return r;
    }

    bf_info("load %s", cgen->chain->name);
    bf_cgen_dump(cgen, EMPTY_PREFIX);

    cgen->program = TAKE_PTR(prog);

    return r;
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

    r = bf_program_attach(cgen->program, hookopts);
    if (r < 0)
        return bf_err_r(r, "failed to attach chain '%s'", cgen->chain->name);

    if (bf_ns_set(bf_ctx_get_ns(), ns))
        bf_abort("failed to restore previous namespaces, aborting");

    if (bf_opts_persist()) {
        r = bf_link_pin(cgen->program->link, pindir_fd);
        if (r) {
            bf_program_detach(cgen->program);
            return r;
        }
    }

    return r;
}

/**
 * @brief Compute a content hash for a set.
 *
 * Hashes the key definition and a commutative sum of element hashes to
 * produce a position-independent identifier. Element order does not
 * affect the result.
 *
 * @param set Set to hash. Can't be NULL.
 * @return 64-bit hash.
 */
static uint64_t _bf_set_hash(const struct bf_set *set)
{
    uint64_t hash = BF_FNV1A_INIT;
    uint64_t elem_sum = 0;

    assert(set);

    hash = bf_fnv1a(&set->n_comps, sizeof(set->n_comps), hash);
    hash =
        bf_fnv1a(set->key, set->n_comps * sizeof(enum bf_matcher_type), hash);

    bf_list_foreach (&set->elems, elem_node) {
        elem_sum += bf_fnv1a(bf_list_node_get_data(elem_node),
                             set->elem_size, BF_FNV1A_INIT);
    }

    hash = bf_fnv1a(&elem_sum, sizeof(elem_sum), hash);

    return hash;
}

struct _bf_hash_entry
{
    uint64_t hash;
    size_t index;
    const void *data;

    // Prevents duplicate entries from mapping to the same old entry.
    bool matched;
};

static int _bf_hash_entry_cmp(const void *lhs, const void *rhs)
{
    const struct _bf_hash_entry *entry_l = lhs;
    const struct _bf_hash_entry *entry_r = rhs;

    // Avoids unsigned overflow from naive subtraction.
    return (entry_l->hash > entry_r->hash) - (entry_l->hash < entry_r->hash);
}

/**
 * @brief Build a mapping from new set indices to old set indices.
 *
 * Sorts old sets by hash and binary-searches for each new set.
 * Hash matches are verified with full sorted element comparison
 * for deterministic correctness.
 *
 * @param old_chain Old chain. Can't be NULL.
 * @param new_chain New chain. Can't be NULL.
 * @param set_map On success, the caller will own a mapping array where
 *        set_map[new_idx] is the matching old index, or -1 if unmatched.
 *        NULL if the new chain has no sets. Can't be NULL.
 * @return 0 on success, or a negative errno value on failure.
 */
static int _bf_cgen_build_set_mapping(const struct bf_chain *old_chain,
                                      const struct bf_chain *new_chain,
                                      int **set_map)
{
    _cleanup_free_ struct _bf_hash_entry *old_entries = NULL;
    _cleanup_free_ int *_map = NULL;
    size_t old_n;
    size_t new_n;
    size_t new_idx = 0;
    size_t i = 0;

    assert(old_chain);
    assert(new_chain);
    assert(set_map);

    old_n = bf_list_size(&old_chain->sets);
    new_n = bf_list_size(&new_chain->sets);

    if (new_n == 0)
        return 0;

    _map = malloc(new_n * sizeof(*_map));
    if (!_map)
        return -ENOMEM;

    for (i = 0; i < new_n; ++i)
        _map[i] = -1;

    if (old_n == 0) {
        *set_map = TAKE_PTR(_map);
        return 0;
    }

    old_entries = calloc(old_n, sizeof(*old_entries));
    if (!old_entries)
        return -ENOMEM;

    i = 0;
    bf_list_foreach (&old_chain->sets, set_node) {
        const struct bf_set *set = bf_list_node_get_data(set_node);
        old_entries[i].data = set;
        old_entries[i].hash = _bf_set_hash(set);
        old_entries[i].index = i;
        old_entries[i].matched = false;
        ++i;
    }

    qsort(old_entries, old_n, sizeof(*old_entries), _bf_hash_entry_cmp);

    bf_list_foreach (&new_chain->sets, set_node) {
        const struct bf_set *new_set = bf_list_node_get_data(set_node);
        uint64_t new_hash = _bf_set_hash(new_set);

        size_t low = 0, high = old_n;
        while (low < high) {
            size_t mid = low + ((high - low) / 2);
            if (old_entries[mid].hash < new_hash)
                low = mid + 1;
            else
                high = mid;
        }

        for (size_t k = low; k < old_n && old_entries[k].hash == new_hash; ++k) {
            int equal;

            if (old_entries[k].matched)
                continue;

            equal = bf_set_equal(old_entries[k].data, new_set);
            if (equal < 0)
                return equal;
            if (!equal)
                continue;

            _map[new_idx] = (int)old_entries[k].index;
            old_entries[k].matched = true;
            break;
        }

        ++new_idx;
    }

    *set_map = TAKE_PTR(_map);

    return 0;
}

/**
 * @brief Hash a rule's content for matching.
 *
 * Matcher hashes are summed (commutative) so matcher order does not
 * affect the result. For set matchers, if a mapping is provided, the
 * mapped index is hashed; otherwise the raw set index is hashed.
 *
 * @param rule Rule to hash. Can't be NULL.
 * @param chain Chain the rule belongs to (for set count). Can't be NULL.
 * @param set_map Set index mapping, or NULL to hash raw set indices.
 * @return 64-bit content hash.
 */
static uint64_t _bf_rule_hash(const struct bf_rule *rule,
                              const struct bf_chain *chain, const int *set_map)
{
    uint64_t hash = BF_FNV1A_INIT;
    uint64_t matcher_sum = 0;

    assert(rule);
    assert(chain);

    hash = bf_fnv1a(&rule->log, sizeof(rule->log), hash);
    hash = bf_fnv1a(&rule->mark, sizeof(rule->mark), hash);
    hash = bf_fnv1a(&rule->counters, sizeof(rule->counters), hash);
    hash = bf_fnv1a(&rule->verdict, sizeof(rule->verdict), hash);
    hash =
        bf_fnv1a(&rule->redirect_ifindex, sizeof(rule->redirect_ifindex), hash);
    hash = bf_fnv1a(&rule->redirect_dir, sizeof(rule->redirect_dir), hash);

    bf_list_foreach (&rule->matchers, matcher_node) {
        const struct bf_matcher *matcher = bf_list_node_get_data(matcher_node);
        enum bf_matcher_type type = bf_matcher_get_type(matcher);
        enum bf_matcher_op op = bf_matcher_get_op(matcher);
        uint64_t matcher_hash = BF_FNV1A_INIT;

        matcher_hash = bf_fnv1a(&type, sizeof(type), matcher_hash);
        matcher_hash = bf_fnv1a(&op, sizeof(op), matcher_hash);

        if (type == BF_MATCHER_SET) {
            uint32_t set_idx = *(const uint32_t *)bf_matcher_payload(matcher);
            uint32_t hash_idx = set_idx;

            if (set_map && set_idx < bf_list_size(&chain->sets) &&
                set_map[set_idx] >= 0)
                hash_idx = (uint32_t)set_map[set_idx];

            matcher_hash = bf_fnv1a(&hash_idx, sizeof(hash_idx), matcher_hash);
        } else {
            matcher_hash =
                bf_fnv1a(bf_matcher_payload(matcher),
                         bf_matcher_payload_len(matcher), matcher_hash);
        }

        matcher_sum += matcher_hash;
    }

    hash = bf_fnv1a(&matcher_sum, sizeof(matcher_sum), hash);

    return hash;
}

/**
 * @brief Compare two matchers for equality, resolving set indices via
 *        the pre-computed set mapping.
 *
 * @param old_matcher Matcher from the old chain. Can't be NULL.
 * @param new_matcher Matcher from the new chain. Can't be NULL.
 * @param set_map Set index mapping (new to old), or NULL if no sets.
 * @param new_n_sets Number of sets in the new chain.
 * @return True if the matchers are equal.
 */
static bool _bf_matcher_equal(const struct bf_matcher *old_matcher,
                              const struct bf_matcher *new_matcher,
                              const int *set_map, size_t new_n_sets)
{
    assert(old_matcher);
    assert(new_matcher);

    if (bf_matcher_get_type(old_matcher) != bf_matcher_get_type(new_matcher))
        return false;
    if (bf_matcher_get_op(old_matcher) != bf_matcher_get_op(new_matcher))
        return false;
    if (bf_matcher_payload_len(old_matcher) !=
        bf_matcher_payload_len(new_matcher))
        return false;

    if (bf_matcher_get_type(old_matcher) == BF_MATCHER_SET) {
        uint32_t idx_old = *(const uint32_t *)bf_matcher_payload(old_matcher);
        uint32_t idx_new = *(const uint32_t *)bf_matcher_payload(new_matcher);

        if (!set_map || idx_new >= new_n_sets)
            return false;
        if (set_map[idx_new] < 0)
            return false;

        return (uint32_t)set_map[idx_new] == idx_old;
    }

    return memcmp(bf_matcher_payload(old_matcher),
                  bf_matcher_payload(new_matcher),
                  bf_matcher_payload_len(old_matcher)) == 0;
}

/**
 * @brief Check if two rules are content-equal with order-independent
 *        matcher comparison and set-aware matching.
 *
 * @param old_rule Rule from the old chain. Can't be NULL.
 * @param new_rule Rule from the new chain. Can't be NULL.
 * @param set_map Set index mapping (new to old), or NULL if no sets.
 * @param new_n_sets Number of sets in the new chain.
 * @return True if the rules are content-equal.
 */
static bool _bf_rules_equal(const struct bf_rule *old_rule,
                            const struct bf_rule *new_rule, const int *set_map,
                            size_t new_n_sets)
{
    size_t n;

    assert(old_rule);
    assert(new_rule);

    if (old_rule->log != new_rule->log || old_rule->mark != new_rule->mark ||
        old_rule->counters != new_rule->counters ||
        old_rule->verdict != new_rule->verdict ||
        old_rule->redirect_ifindex != new_rule->redirect_ifindex ||
        old_rule->redirect_dir != new_rule->redirect_dir)
        return false;

    n = bf_list_size(&old_rule->matchers);
    if (bf_list_size(&new_rule->matchers) != n)
        return false;

    if (n == 0)
        return true;

    bool used[n];
    memset(used, 0, sizeof(used));

    bf_list_foreach (&old_rule->matchers, a_node) {
        const struct bf_matcher *old_m = bf_list_node_get_data(a_node);
        bool found = false;
        size_t idx = 0;

        bf_list_foreach (&new_rule->matchers, b_node) {
            const struct bf_matcher *new_m = bf_list_node_get_data(b_node);

            if (!used[idx] &&
                _bf_matcher_equal(old_m, new_m, set_map, new_n_sets)) {
                used[idx] = true;
                found = true;
                break;
            }
            ++idx;
        }

        if (!found)
            return false;
    }

    return true;
}

/**
 * @brief Build a mapping from new rule indices to old rule indices
 *        based on content hashing.
 *
 * Returns an array where counter_map[new_idx] = old_idx, or -1 if the
 * new rule has no match. The last two entries map the policy and error
 * counters.
 *
 * @param old_chain Old chain. Can't be NULL.
 * @param new_chain New chain. Can't be NULL.
 * @param counter_map On success, the caller will own a mapping array
 *        of size new_rule_count + 2. Can't be NULL.
 * @return 0 on success, or a negative errno value on failure.
 */
static int _bf_cgen_build_counter_mappings(const struct bf_chain *old_chain,
                                           const struct bf_chain *new_chain,
                                           int **counter_map)
{
    _cleanup_free_ int *set_map = NULL;
    _cleanup_free_ struct _bf_hash_entry *old_entries = NULL;
    _cleanup_free_ int *_map = NULL;
    size_t old_n;
    size_t new_n;
    size_t new_n_sets;
    size_t map_size;
    size_t i = 0;
    int r;

    assert(old_chain);
    assert(new_chain);
    assert(counter_map);

    old_n = bf_list_size(&old_chain->rules);
    new_n = bf_list_size(&new_chain->rules);
    new_n_sets = bf_list_size(&new_chain->sets);
    map_size = new_n + 2;

    _map = malloc(map_size * sizeof(*_map));
    if (!_map)
        return -ENOMEM;

    for (i = 0; i < map_size; ++i)
        _map[i] = -1;

    // Policy and error counters always map: they sit after the rule
    // counters at indices rule_count and rule_count+1.
    _map[new_n] = (int)old_n;
    _map[new_n + 1] = (int)(old_n + 1);

    if (old_n == 0 || new_n == 0) {
        *counter_map = TAKE_PTR(_map);
        return 0;
    }

    r = _bf_cgen_build_set_mapping(old_chain, new_chain, &set_map);
    if (r)
        return r;

    old_entries = calloc(old_n, sizeof(*old_entries));
    if (!old_entries)
        return -ENOMEM;

    i = 0;
    bf_list_foreach (&old_chain->rules, rule_node) {
        const struct bf_rule *rule = bf_list_node_get_data(rule_node);
        old_entries[i].hash = _bf_rule_hash(rule, old_chain, NULL);
        old_entries[i].index = rule->index;
        old_entries[i].data = rule;
        old_entries[i].matched = false;
        ++i;
    }

    qsort(old_entries, old_n, sizeof(*old_entries), _bf_hash_entry_cmp);

    bf_list_foreach (&new_chain->rules, rule_node) {
        const struct bf_rule *new_rule = bf_list_node_get_data(rule_node);
        uint64_t new_hash = _bf_rule_hash(new_rule, new_chain, set_map);

        size_t low = 0, high = old_n;
        while (low < high) {
            size_t mid = low + ((high - low) / 2);
            if (old_entries[mid].hash < new_hash)
                low = mid + 1;
            else
                high = mid;
        }

        for (size_t k = low; k < old_n && old_entries[k].hash == new_hash;
             ++k) {
            // Skip already-matched entries to handle duplicate rules
            if (old_entries[k].matched)
                continue;

            if (!_bf_rules_equal(old_entries[k].data, new_rule, set_map,
                                 new_n_sets))
                continue;

            old_entries[k].matched = true;
            _map[new_rule->index] = (int)old_entries[k].index;
            break;
        }
    }

    *counter_map = TAKE_PTR(_map);

    return 0;
}

/**
 * @brief Transfer counters from old program to new program.
 *
 * @param old_prog Old program to read counters from. Can't be NULL.
 * @param new_prog New program to write counters into. Can't be NULL.
 * @param counter_map Mapping array where counter_map[new_idx] = old_idx,
 *        or -1 if unmatched. Can't be NULL.
 * @param map_size Number of entries in counter_map.
 * @return 0 on success, or a negative errno value on failure.
 */
static int _bf_cgen_transfer_counters(const struct bf_program *old_prog,
                                      struct bf_program *new_prog,
                                      const int *counter_map, size_t map_size)
{
    assert(old_prog);
    assert(new_prog);
    assert(counter_map);

    for (size_t i = 0; i < map_size; ++i) {
        struct bf_counter counter = {};
        uint32_t new_idx = i;
        int r;

        if (counter_map[i] < 0)
            continue;

        r = bf_program_get_counter(old_prog, counter_map[i], &counter);
        if (r)
            return bf_err_r(r, "failed to read old counter %d", counter_map[i]);

        if (counter.packets == 0 && counter.bytes == 0)
            continue;

        r = bf_bpf_map_update_elem(new_prog->cmap->fd, &new_idx, &counter, 0);
        if (r)
            return bf_err_r(r, "failed to write counter %u", new_idx);
    }

    return 0;
}

int bf_cgen_update(struct bf_cgen *cgen, struct bf_chain **new_chain)
{
    _free_bf_program_ struct bf_program *new_prog = NULL;
    _cleanup_free_ int *counter_map = NULL;
    _cleanup_close_ int pindir_fd = -1;
    struct bf_program *old_prog;
    int r;

    assert(cgen);
    assert(new_chain);

    old_prog = cgen->program;

    if (bf_opts_persist()) {
        pindir_fd = _bf_cgen_get_chain_pindir_fd((*new_chain)->name);
        if (pindir_fd < 0)
            return pindir_fd;
    }

    r = bf_program_new(&new_prog, *new_chain);
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

    r = _bf_cgen_build_counter_mappings(cgen->chain, *new_chain, &counter_map);
    if (r)
        return bf_err_r(r, "failed to build counter mappings for update");

    r = _bf_cgen_transfer_counters(old_prog, new_prog, counter_map,
                                   bf_list_size(&(*new_chain)->rules) + 2);
    if (r)
        return bf_err_r(r, "failed to transfer counters for update");

    if (bf_opts_persist())
        bf_program_unpin(old_prog, pindir_fd);

    if (old_prog->link->hookopts) {
        // Chain is currently attached, update the link to use new program
        r = bf_link_update(old_prog->link, cgen->chain->hook,
                           new_prog->runtime.prog_fd);
        if (r) {
            bf_err_r(r, "failed to update bf_link object with new program");
            if (bf_opts_persist() && bf_program_pin(old_prog, pindir_fd) < 0)
                bf_err("failed to repin old program, ignoring");
            return r;
        }

        // We updated the old link, we need to store it in the new program
        bf_swap(new_prog->link, old_prog->link);
    }

    if (bf_opts_persist()) {
        r = bf_program_pin(new_prog, pindir_fd);
        if (r)
            bf_warn_r(r, "failed to pin new prog, ignoring");
    }

    bf_swap(cgen->program, new_prog);

    bf_chain_free(&cgen->chain);
    cgen->chain = TAKE_PTR(*new_chain);

    return 0;
}

void bf_cgen_detach(struct bf_cgen *cgen)
{
    assert(cgen);

    bf_program_detach(cgen->program);
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
    bf_program_unpin(cgen->program, chain_fd);
    bf_program_unload(cgen->program);
}

int bf_cgen_get_counters(const struct bf_cgen *cgen, bf_list *counters)
{
    bf_list _counters = bf_list_default_from(*counters);
    int r;

    assert(cgen);
    assert(counters);

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
