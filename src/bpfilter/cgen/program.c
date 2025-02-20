/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#include "bpfilter/cgen/program.h"

#include <linux/bpf.h>
#include <linux/bpf_common.h>
#include <linux/limits.h>

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "bpfilter/cgen/cgroup.h"
#include "bpfilter/cgen/dump.h"
#include "bpfilter/cgen/fixup.h"
#include "bpfilter/cgen/jmp.h"
#include "bpfilter/cgen/matcher/ip4.h"
#include "bpfilter/cgen/matcher/ip6.h"
#include "bpfilter/cgen/matcher/meta.h"
#include "bpfilter/cgen/matcher/set.h"
#include "bpfilter/cgen/matcher/tcp.h"
#include "bpfilter/cgen/matcher/udp.h"
#include "bpfilter/cgen/nf.h"
#include "bpfilter/cgen/printer.h"
#include "bpfilter/cgen/prog/map.h"
#include "bpfilter/cgen/stub.h"
#include "bpfilter/cgen/tc.h"
#include "bpfilter/cgen/xdp.h"
#include "bpfilter/ctx.h"
#include "core/bpf.h"
#include "core/btf.h"
#include "core/chain.h"
#include "core/counter.h"
#include "core/dump.h"
#include "core/flavor.h"
#include "core/front.h"
#include "core/helper.h"
#include "core/hook.h"
#include "core/io.h"
#include "core/list.h"
#include "core/logger.h"
#include "core/marsh.h"
#include "core/matcher.h"
#include "core/opts.h"
#include "core/rule.h"
#include "core/set.h"
#include "core/verdict.h"

#include "external/filter.h"
#include "external/murmur3.h"

#define _BF_PROGRAM_DEFAULT_IMG_SIZE (1 << 6)

static const struct bf_flavor_ops *bf_flavor_ops_get(enum bf_hook hook)
{
    static const struct bf_flavor_ops *flavor_ops[] = {
        [BF_HOOK_XDP] = &bf_flavor_ops_xdp,
        [BF_HOOK_TC_INGRESS] = &bf_flavor_ops_tc,
        [BF_HOOK_NF_PRE_ROUTING] = &bf_flavor_ops_nf,
        [BF_HOOK_NF_LOCAL_IN] = &bf_flavor_ops_nf,
        [BF_HOOK_NF_FORWARD] = &bf_flavor_ops_nf,
        [BF_HOOK_CGROUP_INGRESS] = &bf_flavor_ops_cgroup,
        [BF_HOOK_CGROUP_EGRESS] = &bf_flavor_ops_cgroup,
        [BF_HOOK_NF_LOCAL_OUT] = &bf_flavor_ops_nf,
        [BF_HOOK_NF_POST_ROUTING] = &bf_flavor_ops_nf,
        [BF_HOOK_TC_EGRESS] = &bf_flavor_ops_tc,
    };

    bf_assert(0 <= hook && hook < _BF_HOOK_MAX);
    static_assert(ARRAY_SIZE(flavor_ops) == _BF_HOOK_MAX,
                  "missing entries in flavors array");

    return flavor_ops[hook];
}

/**
 * Generate the program's identifier.
 *
 * A program's ID is a way to idenfity it: there shouldn't be two programs
 * with the same ID. This ID will be used when we need to avoid name clashes,
 * such as when the BPF objects are pinned to the system.
 *
 * The ID is composed of 3 parts:
 * - The @c bf prefix, as the ID will be used as a prefix for the BPF objects
 *   name.
 * - A hook idenfitier
 * - A hash of the unique property of the hook: multiple programs can be
 *   generated for a given hook, so we hash the data that make this specific
 *   program unique amongst other programs attached to the same hook.
 *
 * @param program Program to generate the ID for. Can't be NULL.
 * @return 0 on success, or a negative errno value on error.
 */
static int _bf_program_genid(struct bf_program *program)
{
    static const char *flavor_keys[] = {
        [BF_HOOK_XDP] = "xdp",
        [BF_HOOK_TC_INGRESS] = "tci",
        [BF_HOOK_NF_PRE_ROUTING] = "nfp",
        [BF_HOOK_NF_LOCAL_IN] = "nfi",
        [BF_HOOK_CGROUP_INGRESS] = "cgi",
        [BF_HOOK_CGROUP_EGRESS] = "cge",
        [BF_HOOK_NF_FORWARD] = "nff",
        [BF_HOOK_NF_LOCAL_OUT] = "nfo",
        [BF_HOOK_NF_POST_ROUTING] = "nfr",
        [BF_HOOK_TC_EGRESS] = "tce",
    };
    static_assert(ARRAY_SIZE(flavor_keys) == _BF_HOOK_MAX,
                  "missing entries in flavor_keys array");

    char buf[PATH_MAX];
    uint32_t hash;

    bf_assert(program);

    // If the chain has a name, use it as ID
    if (program->runtime.chain->hook_opts.used_opts & (1 << BF_HOOK_OPT_NAME)) {
        memcpy(program->id, program->runtime.chain->hook_opts.name,
               BF_PROG_ID_LEN);
        return 0;
    }

    switch (program->hook) {
    case BF_HOOK_XDP:
    case BF_HOOK_TC_INGRESS:
    case BF_HOOK_TC_EGRESS:
        (void)snprintf(buf, PATH_MAX, "%s_%08x", flavor_keys[program->hook],
                       program->runtime.chain->hook_opts.ifindex);
        break;
    case BF_HOOK_NF_PRE_ROUTING:
    case BF_HOOK_NF_LOCAL_IN:
    case BF_HOOK_NF_FORWARD:
    case BF_HOOK_NF_LOCAL_OUT:
    case BF_HOOK_NF_POST_ROUTING:
        (void)snprintf(buf, PATH_MAX, "%s", flavor_keys[program->hook]);
        break;
    case BF_HOOK_CGROUP_INGRESS:
    case BF_HOOK_CGROUP_EGRESS:
        (void)snprintf(buf, PATH_MAX, "%s_%s", flavor_keys[program->hook],
                       program->runtime.chain->hook_opts.cgroup);
        break;
    default:
        return bf_err_r(-ENOTSUP, "hook %d is not supported", program->hook);
    }

    murmur3_x86_32(buf, (int)strlen(buf), 0, &hash);

    (void)snprintf(program->id, BF_PROG_ID_LEN, "bf_%3s_%04x",
                   flavor_keys[program->hook], (uint16_t)(hash & 0xff));

    return 0;
}

int bf_program_new(struct bf_program **program, enum bf_hook hook,
                   enum bf_front front, const struct bf_chain *chain)
{
    _cleanup_bf_program_ struct bf_program *_program = NULL;
    char name[BPF_OBJ_NAME_LEN];
    uint32_t set_idx = 0;
    int r;

    bf_assert(chain);

    _program = calloc(1, sizeof(*_program));
    if (!_program)
        return -ENOMEM;

    _program->hook = hook;
    _program->front = front;
    _program->runtime.ops = bf_flavor_ops_get(hook);
    _program->runtime.chain = chain;

    r = _bf_program_genid(_program);
    if (r) {
        return bf_err_r(r,
                        "failed to generate ID for bf_program attached to %s",
                        bf_hook_to_str(hook));
    }

    (void)snprintf(_program->prog_name, BPF_OBJ_NAME_LEN, "%s_prg",
                   _program->id);
    (void)snprintf(_program->link_name, BPF_OBJ_NAME_LEN, "%s_lnk",
                   _program->id);

    (void)snprintf(name, BPF_OBJ_NAME_LEN, "%s_cmp", _program->id);
    r = bf_map_new(&_program->cmap, name, BF_MAP_TYPE_COUNTERS,
                   BF_MAP_BPF_TYPE_ARRAY, sizeof(uint32_t),
                   sizeof(struct bf_counter), 1);
    if (r < 0)
        return bf_err_r(r, "failed to create the counters bf_map object");

    (void)snprintf(name, BPF_OBJ_NAME_LEN, "%s_pmp", _program->id);
    r = bf_map_new(&_program->pmap, name, BF_MAP_TYPE_PRINTER,
                   BF_MAP_BPF_TYPE_ARRAY, sizeof(uint32_t),
                   BF_MAP_VALUE_SIZE_UNKNOWN, 1);
    if (r < 0)
        return bf_err_r(r, "failed to create the printer bf_map object");

    _program->sets = bf_map_list();
    bf_list_foreach (&chain->sets, set_node) {
        struct bf_set *set = bf_list_node_get_data(set_node);
        _cleanup_bf_map_ struct bf_map *map = NULL;

        (void)snprintf(name, BPF_OBJ_NAME_LEN, "%s_s%02x", _program->id,
                       (uint8_t)set_idx++);
        r = bf_map_new(&map, name, BF_MAP_TYPE_SET, BF_MAP_BPF_TYPE_HASH,
                       set->elem_size, 1, bf_list_size(&set->elems));
        if (r < 0)
            return r;

        r = bf_list_add_tail(&_program->sets, map);
        if (r < 0)
            return r;
        TAKE_PTR(map);
    };

    r = bf_printer_new(&_program->printer);
    if (r)
        return r;

    bf_list_init(&_program->fixups,
                 (bf_list_ops[]) {{.free = (bf_list_ops_free)bf_fixup_free}});

    _program->runtime.prog_fd = -1;
    _program->runtime.link_fd = -1;

    *program = TAKE_PTR(_program);

    return 0;
}

void bf_program_free(struct bf_program **program)
{
    if (!*program)
        return;

    bf_list_clean(&(*program)->fixups);
    free((*program)->img);

    /* Close the file descriptors if they are still open. If --transient is
     * used, then the file descriptors are already closed (as
     * bf_program_unload() has been called). Otherwise, bf_program_unload()
     * won't be called, but the programs are pinned, so they can be closed
     * safely. */
    closep(&(*program)->runtime.prog_fd);
    closep(&(*program)->runtime.link_fd);

    bf_map_free(&(*program)->cmap);
    bf_map_free(&(*program)->pmap);
    bf_list_clean(&(*program)->sets);
    bf_printer_free(&(*program)->printer);

    free(*program);
    *program = NULL;
}

int bf_program_marsh(const struct bf_program *program, struct bf_marsh **marsh)
{
    _cleanup_bf_marsh_ struct bf_marsh *_marsh = NULL;
    int r;

    bf_assert(program);
    bf_assert(marsh);

    r = bf_marsh_new(&_marsh, NULL, 0);
    if (r < 0)
        return r;

    r |= bf_marsh_add_child_raw(&_marsh, &program->hook, sizeof(program->hook));
    r |= bf_marsh_add_child_raw(&_marsh, &program->front,
                                sizeof(program->front));
    if (r)
        return r;

    {
        // Serialize bf_program.counters
        _cleanup_bf_marsh_ struct bf_marsh *counters_elem = NULL;

        r = bf_map_marsh(program->cmap, &counters_elem);
        if (r < 0)
            return r;

        r = bf_marsh_add_child_obj(&_marsh, counters_elem);
        if (r < 0)
            return r;
    }

    {
        // Serialize bf_program.pmap
        _cleanup_bf_marsh_ struct bf_marsh *pmap_elem = NULL;

        r = bf_map_marsh(program->pmap, &pmap_elem);
        if (r < 0)
            return r;

        r = bf_marsh_add_child_obj(&_marsh, pmap_elem);
        if (r < 0)
            return r;
    }

    {
        // Serialize bf_program.sets
        _cleanup_bf_marsh_ struct bf_marsh *sets_elem = NULL;

        r = bf_list_marsh(&program->sets, &sets_elem);
        if (r < 0)
            return r;

        r = bf_marsh_add_child_obj(&_marsh, sets_elem);
        if (r < 0) {
            return bf_err_r(
                r,
                "failed to insert serialized sets into bf_program serialized data");
        }
    }

    {
        // Serialise bf_program.printer
        _cleanup_bf_marsh_ struct bf_marsh *child = NULL;

        r = bf_printer_marsh(program->printer, &child);
        if (r)
            return bf_err_r(r, "failed to marsh bf_printer object");

        r = bf_marsh_add_child_obj(&_marsh, child);
        if (r)
            return bf_err_r(r, "failed to append object to marsh");
    }

    r |= bf_marsh_add_child_raw(&_marsh, &program->num_counters,
                                sizeof(program->num_counters));
    r |= bf_marsh_add_child_raw(&_marsh, program->img,
                                program->img_size * sizeof(struct bpf_insn));
    if (r)
        return bf_err_r(r, "Failed to serialize program");

    *marsh = TAKE_PTR(_marsh);

    return 0;
}

int bf_program_unmarsh(const struct bf_marsh *marsh,
                       struct bf_program **program,
                       const struct bf_chain *chain)
{
    enum bf_hook hook;
    enum bf_front front;
    char dir[PATH_MAX];
    _cleanup_close_ int pindir_fd = -1;
    _cleanup_bf_program_ struct bf_program *_program = NULL;
    struct bf_marsh *child = NULL;
    int r;

    bf_assert(marsh);
    bf_assert(program);

    if (!(child = bf_marsh_next_child(marsh, NULL)))
        return -EINVAL;
    memcpy(&hook, child->data, sizeof(hook));

    if (!(child = bf_marsh_next_child(marsh, child)))
        return -EINVAL;
    memcpy(&front, child->data, sizeof(front));

    r = bf_program_new(&_program, hook, front, chain);
    if (r < 0)
        return r;

    (void)snprintf(dir, PATH_MAX, "%s/%s", BF_PIN_DIR, _program->id);
    pindir_fd = open(dir, O_DIRECTORY, 0);
    if (pindir_fd < 0) {
        return bf_err_r(errno, "failed to open bf_program pin directory %s",
                        dir);
    }

    if (!(child = bf_marsh_next_child(marsh, child)))
        return -EINVAL;
    bf_map_free(&_program->cmap);
    r = bf_map_new_from_marsh(&_program->cmap, pindir_fd, child);
    if (r < 0)
        return r;

    if (!(child = bf_marsh_next_child(marsh, child)))
        return -EINVAL;
    bf_map_free(&_program->pmap);
    r = bf_map_new_from_marsh(&_program->pmap, pindir_fd, child);
    if (r < 0)
        return r;

    /** @todo Avoid creating and filling the list in @ref bf_program_new before
     * trashing it all here. Eventually, this function will be replaced with
     * @c bf_program_new_from_marsh and this issue could be solved by **not**
     * relying on @ref bf_program_new to allocate an initialize @p _program . */
    bf_list_clean(&_program->sets);
    _program->sets = bf_map_list();

    if (!(child = bf_marsh_next_child(marsh, child)))
        return -EINVAL;
    {
        // Unmarsh bf_program.sets
        struct bf_marsh *set_elem = NULL;

        while ((set_elem = bf_marsh_next_child(child, set_elem))) {
            _cleanup_bf_map_ struct bf_map *map = NULL;

            r = bf_map_new_from_marsh(&map, pindir_fd, set_elem);
            if (r < 0)
                return r;

            r = bf_list_add_tail(&_program->sets, map);
            if (r < 0)
                return r;

            TAKE_PTR(map);
        }
    }

    // Unmarsh bf_program.printer
    child = bf_marsh_next_child(marsh, child);
    if (!child)
        return bf_err_r(-EINVAL, "failed to find valid child");

    bf_printer_free(&_program->printer);
    r = bf_printer_new_from_marsh(&_program->printer, child);
    if (r)
        return bf_err_r(r, "failed to restore bf_printer object");

    if (!(child = bf_marsh_next_child(marsh, child)))
        return -EINVAL;
    memcpy(&_program->num_counters, child->data,
           sizeof(_program->num_counters));

    if (!(child = bf_marsh_next_child(marsh, child)))
        return -EINVAL;
    _program->img = bf_memdup(child->data, child->data_len);
    _program->img_size = child->data_len / sizeof(struct bpf_insn);
    _program->img_cap = child->data_len / sizeof(struct bpf_insn);

    if (bf_marsh_next_child(marsh, child))
        bf_warn("codegen marsh has more children than expected");

    r = bf_bpf_obj_get(_program->prog_name, pindir_fd,
                       &_program->runtime.prog_fd);
    if (r < 0)
        return bf_err_r(r, "failed to get prog fd");

    if (_program->runtime.chain->hook_opts.attach) {
        r = bf_bpf_obj_get(_program->link_name, pindir_fd,
                           &_program->runtime.link_fd);
        if (r < 0)
            return bf_err_r(r, "failed to get link fd");
    }

    *program = TAKE_PTR(_program);

    return 0;
}

void bf_program_dump(const struct bf_program *program, prefix_t *prefix)
{
    bf_assert(program);
    bf_assert(prefix);

    DUMP(prefix, "struct bf_program at %p", program);

    bf_dump_prefix_push(prefix);

    DUMP(prefix, "id: %s", program->id);
    DUMP(prefix, "hook: %s", bf_hook_to_str(program->hook));
    DUMP(prefix, "front: %s", bf_front_to_str(program->front));
    DUMP(prefix, "num_counters: %lu", program->num_counters);
    DUMP(prefix, "prog_name: %s", program->prog_name);
    DUMP(prefix, "link_name: %s", program->link_name);

    DUMP(prefix, "cmap: struct bf_map *");
    bf_dump_prefix_push(prefix);
    bf_map_dump(program->cmap, bf_dump_prefix_last(prefix));
    bf_dump_prefix_pop(prefix);

    DUMP(prefix, "pmap: struct bf_map *");
    bf_dump_prefix_push(prefix);
    bf_map_dump(program->pmap, bf_dump_prefix_last(prefix));
    bf_dump_prefix_pop(prefix);

    DUMP(prefix, "sets: bf_list<bf_map>[%lu]", bf_list_size(&program->sets));
    bf_dump_prefix_push(prefix);
    bf_list_foreach (&program->sets, map_node) {
        struct bf_map *map = bf_list_node_get_data(map_node);

        if (bf_list_is_tail(&program->sets, map_node))
            bf_dump_prefix_last(prefix);

        bf_map_dump(map, prefix);
    }
    bf_dump_prefix_pop(prefix);

    DUMP(prefix, "printer: struct bf_printer *");
    bf_dump_prefix_push(prefix);
    bf_printer_dump(program->printer, prefix);
    bf_dump_prefix_pop(prefix);

    DUMP(prefix, "img: %p", program->img);
    DUMP(prefix, "img_size: %lu", program->img_size);
    DUMP(prefix, "img_cap: %lu", program->img_cap);

    DUMP(prefix, "fixups: bf_list<struct bf_fixup>[%lu]",
         bf_list_size(&program->fixups));
    bf_dump_prefix_push(prefix);
    bf_list_foreach (&program->fixups, fixup_node) {
        struct bf_fixup *fixup = bf_list_node_get_data(fixup_node);

        if (bf_list_is_tail(&program->fixups, fixup_node))
            bf_dump_prefix_last(prefix);

        bf_fixup_dump(fixup, prefix);
    }
    bf_dump_prefix_pop(prefix);

    DUMP(bf_dump_prefix_last(prefix), "runtime: <anonymous>");
    bf_dump_prefix_push(prefix);
    DUMP(prefix, "prog_fd: %d", program->runtime.prog_fd);
    DUMP(prefix, "link_fd: %d", program->runtime.link_fd);
    DUMP(bf_dump_prefix_last(prefix), "ops: %p", program->runtime.ops);
    bf_dump_prefix_pop(prefix);

    bf_dump_prefix_pop(prefix);
}

static inline size_t _bf_round_next_power_of_2(size_t value)
{
    value--;
    value |= value >> 1;
    value |= value >> 2;
    value |= value >> 4;
    value |= value >> 8;
    value |= value >> 16;

    return ++value;
}

int bf_program_grow_img(struct bf_program *program)
{
    size_t new_cap = _BF_PROGRAM_DEFAULT_IMG_SIZE;
    int r;

    bf_assert(program);

    if (program->img)
        new_cap = _bf_round_next_power_of_2(program->img_cap << 1);

    r = bf_realloc((void **)&program->img, new_cap * sizeof(struct bpf_insn));
    if (r < 0) {
        return bf_err_r(r, "failed to grow program img from %lu to %lu insn",
                        program->img_cap, new_cap);
    }

    program->img_cap = new_cap;

    return 0;
}

static void _bf_program_fixup_insn(struct bpf_insn *insn,
                                   enum bf_fixup_insn type, int32_t value)
{
    switch (type) {
    case BF_FIXUP_INSN_OFF:
        bf_assert(!insn->off);
        bf_assert(value < SHRT_MAX);
        insn->off = (int16_t)value;
        break;
    case BF_FIXUP_INSN_IMM:
        bf_assert(!insn->imm);
        insn->imm = value;
        break;
    default:
        bf_abort(
            "unsupported fixup instruction type, this should not happen: %d",
            type);
        break;
    }
}

static int _bf_program_fixup(struct bf_program *program,
                             enum bf_fixup_type type)
{
    bf_assert(program);
    bf_assert(type >= 0 && type < _BF_FIXUP_TYPE_MAX);

    bf_list_foreach (&program->fixups, fixup_node) {
        enum bf_fixup_insn insn_type = _BF_FIXUP_INSN_MAX;
        int32_t value;
        size_t offset;
        struct bf_fixup *fixup = bf_list_node_get_data(fixup_node);
        struct bpf_insn *insn = &program->img[fixup->insn];
        struct bf_map *map;

        if (type != fixup->type)
            continue;

        switch (type) {
        case BF_FIXUP_TYPE_JMP_NEXT_RULE:
            insn_type = BF_FIXUP_INSN_OFF;
            value = (int)(program->img_size - fixup->insn - 1U);
            break;
        case BF_FIXUP_TYPE_COUNTERS_MAP_FD:
            insn_type = BF_FIXUP_INSN_IMM;
            value = program->cmap->fd;
            break;
        case BF_FIXUP_TYPE_PRINTER_MAP_FD:
            insn_type = BF_FIXUP_INSN_IMM;
            value = program->pmap->fd;
            break;
        case BF_FIXUP_TYPE_SET_MAP_FD:
            map = bf_list_get_at(&program->sets, insn->imm);
            if (!map) {
                return bf_err_r(-ENOENT, "can't find set map at index %d",
                                insn->imm);
            }
            insn_type = BF_FIXUP_INSN_IMM;
            value = map->fd;
            break;
        case BF_FIXUP_TYPE_FUNC_CALL:
            insn_type = BF_FIXUP_INSN_IMM;
            offset = program->functions_location[fixup->attr.function] -
                     fixup->insn - 1;
            bf_assert(offset < INT_MAX);
            value = (int32_t)offset;
            break;
        default:
            bf_abort("unsupported fixup type, this should not happen: %d",
                     type);
            break;
        }

        _bf_program_fixup_insn(insn, insn_type, value);
        bf_list_delete(&program->fixups, fixup_node);
    }

    return 0;
}

static int _bf_program_generate_rule(struct bf_program *program,
                                     struct bf_rule *rule)
{
    int r;

    bf_assert(program);
    bf_assert(rule);

    bf_list_foreach (&rule->matchers, matcher_node) {
        struct bf_matcher *matcher = bf_list_node_get_data(matcher_node);

        switch (matcher->type) {
        case BF_MATCHER_META_IFINDEX:
        case BF_MATCHER_META_L3_PROTO:
        case BF_MATCHER_META_L4_PROTO:
        case BF_MATCHER_META_SPORT:
        case BF_MATCHER_META_DPORT:
            r = bf_matcher_generate_meta(program, matcher);
            if (r)
                return r;
            break;
        case BF_MATCHER_IP4_SRC_ADDR:
        case BF_MATCHER_IP4_DST_ADDR:
        case BF_MATCHER_IP4_PROTO:
            r = bf_matcher_generate_ip4(program, matcher);
            if (r)
                return r;
            break;
        case BF_MATCHER_IP6_SADDR:
        case BF_MATCHER_IP6_DADDR:
            r = bf_matcher_generate_ip6(program, matcher);
            if (r)
                return r;
            break;
        case BF_MATCHER_TCP_SPORT:
        case BF_MATCHER_TCP_DPORT:
        case BF_MATCHER_TCP_FLAGS:
            r = bf_matcher_generate_tcp(program, matcher);
            if (r)
                return r;
            break;
        case BF_MATCHER_UDP_SPORT:
        case BF_MATCHER_UDP_DPORT:
            r = bf_matcher_generate_udp(program, matcher);
            if (r)
                return r;
            break;
        case BF_MATCHER_SET_SRCIP6PORT:
        case BF_MATCHER_SET_SRCIP6:
            r = bf_matcher_generate_set(program, matcher);
            if (r)
                return r;
            break;
        default:
            return bf_err_r(-EINVAL, "unknown matcher type %d", matcher->type);
        };
    }

    if (rule->counters) {
        EMIT(program, BPF_MOV32_IMM(BPF_REG_1, rule->index));
        EMIT(program, BPF_LDX_MEM(BPF_DW, BPF_REG_2, BPF_REG_10,
                                  BF_PROG_CTX_OFF(pkt_size)));
        EMIT_FIXUP_CALL(program, BF_FIXUP_FUNC_UPDATE_COUNTERS);
    }

    switch (rule->verdict) {
    case BF_VERDICT_ACCEPT:
    case BF_VERDICT_DROP:
        EMIT(program,
             BPF_MOV64_IMM(BPF_REG_0,
                           program->runtime.ops->get_verdict(rule->verdict)));
        EMIT(program, BPF_EXIT_INSN());
        break;
    case BF_VERDICT_CONTINUE:
        // Fall through to next rule or default chain policy.
        break;
    default:
        bf_abort("unsupported verdict, this should not happen: %d",
                 rule->verdict);
        break;
    }

    r = _bf_program_fixup(program, BF_FIXUP_TYPE_JMP_NEXT_RULE);
    if (r)
        return bf_err_r(r, "failed to generate next rule fixups");

    return 0;
}

/**
 * Generate the BPF function to update a rule's counters.
 *
 * This function defines a new function **in** the generated BPF program to
 * be called during packet processing.
 *
 * Parameters:
 * - @c r1 : index of the rule to update the counters for.
 * - @c r2 : size of the packet.
 * Returns:
 * 0 on success, non-zero on error.
 *
 * @param program Program to emit the function into. Can not be NULL.
 * @return 0 on success, or negative errno value on error.
 */
static int _bf_program_generate_update_counters(struct bf_program *program)
{
    // Move the counters key in scratch[0..4] and the packet size in scratch[8..15]
    EMIT(program,
         BPF_STX_MEM(BPF_W, BPF_REG_10, BPF_REG_1, BF_PROG_SCR_OFF(0)));
    EMIT(program,
         BPF_STX_MEM(BPF_DW, BPF_REG_10, BPF_REG_2, BF_PROG_SCR_OFF(8)));

    // Call bpf_map_lookup_elem()
    EMIT_LOAD_COUNTERS_FD_FIXUP(program, BPF_REG_1);
    EMIT(program, BPF_MOV64_REG(BPF_REG_2, BPF_REG_10));
    EMIT(program, BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, BF_PROG_SCR_OFF(0)));
    EMIT(program, BPF_EMIT_CALL(BPF_FUNC_map_lookup_elem));

    // If the counters doesn't exist, return from the function
    {
        _cleanup_bf_jmpctx_ struct bf_jmpctx _ =
            bf_jmpctx_get(program, BPF_JMP_IMM(BPF_JNE, BPF_REG_0, 0, 0));

        if (bf_opts_is_verbose(BF_VERBOSE_BPF))
            EMIT_PRINT(program, "failed to fetch the rule's counters");

        EMIT(program, BPF_MOV32_IMM(BPF_REG_0, 1));
        EMIT(program, BPF_EXIT_INSN());
    }

    // Increment the packets count by 1.
    EMIT(program, BPF_LDX_MEM(BPF_DW, BPF_REG_1, BPF_REG_0,
                              offsetof(struct bf_counter, packets)));
    EMIT(program, BPF_ALU64_IMM(BPF_ADD, BPF_REG_1, 1));
    EMIT(program, BPF_STX_MEM(BPF_DW, BPF_REG_0, BPF_REG_1,
                              offsetof(struct bf_counter, packets)));

    // Increase the total byte by the size of the packet.
    EMIT(program, BPF_LDX_MEM(BPF_DW, BPF_REG_1, BPF_REG_0,
                              offsetof(struct bf_counter, bytes)));
    EMIT(program,
         BPF_LDX_MEM(BPF_DW, BPF_REG_2, BPF_REG_10, BF_PROG_SCR_OFF(8)));
    EMIT(program, BPF_ALU64_REG(BPF_ADD, BPF_REG_1, BPF_REG_2));
    EMIT(program, BPF_STX_MEM(BPF_DW, BPF_REG_0, BPF_REG_1,
                              offsetof(struct bf_counter, bytes)));

    // On success, return 0
    EMIT(program, BPF_MOV32_IMM(BPF_REG_0, 0));
    EMIT(program, BPF_EXIT_INSN());

    return 0;
}

static int _bf_program_generate_functions(struct bf_program *program)
{
    int r;

    bf_assert(program);

    bf_list_foreach (&program->fixups, fixup_node) {
        struct bf_fixup *fixup = bf_list_node_get_data(fixup_node);
        size_t off = program->img_size;

        if (fixup->type != BF_FIXUP_TYPE_FUNC_CALL)
            continue;

        bf_assert(fixup->attr.function >= 0 &&
                  fixup->attr.function < _BF_FIXUP_FUNC_MAX);

        // Only generate each function once
        if (program->functions_location[fixup->attr.function])
            continue;

        switch (fixup->attr.function) {
        case BF_FIXUP_FUNC_UPDATE_COUNTERS:
            r = _bf_program_generate_update_counters(program);
            if (r)
                return r;
            break;
        default:
            bf_abort("unsupported fixup function, this should not happen: %d",
                     fixup->attr.function);
            break;
        }

        program->functions_location[fixup->attr.function] = off;
    }

    return 0;
}

int bf_program_emit(struct bf_program *program, struct bpf_insn insn)
{
    int r;

    bf_assert(program);

    if (program->img_size == program->img_cap) {
        r = bf_program_grow_img(program);
        if (r)
            return r;
    }

    program->img[program->img_size++] = insn;

    return 0;
}

int bf_program_emit_kfunc_call(struct bf_program *program, const char *name)
{
    int r;

    bf_assert(program);
    bf_assert(name);

    r = bf_btf_get_id(name);
    if (r < 0)
        return r;

    EMIT(program, ((struct bpf_insn) {.code = BPF_JMP | BPF_CALL,
                                      .dst_reg = 0,
                                      .src_reg = BPF_PSEUDO_KFUNC_CALL,
                                      .off = 0,
                                      .imm = r}));

    return 0;
}

int bf_program_emit_fixup(struct bf_program *program, enum bf_fixup_type type,
                          struct bpf_insn insn, const union bf_fixup_attr *attr)
{
    _cleanup_bf_fixup_ struct bf_fixup *fixup = NULL;
    int r;

    bf_assert(program);

    if (program->img_size == program->img_cap) {
        r = bf_program_grow_img(program);
        if (r)
            return r;
    }

    r = bf_fixup_new(&fixup, type, program->img_size, attr);
    if (r)
        return r;

    r = bf_list_add_tail(&program->fixups, fixup);
    if (r)
        return r;

    TAKE_PTR(fixup);

    /* This call could fail and return an error, in which case it is not
     * properly handled. However, this shouldn't be an issue as we previously
     * test whether enough room is available in cgen.img, which is currently
     * the only reason for EMIT() to fail. */
    EMIT(program, insn);

    return 0;
}

int bf_program_emit_fixup_call(struct bf_program *program,
                               enum bf_fixup_func function)
{
    _cleanup_bf_fixup_ struct bf_fixup *fixup = NULL;
    int r;

    bf_assert(program);

    if (program->img_size == program->img_cap) {
        r = bf_program_grow_img(program);
        if (r)
            return r;
    }

    r = bf_fixup_new(&fixup, BF_FIXUP_TYPE_FUNC_CALL, program->img_size, NULL);
    if (r)
        return r;

    fixup->attr.function = function;

    r = bf_list_add_tail(&program->fixups, fixup);
    if (r)
        return r;

    TAKE_PTR(fixup);

    /* This call could fail and return an error, in which case it is not
     * properly handled. However, this shouldn't be an issue as we previously
     * test whether enough room is available in cgen.img, which is currently
     * the only reason for EMIT() to fail. */
    EMIT(program, BPF_CALL_REL(0));

    return 0;
}

int bf_program_generate(struct bf_program *program)
{
    const struct bf_chain *chain = program->runtime.chain;
    int r;

    bf_info("generating program for %s::%s", bf_front_to_str(program->front),
            bf_hook_to_str(program->hook));

    /* Add 1 to the number of counters for the policy counter, and 1
     * for the first reserved error slot. This must be done ahead of
     * generation, as we will index into the error counters. */
    program->num_counters = bf_list_size(&chain->rules) + 2;

    // Save the program's argument into the context.
    EMIT(program,
         BPF_STX_MEM(BPF_DW, BPF_REG_10, BPF_REG_1, BF_PROG_CTX_OFF(arg)));

    // Reset the protocol ID registers
    EMIT(program, BPF_MOV64_IMM(BPF_REG_7, 0));
    EMIT(program, BPF_MOV64_IMM(BPF_REG_8, 0));

    r = program->runtime.ops->gen_inline_prologue(program);
    if (r)
        return r;

    bf_list_foreach (&chain->rules, rule_node) {
        r = _bf_program_generate_rule(program,
                                      bf_list_node_get_data(rule_node));
        if (r)
            return r;
    }

    r = program->runtime.ops->gen_inline_epilogue(program);
    if (r)
        return r;

    // Call the update counters function
    EMIT(program, BPF_MOV32_IMM(BPF_REG_1, bf_list_size(&chain->rules)));
    EMIT(program,
         BPF_LDX_MEM(BPF_DW, BPF_REG_2, BPF_REG_10, BF_PROG_CTX_OFF(pkt_size)));
    EMIT_FIXUP_CALL(program, BF_FIXUP_FUNC_UPDATE_COUNTERS);

    EMIT(program, BPF_MOV64_IMM(BPF_REG_0, program->runtime.ops->get_verdict(
                                               chain->policy)));
    EMIT(program, BPF_EXIT_INSN());

    r = _bf_program_generate_functions(program);
    if (r)
        return r;

    r = _bf_program_fixup(program, BF_FIXUP_TYPE_FUNC_CALL);
    if (r)
        return bf_err_r(r, "failed to generate function call fixups");

    return 0;
}

static void _bf_program_unpin(const struct bf_program *program);

/**
 * Pin the BPF objects that should survive the daemon's lifetime.
 *
 * If any of the BPF objects can't be pinned, unpin all of them to ensure
 * there will be no leftovers.
 *
 * @param program Program containing the objects to pin. Can't be NULL.
 * @return 0 on success, or negative erron value on failure.
 */
static int _bf_program_pin(const struct bf_program *program)
{
    _cleanup_close_ int pindir_fd = -1;
    char dir[PATH_MAX];
    int r;

    bf_assert(program);

    r = bf_ensure_dir(BF_PIN_DIR);
    if (r)
        return bf_err_r(r, "failed to ensure BPF objects pin directory exists");

    (void)snprintf(dir, PATH_MAX, "%s/%s", BF_PIN_DIR, program->id);

    r = bf_ensure_dir(dir);
    if (r)
        return bf_err_r(r, "failed to validate pin directory %s", dir);

    pindir_fd = open(dir, O_DIRECTORY, 0);
    if (pindir_fd < 0) {
        return bf_err_r(errno, "failed to open bf_program pin directory %s",
                        dir);
    }

    r = bf_bpf_obj_pin(program->prog_name, program->runtime.prog_fd, pindir_fd);
    if (r < 0) {
        bf_err_r(r, "failed to pin program '%s' in %s", program->prog_name,
                 BF_PIN_DIR);
        goto err_prog_pin;
    }

    if (program->runtime.chain->hook_opts.attach) {
        r = bf_bpf_obj_pin(program->link_name, program->runtime.link_fd,
                           pindir_fd);
        if (r < 0) {
            bf_err_r(r, "failed to pin link '%s' in %s", program->link_name,
                     BF_PIN_DIR);
            goto err_link_pin;
        }
    }

    r = bf_map_pin(program->cmap, pindir_fd);
    if (r < 0)
        goto err_cmap_pin;

    r = bf_map_pin(program->pmap, pindir_fd);
    if (r < 0)
        goto err_pmap_pin;

    bf_list_foreach (&program->sets, set_node) {
        r = bf_map_pin(bf_list_node_get_data(set_node), pindir_fd);
        if (r < 0)
            goto err_set_pin;
    }

    return 0;

err_set_pin:
    bf_list_foreach (&program->sets, set_node)
        bf_map_unpin(bf_list_node_get_data(set_node), pindir_fd);
    bf_map_unpin(program->pmap, pindir_fd);
err_pmap_pin:
    bf_map_unpin(program->cmap, pindir_fd);
err_cmap_pin:
    // Unconditionally unpin the link, ignore if it doesn't exist
    unlinkat(pindir_fd, program->link_name, 0);
err_link_pin:
    unlinkat(pindir_fd, program->prog_name, 0);
err_prog_pin:
    closep(&pindir_fd);
    return r;
}

/**
 * Unpin the BPF objects owned by a program.
 *
 * If the @p program object is deleted, the BPF object will disappear from
 * the system.
 *
 * @param program Program containing the objects to unpin. Can't be NULL.
 */
static void _bf_program_unpin(const struct bf_program *program)
{
    char dir[PATH_MAX];
    int pindir_fd;
    int r;

    bf_assert(program);

    (void)snprintf(dir, PATH_MAX, "%s/%s", BF_PIN_DIR, program->id);
    pindir_fd = open(dir, O_DIRECTORY, 0);
    if (pindir_fd < 0) {
        bf_warn_r(
            errno,
            "failed to open bf_program pin directory %s, assuming BPF objects are unpinned",
            dir);
        return;
    }

    unlinkat(pindir_fd, program->prog_name, 0);
    unlinkat(pindir_fd, program->link_name, 0);
    bf_map_unpin(program->pmap, pindir_fd);
    bf_map_unpin(program->cmap, pindir_fd);
    bf_list_foreach (&program->sets, set_node)
        bf_map_unpin(bf_list_node_get_data(set_node), pindir_fd);

    closep(&pindir_fd);
    r = rmdir(dir);
    if (r) {
        bf_warn_r(r, "failed to remove bf_program pin directory %s, ignoring",
                  dir);
    }
}

static int _bf_program_load_printer_map(struct bf_program *program)
{
    _cleanup_free_ void *pstr = NULL;
    size_t pstr_len;
    uint32_t key = 0;
    int r;

    bf_assert(program);

    r = bf_printer_assemble(program->printer, &pstr, &pstr_len);
    if (r)
        return bf_err_r(r, "failed to assemble printer map string");

    r = bf_map_set_value_size(program->pmap, pstr_len);
    if (r < 0)
        return r;

    r = bf_map_create(program->pmap, 0);
    if (r < 0)
        return r;

    r = bf_map_set_elem(program->pmap, &key, pstr);
    if (r)
        return r;

    r = _bf_program_fixup(program, BF_FIXUP_TYPE_PRINTER_MAP_FD);
    if (r) {
        bf_map_destroy(program->pmap);
        return bf_err_r(r, "failed to fixup printer map FD");
    }

    return 0;
}

static int _bf_program_load_counters_map(struct bf_program *program)
{
    _cleanup_close_ int _fd = -1;
    int r;

    bf_assert(program);

    r = bf_map_set_n_elems(program->cmap, program->num_counters);
    if (r < 0)
        return r;

    r = bf_map_create(program->cmap, 0);
    if (r < 0)
        return r;

    r = _bf_program_fixup(program, BF_FIXUP_TYPE_COUNTERS_MAP_FD);
    if (r < 0) {
        bf_map_destroy(program->cmap);
        return bf_err_r(r, "failed to fixup counters map FD");
    }

    return 0;
}

static int _bf_program_load_sets_maps(struct bf_program *new_prog)
{
    const bf_list_node *set_node;
    const bf_list_node *map_node;
    int r;

    bf_assert(new_prog);

    set_node = bf_list_get_head(&new_prog->runtime.chain->sets);
    map_node = bf_list_get_head(&new_prog->sets);

    // Fill the bf_map with the sets content
    while (set_node && map_node) {
        _cleanup_free_ uint8_t *values = NULL;
        _cleanup_free_ uint8_t *keys = NULL;
        struct bf_set *set = bf_list_node_get_data(set_node);
        struct bf_map *map = bf_list_node_get_data(map_node);
        size_t nelems = bf_list_size(&set->elems);
        union bpf_attr attr = {};
        size_t idx = 0;

        r = bf_map_create(map, 0);
        if (r < 0) {
            r = bf_err_r(r, "failed to create BPF map for set");
            goto err_destroy_maps;
        }

        values = malloc(nelems);
        if (!values) {
            r = bf_err_r(errno, "failed to allocate map values");
            goto err_destroy_maps;
        }

        keys = malloc(set->elem_size * nelems);
        if (!keys) {
            r = bf_err_r(errno, "failed to allocate map keys");
            goto err_destroy_maps;
        }

        bf_list_foreach (&set->elems, elem_node) {
            void *elem = bf_list_node_get_data(elem_node);

            memcpy(keys + (idx * set->elem_size), elem, set->elem_size);
            values[idx] = 1;
            ++idx;
        }

        attr.batch.map_fd = map->fd;
        attr.batch.keys = (unsigned long long)keys;
        attr.batch.values = (unsigned long long)values;
        attr.batch.count = nelems;
        attr.batch.flags = BPF_ANY;

        r = bf_bpf(BPF_MAP_UPDATE_BATCH, &attr);
        if (r < 0) {
            bf_err_r(r, "failed to add set elements to the map");
            goto err_destroy_maps;
        }

        set_node = bf_list_node_next(set_node);
        map_node = bf_list_node_next(map_node);
    }

    r = _bf_program_fixup(new_prog, BF_FIXUP_TYPE_SET_MAP_FD);
    if (r < 0)
        goto err_destroy_maps;

    return 0;

err_destroy_maps:
    bf_list_foreach (&new_prog->sets, map_node)
        bf_map_destroy(bf_list_node_get_data(map_node));
    return r;
}

int bf_program_load(struct bf_program *new_prog, struct bf_program *old_prog)
{
    int r;

    bf_assert(new_prog);

    r = _bf_program_load_sets_maps(new_prog);
    if (r < 0)
        return r;

    r = _bf_program_load_counters_map(new_prog);
    if (r)
        return r;

    r = _bf_program_load_printer_map(new_prog);
    if (r)
        return r;

    if (bf_opts_is_verbose(BF_VERBOSE_BYTECODE))
        bf_program_dump_bytecode(new_prog);

    r = bf_bpf_prog_load(
        new_prog->prog_name, bf_hook_to_bpf_prog_type(new_prog->hook),
        new_prog->img, new_prog->img_size,
        bf_hook_to_attach_type(new_prog->hook), &new_prog->runtime.prog_fd);
    if (r)
        return bf_err_r(r, "failed to load new bf_program");

    if (new_prog->runtime.chain->hook_opts.attach) {
        r = new_prog->runtime.ops->attach_prog(new_prog, old_prog);
        if (r)
            return r;
    }

    if (!bf_opts_transient()) {
        if (old_prog)
            _bf_program_unpin(old_prog);
        r = _bf_program_pin(new_prog);
    }

    return r;
}

int bf_program_unload(struct bf_program *program)
{
    int r;

    bf_assert(program);

    if (program->runtime.chain->hook_opts.attach) {
        r = program->runtime.ops->detach_prog(program);
        if (r)
            return r;
    }

    if (!bf_opts_transient())
        _bf_program_unpin(program);

    closep(&program->runtime.prog_fd);
    closep(&program->runtime.link_fd);

    bf_map_destroy(program->cmap);
    bf_map_destroy(program->pmap);

    bf_list_foreach (&program->sets, map_node)
        bf_map_destroy(bf_list_node_get_data(map_node));

    bf_dbg("unloaded %s program from %s", bf_front_to_str(program->front),
           bf_hook_to_str(program->hook));

    return 0;
}

int bf_program_get_counter(const struct bf_program *program,
                           uint32_t counter_idx, struct bf_counter *counter)
{
    bf_assert(program);
    bf_assert(counter);

    int r;

    r = bf_bpf_map_lookup_elem(program->cmap->fd, &counter_idx, counter);
    if (r < 0)
        return bf_err_r(errno, "failed to lookup counters map");

    return 0;
}

int bf_cgen_set_counters(struct bf_program *program,
                         const struct bf_counter *counters)
{
    UNUSED(program);
    UNUSED(counters);

    return -ENOTSUP;
}
