/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#include "bpfilter/cgen/program.h"

#include <linux/bpf.h>
#include <linux/bpf_common.h>

#include <errno.h>
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
#include "bpfilter/cgen/matcher/tcp.h"
#include "bpfilter/cgen/matcher/udp.h"
#include "bpfilter/cgen/printer.h"
#include "bpfilter/cgen/prog/map.h"
#include "bpfilter/cgen/reg.h"
#include "bpfilter/cgen/stub.h"
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
#include "core/list.h"
#include "core/logger.h"
#include "core/marsh.h"
#include "core/matcher.h"
#include "core/opts.h"
#include "core/rule.h"
#include "core/set.h"
#include "core/verdict.h"

#include "external/filter.h"

#define _BF_PROGRAM_DEFAULT_IMG_SIZE (1 << 6)

extern const struct bf_flavor_ops bf_flavor_ops_tc;
extern const struct bf_flavor_ops bf_flavor_ops_nf;
extern const struct bf_flavor_ops bf_flavor_ops_xdp;

static const struct bf_flavor_ops *bf_flavor_ops_get(enum bf_flavor flavor)
{
    static const struct bf_flavor_ops *flavor_ops[] = {
        [BF_FLAVOR_TC] = &bf_flavor_ops_tc,
        [BF_FLAVOR_NF] = &bf_flavor_ops_nf,
        [BF_FLAVOR_XDP] = &bf_flavor_ops_xdp,
        [BF_FLAVOR_CGROUP] = &bf_flavor_ops_cgroup,
    };

    bf_assert(0 <= flavor && flavor < _BF_FLAVOR_MAX);
    static_assert(ARRAY_SIZE(flavor_ops) == _BF_FLAVOR_MAX,
                  "missing entries in fronts array");

    return flavor_ops[flavor];
}

int bf_program_new(struct bf_program **program, enum bf_hook hook,
                   enum bf_front front, const struct bf_chain *chain)
{
    _cleanup_bf_program_ struct bf_program *_program = NULL;
    char suffix[BPF_OBJ_NAME_LEN] = {};
    int r;

    bf_assert(chain);

    _program = calloc(1, sizeof(*_program));
    if (!_program)
        return -ENOMEM;

    _program->hook = hook;
    _program->front = front;
    _program->runtime.ops = bf_flavor_ops_get(bf_hook_to_flavor(hook));
    _program->runtime.chain = chain;

    // Subpar, but at least there won't be any name clash.
    (void)snprintf(suffix, BPF_OBJ_NAME_LEN, "%02hx%02hx%02hx", hook, front,
                   chain->hook_opts.ifindex);
    (void)snprintf(_program->prog_name, BPF_OBJ_NAME_LEN, "bf_prog_%.6s",
                   suffix);
    (void)snprintf(_program->link_name, BPF_OBJ_NAME_LEN, "bf_link_%.6s",
                   suffix);
    (void)snprintf(_program->pmap_name, BPF_OBJ_NAME_LEN, "bf_pmap_%.6s",
                   suffix);
    (void)snprintf(_program->prog_pin_path, PIN_PATH_LEN,
                   "/sys/fs/bpf/bf_prog_%.6s", suffix);
    (void)snprintf(_program->link_pin_path, PIN_PATH_LEN,
                   "/sys/fs/bpf/bf_link_%.6s", suffix);
    (void)snprintf(_program->pmap_pin_path, PIN_PATH_LEN,
                   "/sys/fs/bpf/bf_pmap_%.6s", suffix);

    r = bf_map_new(&_program->counters, BF_MAP_TYPE_COUNTERS, suffix,
                   BF_MAP_BPF_TYPE_ARRAY, sizeof(uint32_t),
                   sizeof(struct bf_counter), 1);
    if (r < 0)
        return bf_err_r(r, "failed to create the counters bf_map object");

    _program->sets = bf_map_list();
    bf_list_foreach (&chain->sets, set_node) {
        struct bf_set *set = bf_list_node_get_data(set_node);
        _cleanup_bf_map_ struct bf_map *map = NULL;

        r = bf_map_new(&map, BF_MAP_TYPE_SET, suffix, BF_MAP_BPF_TYPE_HASH,
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
    _program->runtime.pmap_fd = -1;

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
    closep(&(*program)->runtime.pmap_fd);

    bf_map_free(&(*program)->counters);
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

        r = bf_map_marsh(program->counters, &counters_elem);
        if (r < 0)
            return r;

        r = bf_marsh_add_child_obj(&_marsh, counters_elem);
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
    _cleanup_bf_program_ struct bf_program *_program = NULL;
    _cleanup_bf_map_ struct bf_map *counters = NULL;
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

    if (!(child = bf_marsh_next_child(marsh, child)))
        return -EINVAL;
    bf_map_free(&_program->counters);
    r = bf_map_new_from_marsh(&_program->counters, child);
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

            r = bf_map_new_from_marsh(&map, set_elem);
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

    r = bf_bpf_obj_get(_program->prog_pin_path, &_program->runtime.prog_fd);
    if (r < 0)
        return bf_err_r(r, "failed to get prog fd");

    if (_program->runtime.chain->hook_opts.attach) {
        r = bf_bpf_obj_get(_program->link_pin_path, &_program->runtime.link_fd);
        if (r < 0)
            return bf_err_r(r, "failed to get link fd");
    }

    r = bf_bpf_obj_get(_program->pmap_pin_path, &_program->runtime.pmap_fd);
    if (r < 0)
        return bf_err_r(r, "failed to get printer map fd");

    *program = TAKE_PTR(_program);

    return 0;
}

void bf_program_dump(const struct bf_program *program, prefix_t *prefix)
{
    bf_assert(program);
    bf_assert(prefix);

    DUMP(prefix, "struct bf_program at %p", program);

    bf_dump_prefix_push(prefix);

    DUMP(prefix, "hook: %s", bf_hook_to_str(program->hook));
    DUMP(prefix, "front: %s", bf_front_to_str(program->front));
    DUMP(prefix, "num_counters: %lu", program->num_counters);
    DUMP(prefix, "prog_name: %s", program->prog_name);
    DUMP(prefix, "link_name: %s", program->link_name);
    DUMP(prefix, "pmap_name: %s", program->pmap_name);
    DUMP(prefix, "prog_pin_path: %s",
         bf_opts_transient() ? "<transient>" : program->prog_pin_path);
    DUMP(prefix, "link_pin_path: %s",
         bf_opts_transient() ? "<transient>" : program->link_pin_path);
    DUMP(prefix, "pmap_pin_path: %s",
         bf_opts_transient() ? "<transient>" : program->pmap_pin_path);

    DUMP(prefix, "counters: struct bf_map *");
    bf_dump_prefix_push(prefix);
    bf_map_dump(program->counters, bf_dump_prefix_last(prefix));
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
    DUMP(prefix, "pmap_fd: %d", program->runtime.pmap_fd);
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
            value = program->counters->fd;
            break;
        case BF_FIXUP_TYPE_PRINTER_MAP_FD:
            insn_type = BF_FIXUP_INSN_IMM;
            value = program->runtime.pmap_fd;
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
        default:
            return bf_err_r(-EINVAL, "unknown matcher type %d", matcher->type);
        };
    }

    if (rule->counters) {
        // BF_ARG_1: index of the current rule in counters map.
        EMIT(program, BPF_MOV32_IMM(BF_ARG_1, rule->index));

        // BF_ARG_2: packet size, from the context.
        EMIT(program, BPF_LDX_MEM(BPF_DW, BF_ARG_2, BF_REG_CTX,
                                  BF_PROG_CTX_OFF(pkt_size)));

        EMIT_FIXUP_CALL(program, BF_FIXUP_FUNC_UPDATE_COUNTERS);
    }

    EMIT(program, BPF_MOV64_IMM(BF_REG_RET, program->runtime.ops->get_verdict(
                                                rule->verdict)));
    EMIT(program, BPF_EXIT_INSN());

    r = _bf_program_fixup(program, BF_FIXUP_TYPE_JMP_NEXT_RULE);
    if (r)
        return bf_err_r(r, "failed to generate next rule fixups");

    return 0;
}

/**
 * Generate the BPF function to update a rule's counters.
 *
 * Parameters:
 * - @c BF_ARG_1 : index of the rule to update the counters for.
 * - @c BF_ARG_2 : size of the packet.
 * Returns:
 * 0 on success, non-zero on error.
 *
 * @param program Program to emit the function into. Can not be NULL.
 * @return 0 on success, or negative errno value on error.
 */
static int _bf_program_generate_update_counters(struct bf_program *program)
{
    // Move the rule's key at FP - 8
    EMIT(program, BPF_STX_MEM(BPF_W, BF_REG_FP, BF_ARG_1, -8));

    // Move the packet size at FP - 16
    EMIT(program, BPF_STX_MEM(BPF_DW, BF_REG_FP, BF_ARG_2, -16));

    // BF_ARG_1: counters map file descriptor
    EMIT_LOAD_COUNTERS_FD_FIXUP(program, BF_ARG_1);

    // BF_ARG_2: address of the rule's counters map key.
    EMIT(program, BPF_MOV64_REG(BF_ARG_2, BF_REG_FP));
    EMIT(program, BPF_ALU64_IMM(BPF_ADD, BF_ARG_2, -8));

    EMIT(program, BPF_EMIT_CALL(BPF_FUNC_map_lookup_elem));
    {
        // If the counters doesn't exist, return from the function
        _cleanup_bf_jmpctx_ struct bf_jmpctx _ =
            bf_jmpctx_get(program, BPF_JMP_IMM(BPF_JNE, BF_REG_0, 0, 0));

        if (bf_opts_is_verbose(BF_VERBOSE_BPF))
            EMIT_PRINT(program, "failed to fetch the rule's counters");

        EMIT(program, BPF_MOV32_IMM(BF_REG_0, 1));
        EMIT(program, BPF_EXIT_INSN());
    }

    // Increment the packets count by 1.
    EMIT(program, BPF_LDX_MEM(BPF_DW, BF_REG_1, BF_REG_0,
                              offsetof(struct bf_counter, packets)));
    EMIT(program, BPF_ALU64_IMM(BPF_ADD, BF_REG_1, 1));
    EMIT(program, BPF_STX_MEM(BPF_DW, BF_REG_0, BF_REG_1,
                              offsetof(struct bf_counter, packets)));

    // Increase the total byte by the size of the packet.
    EMIT(program, BPF_LDX_MEM(BPF_DW, BF_REG_1, BF_REG_0,
                              offsetof(struct bf_counter, bytes)));
    EMIT(program, BPF_LDX_MEM(BPF_DW, BF_REG_2, BF_REG_FP, -16));
    EMIT(program, BPF_ALU64_REG(BPF_ADD, BF_REG_1, BF_REG_2));
    EMIT(program, BPF_STX_MEM(BPF_DW, BF_REG_0, BF_REG_1,
                              offsetof(struct bf_counter, bytes)));

    // On success, BF_REG_0 is 0.
    EMIT(program, BPF_MOV32_IMM(BF_REG_0, 0));
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

static int _bf_program_load_printer_map(struct bf_program *program)
{
    _cleanup_free_ void *pstr = NULL;
    _cleanup_close_ int fd = -1;
    size_t pstr_len;
    int r;

    bf_assert(program);

    r = bf_printer_assemble(program->printer, &pstr, &pstr_len);
    if (r)
        return bf_err_r(r, "failed to assemble printer map string");

    r = bf_bpf__map_create(program->pmap_name, BPF_MAP_TYPE_ARRAY,
                           sizeof(uint32_t), pstr_len, 1, BPF_F_RDONLY_PROG,
                           &fd);
    if (r)
        return bf_err_r(r, "failed to create printer map");

    r = bf_bpf_map_update_elem(fd, (void *)(uint32_t[]) {0}, pstr);
    if (r)
        return bf_err_r(r, "failed to insert messages in printer map");

    program->runtime.pmap_fd = TAKE_FD(fd);
    r = _bf_program_fixup(program, BF_FIXUP_TYPE_PRINTER_MAP_FD);
    if (r) {
        // Not ideal, but will be resolved with bf_map
        closep(&program->runtime.pmap_fd);
        return bf_err_r(r, "can't update instruction with printer map fd");
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

static int _bf_program_generate_runtime_init(struct bf_program *program)
{
    // Store the context's address in BF_REG_CTX.
    EMIT(program, BPF_MOV64_REG(BF_REG_CTX, BF_REG_FP));
    EMIT(program, BPF_ALU64_IMM(BPF_ADD, BF_REG_CTX,
                                -(int)sizeof(struct bf_program_context)));

    // Save the program's argument into the context.
    EMIT(program,
         BPF_STX_MEM(BPF_DW, BF_REG_CTX, BF_ARG_1, BF_PROG_CTX_OFF(arg)));

    // Initialize the context's headers metadata
    EMIT(program, BPF_MOV64_IMM(BF_REG_2, 0));
    EMIT(program,
         BPF_STX_MEM(BPF_W, BF_REG_CTX, BF_REG_2, BF_PROG_CTX_OFF(l3_offset)));
    EMIT(program,
         BPF_STX_MEM(BPF_W, BF_REG_CTX, BF_REG_2, BF_PROG_CTX_OFF(l4_offset)));
    EMIT(program,
         BPF_STX_MEM(BPF_H, BF_REG_CTX, BF_REG_2, BF_PROG_CTX_OFF(l3_proto)));
    EMIT(program,
         BPF_STX_MEM(BPF_B, BF_REG_CTX, BF_REG_2, BF_PROG_CTX_OFF(l4_proto)));

    return 0;
}

int bf_program_generate(struct bf_program *program)
{
    const struct bf_chain *chain = program->runtime.chain;
    int r;

    bf_info("generating %s program for %s::%s",
            bf_flavor_to_str(bf_hook_to_flavor(program->hook)),
            bf_front_to_str(program->front), bf_hook_to_str(program->hook));

    r = _bf_program_generate_runtime_init(program);
    if (r)
        return r;

    // Set default return value to ACCEPT.
    EMIT(program, BPF_MOV64_IMM(BF_REG_RET, program->runtime.ops->get_verdict(
                                                BF_VERDICT_ACCEPT)));

    r = program->runtime.ops->gen_inline_prologue(program);
    if (r)
        return r;

    bf_list_foreach (&chain->rules, rule_node) {
        struct bf_rule *rule = bf_list_node_get_data(rule_node);

        r = _bf_program_generate_rule(program, rule);
        if (r)
            return r;
    }

    r = program->runtime.ops->gen_inline_epilogue(program);
    if (r)
        return r;

    // BF_ARG_1: index of the current rule in counters map.
    EMIT(program, BPF_MOV32_IMM(BF_ARG_1, bf_list_size(&chain->rules)));

    // BF_ARG_2: packet size, from the context.
    EMIT(program,
         BPF_LDX_MEM(BPF_DW, BF_ARG_2, BF_REG_CTX, BF_PROG_CTX_OFF(pkt_size)));

    EMIT_FIXUP_CALL(program, BF_FIXUP_FUNC_UPDATE_COUNTERS);

    EMIT(program, BPF_MOV64_IMM(BF_REG_RET, program->runtime.ops->get_verdict(
                                                chain->policy)));
    EMIT(program, BPF_EXIT_INSN());

    r = _bf_program_generate_functions(program);
    if (r)
        return r;

    r = _bf_program_fixup(program, BF_FIXUP_TYPE_FUNC_CALL);
    if (r)
        return bf_err_r(r, "failed to generate function call fixups");

    // Add 1 to the number of counters for the policy counter.
    program->num_counters = bf_list_size(&chain->rules) + 1;

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
    int r;

    bf_assert(program);

    r = bf_bpf_obj_pin(program->prog_pin_path, program->runtime.prog_fd);
    if (r < 0) {
        bf_err_r(r, "failed to pin program fd to %s", program->prog_pin_path);
        goto err;
    }

    if (program->runtime.chain->hook_opts.attach) {
        r = bf_bpf_obj_pin(program->link_pin_path, program->runtime.link_fd);
        if (r < 0) {
            bf_err_r(r, "failed to pin link fd to %s", program->link_pin_path);
            goto err;
        }
    }

    r = bf_bpf_obj_pin(program->pmap_pin_path, program->runtime.pmap_fd);
    if (r < 0) {
        bf_err_r(r, "failed to pin printer map fd to %s",
                 program->pmap_pin_path);
        goto err;
    }

    r = bf_map_pin(program->counters);
    if (r < 0)
        goto err;

    bf_list_foreach (&program->sets, set_node) {
        r = bf_map_pin(bf_list_node_get_data(set_node));
        if (r < 0)
            goto err;
    }

    return 0;

err:
    _bf_program_unpin(program);
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
    bf_assert(program);

    unlink(program->prog_pin_path);
    unlink(program->link_pin_path);
    unlink(program->pmap_pin_path);
    bf_map_unpin(program->counters);

    bf_list_foreach (&program->sets, set_node)
        bf_map_unpin(bf_list_node_get_data(set_node));
}

static int _bf_program_load_counters_map(struct bf_program *program)
{
    _cleanup_close_ int _fd = -1;
    int r;

    bf_assert(program);

    r = bf_map_set_n_elems(program->counters, program->num_counters);
    if (r < 0)
        return r;

    r = bf_map_create(program->counters, 0);
    if (r < 0)
        return r;

    r = _bf_program_fixup(program, BF_FIXUP_TYPE_COUNTERS_MAP_FD);
    if (r < 0) {
        bf_map_destroy(program->counters);
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

    // Create the BPF maps
    bf_list_foreach (&new_prog->sets, map_node) {
        struct bf_map *map = bf_list_node_get_data(map_node);
        r = bf_map_create(map, 0);
        if (r < 0)
            return r;
    }

    set_node = bf_list_get_head(&new_prog->runtime.chain->sets);
    map_node = bf_list_get_head(&new_prog->sets);

    // Fill the bf_map with the sets content
    while (set_node && map_node) {
        struct bf_set *set = bf_list_node_get_data(set_node);
        struct bf_map *map = bf_list_node_get_data(map_node);

        bf_list_foreach (&set->elems, elem_node) {
            uint8_t fake_value = 1;
            void *elem = bf_list_node_get_data(elem_node);

            r = bf_map_set_elem(map, elem, &fake_value);
            if (r < 0) {
                bf_err_r(r, "failed to add element to map");
                goto err_destroy_maps;
            }
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
    const char *name;
    int r;

    bf_assert(new_prog);

    name = new_prog->runtime.chain->hook_opts.name ?: new_prog->prog_name;

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

    r = bf_bpf_prog_load(name, bf_hook_to_bpf_prog_type(new_prog->hook),
                         new_prog->img, new_prog->img_size,
                         bf_hook_to_attach_type(new_prog->hook),
                         &new_prog->runtime.prog_fd);
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

    r = program->runtime.ops->detach_prog(program);
    if (r)
        return r;

    if (!bf_opts_transient())
        _bf_program_unpin(program);

    closep(&program->runtime.prog_fd);
    closep(&program->runtime.link_fd);
    closep(&program->runtime.pmap_fd);

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

    r = bf_bpf_map_lookup_elem(program->counters->fd, &counter_idx, counter);
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
