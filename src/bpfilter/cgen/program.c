/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#include "cgen/program.h"

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

#include <bpfilter/bpf.h>
#include <bpfilter/btf.h>
#include <bpfilter/chain.h>
#include <bpfilter/counter.h>
#include <bpfilter/dump.h>
#include <bpfilter/flavor.h>
#include <bpfilter/helper.h>
#include <bpfilter/hook.h>
#include <bpfilter/io.h>
#include <bpfilter/list.h>
#include <bpfilter/logger.h>
#include <bpfilter/matcher.h>
#include <bpfilter/pack.h>
#include <bpfilter/rule.h>
#include <bpfilter/set.h>
#include <bpfilter/verdict.h>

#include "cgen/cgroup.h"
#include "cgen/dump.h"
#include "cgen/fixup.h"
#include "cgen/jmp.h"
#include "cgen/matcher/icmp.h"
#include "cgen/matcher/ip4.h"
#include "cgen/matcher/ip6.h"
#include "cgen/matcher/meta.h"
#include "cgen/matcher/set.h"
#include "cgen/matcher/tcp.h"
#include "cgen/matcher/udp.h"
#include "cgen/nf.h"
#include "cgen/printer.h"
#include "cgen/prog/link.h"
#include "cgen/prog/map.h"
#include "cgen/stub.h"
#include "cgen/tc.h"
#include "cgen/xdp.h"
#include "ctx.h"
#include "filter.h"
#include "opts.h"

#define _BF_LOG_BUF_SIZE                                                       \
    (UINT32_MAX >> 8) /* verifier maximum in kernels <= 5.1 */
#define _BF_PROGRAM_DEFAULT_IMG_SIZE (1 << 6)
#define _BF_LOG_MAP_N_ENTRIES 1000
#define _BF_LOG_MAP_SIZE                                                       \
    _bf_round_next_power_of_2(sizeof(struct bf_log) * _BF_LOG_MAP_N_ENTRIES)

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

static const struct bf_flavor_ops *bf_flavor_ops_get(enum bf_flavor flavor)
{
    static const struct bf_flavor_ops *flavor_ops[] = {
        [BF_FLAVOR_TC] = &bf_flavor_ops_tc,
        [BF_FLAVOR_NF] = &bf_flavor_ops_nf,
        [BF_FLAVOR_XDP] = &bf_flavor_ops_xdp,
        [BF_FLAVOR_CGROUP] = &bf_flavor_ops_cgroup,
    };

    static_assert(ARRAY_SIZE(flavor_ops) == _BF_FLAVOR_MAX,
                  "missing entries in bf_flavor_ops array");

    return flavor_ops[flavor];
}

int bf_program_new(struct bf_program **program, const struct bf_chain *chain)
{
    _free_bf_program_ struct bf_program *_program = NULL;
    char name[BPF_OBJ_NAME_LEN];
    uint32_t set_idx = 0;
    int r;

    bf_assert(program && chain);

    _program = calloc(1, sizeof(*_program));
    if (!_program)
        return -ENOMEM;

    _program->flavor = bf_hook_to_flavor(chain->hook);
    _program->runtime.prog_fd = -1;
    _program->runtime.ops = bf_flavor_ops_get(_program->flavor);
    _program->runtime.chain = chain;

    (void)snprintf(_program->prog_name, BPF_OBJ_NAME_LEN, "%s", "bf_prog");

    r = bf_map_new(&_program->cmap, "counters_map", BF_MAP_TYPE_COUNTERS,
                   sizeof(uint32_t), sizeof(struct bf_counter), 1);
    if (r < 0)
        return bf_err_r(r, "failed to create the counters bf_map object");

    r = bf_map_new(&_program->pmap, "printer_map", BF_MAP_TYPE_PRINTER,
                   sizeof(uint32_t), BF_MAP_VALUE_SIZE_UNKNOWN, 1);
    if (r < 0)
        return bf_err_r(r, "failed to create the printer bf_map object");

    r = bf_map_new(&_program->lmap, "log_map", BF_MAP_TYPE_LOG, 0, 0,
                   _BF_LOG_MAP_SIZE);
    if (r < 0)
        return bf_err_r(r, "failed to create the log bf_map object");

    _program->sets = bf_list_default(bf_map_free, bf_map_pack);
    bf_list_foreach (&chain->sets, set_node) {
        struct bf_set *set = bf_list_node_get_data(set_node);
        _free_bf_map_ struct bf_map *map = NULL;

        (void)snprintf(name, BPF_OBJ_NAME_LEN, "set_%04x", (uint8_t)set_idx++);
        r = bf_map_new_from_set(&map, name, set);
        if (r < 0)
            return r;

        r = bf_list_add_tail(&_program->sets, map);
        if (r < 0)
            return r;
        TAKE_PTR(map);
    };

    r = bf_link_new(&_program->link, "bf_link");
    if (r)
        return r;

    r = bf_printer_new(&_program->printer);
    if (r)
        return r;

    bf_list_init(&_program->fixups,
                 (bf_list_ops[]) {{.free = (bf_list_ops_free)bf_fixup_free}});

    *program = TAKE_PTR(_program);

    return 0;
}

int bf_program_new_from_pack(struct bf_program **program,
                             const struct bf_chain *chain, int dir_fd,
                             bf_rpack_node_t node)
{
    _free_bf_program_ struct bf_program *_program = NULL;
    _free_bf_link_ struct bf_link *link = NULL;
    const void *img;
    size_t img_len;
    bf_rpack_node_t child, array_node;
    int r;

    bf_assert(program);
    bf_assert(chain);

    r = bf_program_new(&_program, chain);
    if (r < 0)
        return r;

    bf_map_free(&_program->cmap);
    r = bf_rpack_kv_obj(node, "cmap", &child);
    if (r)
        return bf_rpack_key_err(r, "bf_program.cmap");
    r = bf_map_new_from_pack(&_program->cmap, dir_fd, child);
    if (r)
        return r;

    bf_map_free(&_program->pmap);
    r = bf_rpack_kv_obj(node, "pmap", &child);
    if (r)
        return bf_rpack_key_err(r, "bf_program.pmap");
    r = bf_map_new_from_pack(&_program->pmap, dir_fd, child);
    if (r)
        return r;

    bf_map_free(&_program->lmap);
    r = bf_rpack_kv_obj(node, "lmap", &child);
    if (r)
        return bf_rpack_key_err(r, "bf_program.lmap");
    r = bf_map_new_from_pack(&_program->lmap, dir_fd, child);
    if (r)
        return r;

    bf_list_clean(&_program->sets);
    _program->sets = bf_list_default(bf_map_free, bf_map_pack);
    r = bf_rpack_kv_array(node, "sets", &child);
    if (r)
        return bf_rpack_key_err(r, "bf_program.sets");
    bf_rpack_array_foreach (child, array_node) {
        _free_bf_map_ struct bf_map *map = NULL;

        r = bf_list_emplace(&_program->sets, bf_map_new_from_pack, map, dir_fd,
                            array_node);
        if (r)
            return bf_err_r(r, "failed to unpack bf_map into bf_program.sets");
    }

    /* Try to restore the link: on success, replace the program's link with the
     * restored on. If -ENOENT is returned, the link doesn't exist, meaning the
     * program is not attached. Otherwise, return an error. */
    r = bf_rpack_kv_obj(node, "link", &child);
    if (r)
        return bf_rpack_key_err(r, "bf_program.link");
    r = bf_link_new_from_pack(&link, dir_fd, child);
    if (!r)
        bf_swap(_program->link, link);
    else if (r != -ENOENT)
        return bf_err_r(r, "failed to restore bf_program.link");

    bf_printer_free(&_program->printer);
    r = bf_rpack_kv_obj(node, "printer", &child);
    if (r)
        return bf_rpack_key_err(r, "bf_program.printer");
    r = bf_printer_new_from_pack(&_program->printer, child);
    if (r)
        return r;

    r = bf_rpack_kv_bin(node, "img", &img, &img_len);
    if (r)
        return bf_rpack_key_err(r, "bf_program.img");
    _program->img = bf_memdup(img, img_len);
    if (!_program->img)
        return bf_rpack_key_err(-ENOMEM, "bf_program.img");
    _program->img_size = img_len / sizeof(struct bpf_insn);
    _program->img_cap = _program->img_size;

    r = bf_bpf_obj_get(_program->prog_name, dir_fd, &_program->runtime.prog_fd);
    if (r < 0)
        return bf_err_r(r, "failed to restore bf_program.fd");

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

    bf_map_free(&(*program)->cmap);
    bf_map_free(&(*program)->pmap);
    bf_map_free(&(*program)->lmap);
    bf_list_clean(&(*program)->sets);
    bf_link_free(&(*program)->link);
    bf_printer_free(&(*program)->printer);

    free(*program);
    *program = NULL;
}

int bf_program_pack(const struct bf_program *program, bf_wpack_t *pack)
{
    bf_assert(program);
    bf_assert(pack);

    bf_wpack_open_object(pack, "cmap");
    bf_map_pack(program->cmap, pack);
    bf_wpack_close_object(pack);

    bf_wpack_open_object(pack, "pmap");
    bf_map_pack(program->pmap, pack);
    bf_wpack_close_object(pack);

    bf_wpack_open_object(pack, "lmap");
    bf_map_pack(program->lmap, pack);
    bf_wpack_close_object(pack);

    bf_wpack_kv_list(pack, "sets", &program->sets);

    bf_wpack_open_object(pack, "link");
    bf_link_pack(program->link, pack);
    bf_wpack_close_object(pack);

    bf_wpack_open_object(pack, "printer");
    bf_printer_pack(program->printer, pack);
    bf_wpack_close_object(pack);

    bf_wpack_kv_bin(pack, "img", program->img,
                    program->img_size * sizeof(struct bpf_insn));

    return bf_wpack_is_valid(pack) ? 0 : -EINVAL;
}

void bf_program_dump(const struct bf_program *program, prefix_t *prefix)
{
    bf_assert(program);
    bf_assert(prefix);

    DUMP(prefix, "struct bf_program at %p", program);

    bf_dump_prefix_push(prefix);

    DUMP(prefix, "prog_name: %s", program->prog_name);

    DUMP(prefix, "cmap: struct bf_map *");
    bf_dump_prefix_push(prefix);
    bf_map_dump(program->cmap, bf_dump_prefix_last(prefix));
    bf_dump_prefix_pop(prefix);

    DUMP(prefix, "pmap: struct bf_map *");
    bf_dump_prefix_push(prefix);
    bf_map_dump(program->pmap, bf_dump_prefix_last(prefix));
    bf_dump_prefix_pop(prefix);

    DUMP(prefix, "lmap: struct bf_map *");
    bf_dump_prefix_push(prefix);
    bf_map_dump(program->lmap, bf_dump_prefix_last(prefix));
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

    DUMP(prefix, "link: struct bf_link *");
    bf_dump_prefix_push(prefix);
    bf_link_dump(program->link, prefix);
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
    DUMP(bf_dump_prefix_last(prefix), "ops: %p", program->runtime.ops);
    bf_dump_prefix_pop(prefix);

    bf_dump_prefix_pop(prefix);
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
        case BF_FIXUP_TYPE_LOG_MAP_FD:
            insn_type = BF_FIXUP_INSN_IMM;
            value = program->lmap->fd;
            break;
        case BF_FIXUP_TYPE_SET_MAP_FD:
            map = bf_list_get_at(&program->sets, fixup->attr.set_index);
            if (!map) {
                return bf_err_r(-ENOENT, "can't find set map at index %lu",
                                fixup->attr.set_index);
            }
            insn_type = BF_FIXUP_INSN_IMM;
            value = map->fd;
            break;
        case BF_FIXUP_ELFSTUB_CALL:
            insn_type = BF_FIXUP_INSN_IMM;
            offset = program->elfstubs_location[fixup->attr.elfstub_id] -
                     fixup->insn - 1;
            if (offset >= INT_MAX)
                return bf_err_r(-EINVAL, "invalid ELF stub call offset");
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

        switch (bf_matcher_get_type(matcher)) {
        case BF_MATCHER_META_IFACE:
        case BF_MATCHER_META_L3_PROTO:
        case BF_MATCHER_META_L4_PROTO:
        case BF_MATCHER_META_PROBABILITY:
        case BF_MATCHER_META_SPORT:
        case BF_MATCHER_META_DPORT:
        case BF_MATCHER_META_MARK:
            r = bf_matcher_generate_meta(program, matcher);
            if (r)
                return r;
            break;
        case BF_MATCHER_IP4_SADDR:
        case BF_MATCHER_IP4_SNET:
        case BF_MATCHER_IP4_DADDR:
        case BF_MATCHER_IP4_DNET:
        case BF_MATCHER_IP4_PROTO:
            r = bf_matcher_generate_ip4(program, matcher);
            if (r)
                return r;
            break;
        case BF_MATCHER_IP6_SADDR:
        case BF_MATCHER_IP6_SNET:
        case BF_MATCHER_IP6_DADDR:
        case BF_MATCHER_IP6_DNET:
        case BF_MATCHER_IP6_NEXTHDR:
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
        case BF_MATCHER_ICMP_TYPE:
        case BF_MATCHER_ICMP_CODE:
        case BF_MATCHER_ICMPV6_TYPE:
        case BF_MATCHER_ICMPV6_CODE:
            r = bf_matcher_generate_icmp(program, matcher);
            if (r)
                return r;
            break;
        case BF_MATCHER_SET:
            r = bf_matcher_generate_set(program, matcher);
            if (r)
                return r;
            break;
        default:
            return bf_err_r(-EINVAL, "unknown matcher type %d",
                            bf_matcher_get_type(matcher));
        };
    }

    if (bf_rule_mark_is_set(rule)) {
        if (!program->runtime.ops->gen_inline_set_mark) {
            return bf_err_r(-ENOTSUP, "set mark is not supported by %s",
                            program->runtime.chain->name);
        }

        r = program->runtime.ops->gen_inline_set_mark(program,
                                                      bf_rule_mark_get(rule));
        if (r) {
            return bf_err_r(r,
                            "failed to generate bytecode to set mark for '%s'",
                            program->runtime.chain->name);
        }
    }

    if (rule->log) {
        EMIT(program, BPF_MOV64_REG(BPF_REG_1, BPF_REG_10));
        EMIT(program, BPF_ALU64_IMM(BPF_ADD, BPF_REG_1, BF_PROG_CTX_OFF(arg)));
        EMIT(program, BPF_MOV64_IMM(BPF_REG_2, rule->index));
        EMIT(program, BPF_MOV64_IMM(BPF_REG_3, rule->log));
        EMIT(program, BPF_MOV64_REG(BPF_REG_4, BPF_REG_7));
        EMIT(program, BPF_MOV64_REG(BPF_REG_5, BPF_REG_8));

        EMIT_FIXUP_ELFSTUB(program, BF_ELFSTUB_LOG);
    }

    if (rule->counters) {
        EMIT(program, BPF_MOV64_REG(BPF_REG_1, BPF_REG_10));
        EMIT(program, BPF_ALU64_IMM(BPF_ADD, BPF_REG_1, BF_PROG_CTX_OFF(arg)));
        EMIT_LOAD_COUNTERS_FD_FIXUP(program, BPF_REG_2);
        EMIT(program, BPF_MOV32_IMM(BPF_REG_3, rule->index));
        EMIT_FIXUP_ELFSTUB(program, BF_ELFSTUB_UPDATE_COUNTERS);
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

static int _bf_program_generate_elfstubs(struct bf_program *program)
{
    const struct bf_elfstub *elfstub;
    size_t start_at;
    int r;

    bf_assert(program);

    bf_list_foreach (&program->fixups, fixup_node) {
        struct bf_fixup *fixup = bf_list_node_get_data(fixup_node);
        size_t off = program->img_size;

        if (fixup->type != BF_FIXUP_ELFSTUB_CALL)
            continue;

        // Only generate each ELF stub once
        if (program->elfstubs_location[fixup->attr.elfstub_id])
            continue;

        bf_dbg("generate ELF stub for ID %d", fixup->attr.elfstub_id);

        elfstub = bf_ctx_get_elfstub(fixup->attr.elfstub_id);
        if (!elfstub) {
            return bf_err_r(-ENOENT, "no ELF stub found for ID %d",
                            fixup->attr.elfstub_id);
        }

        start_at = program->img_size;

        for (size_t i = 0; i < elfstub->ninsns; ++i) {
            r = bf_program_emit(program, elfstub->insns[i]);
            if (r)
                return bf_err_r(r, "failed to insert ELF stub instruction");
        }

        bf_list_foreach (&elfstub->strs, pstr_node) {
            _free_bf_fixup_ struct bf_fixup *fixup = NULL;
            struct bf_printk_str *pstr = bf_list_node_get_data(pstr_node);
            size_t insn_idx = start_at + pstr->insn_idx;
            const struct bf_printer_msg *msg =
                bf_printer_add_msg(program->printer, pstr->str);
            struct bpf_insn ld_insn[2] = {
                BPF_LD_MAP_FD(BPF_REG_1, 0),
            };

            ld_insn[0].src_reg = BPF_PSEUDO_MAP_VALUE;
            ld_insn[1].imm = (int)bf_printer_msg_offset(msg);

            program->img[insn_idx] = ld_insn[0];
            program->img[insn_idx + 1] = ld_insn[1];

            r = bf_fixup_new(&fixup, BF_FIXUP_TYPE_PRINTER_MAP_FD, insn_idx,
                             NULL);
            if (r)
                return r;

            r = bf_list_add_tail(&program->fixups, fixup);
            if (r)
                return r;

            TAKE_PTR(fixup);
        }

        program->elfstubs_location[fixup->attr.elfstub_id] = off;
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
    _free_bf_fixup_ struct bf_fixup *fixup = NULL;
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

int bf_program_emit_fixup_elfstub(struct bf_program *program,
                                  enum bf_elfstub_id id)
{
    _free_bf_fixup_ struct bf_fixup *fixup = NULL;
    int r;

    bf_assert(program);

    if (program->img_size == program->img_cap) {
        r = bf_program_grow_img(program);
        if (r)
            return r;
    }

    r = bf_fixup_new(&fixup, BF_FIXUP_ELFSTUB_CALL, program->img_size, NULL);
    if (r)
        return r;

    fixup->attr.elfstub_id = id;

    r = bf_list_add_tail(&program->fixups, fixup);
    if (r)
        return r;

    TAKE_PTR(fixup);

    EMIT(program, BPF_CALL_REL(0));

    return 0;
}

int bf_program_generate(struct bf_program *program)
{
    const struct bf_chain *chain = program->runtime.chain;
    int r;

    // Save the program's argument into the context.
    EMIT(program,
         BPF_STX_MEM(BPF_DW, BPF_REG_10, BPF_REG_1, BF_PROG_CTX_OFF(arg)));

    // Reset the protocol ID registers
    EMIT(program, BPF_MOV64_IMM(BPF_REG_7, 0));
    EMIT(program, BPF_MOV64_IMM(BPF_REG_8, 0));

    // If at least one rule logs the matched packets, populate ctx->log_map
    if (program->runtime.chain->flags & BF_FLAG(BF_CHAIN_LOG)) {
        EMIT_LOAD_LOG_FD_FIXUP(program, BPF_REG_2);
        EMIT(program, BPF_STX_MEM(BPF_DW, BPF_REG_10, BPF_REG_2,
                                  BF_PROG_CTX_OFF(log_map)));
    }

    // Zeroing IPv6 extension headers
    if (program->runtime.chain->flags & BF_FLAG(BF_CHAIN_STORE_NEXTHDR)) {
        EMIT(program, BPF_STX_MEM(BPF_DW, BPF_REG_10, BPF_REG_7,
                                  BF_PROG_CTX_OFF(ipv6_eh)));
    }

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
    /// @todo Allow chains to have no counters at all.
    EMIT(program, BPF_MOV64_REG(BPF_REG_1, BPF_REG_10));
    EMIT(program, BPF_ALU64_IMM(BPF_ADD, BPF_REG_1, BF_PROG_CTX_OFF(arg)));
    EMIT_LOAD_COUNTERS_FD_FIXUP(program, BPF_REG_2);
    EMIT(program,
         BPF_MOV32_IMM(BPF_REG_3, bf_program_chain_counter_idx(program)));
    EMIT_FIXUP_ELFSTUB(program, BF_ELFSTUB_UPDATE_COUNTERS);

    EMIT(program, BPF_MOV64_IMM(BPF_REG_0, program->runtime.ops->get_verdict(
                                               chain->policy)));
    EMIT(program, BPF_EXIT_INSN());

    r = _bf_program_generate_elfstubs(program);
    if (r)
        return r;

    r = _bf_program_fixup(program, BF_FIXUP_ELFSTUB_CALL);
    if (r)
        return bf_err_r(r, "failed to generate ELF stub call fixups");

    return 0;
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

    r = bf_map_create(program->pmap);
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

    r = bf_map_set_n_elems(program->cmap,
                           bf_list_size(&program->runtime.chain->rules) + 2);
    if (r < 0)
        return r;

    r = bf_map_create(program->cmap);
    if (r < 0)
        return r;

    r = _bf_program_fixup(program, BF_FIXUP_TYPE_COUNTERS_MAP_FD);
    if (r < 0) {
        bf_map_destroy(program->cmap);
        return bf_err_r(r, "failed to fixup counters map FD");
    }

    return 0;
}

static int _bf_program_load_log_map(struct bf_program *program)
{
    _cleanup_close_ int _fd = -1;
    int r;

    bf_assert(program);

    r = bf_map_create(program->lmap);
    if (r < 0)
        return r;

    r = _bf_program_fixup(program, BF_FIXUP_TYPE_LOG_MAP_FD);
    if (r < 0) {
        bf_map_destroy(program->lmap);
        return bf_err_r(r, "failed to fixup log map FD");
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
        size_t idx = 0;

        r = bf_map_create(map);
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

        r = bf_bpf_map_update_batch(map->fd, keys, values, nelems, BPF_ANY);
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

int bf_program_load(struct bf_program *prog)
{
    _cleanup_free_ char *log_buf = NULL;
    int r;

    bf_assert(prog && prog->img);

    r = _bf_program_load_sets_maps(prog);
    if (r)
        return r;

    r = _bf_program_load_counters_map(prog);
    if (r)
        return r;

    r = _bf_program_load_printer_map(prog);
    if (r)
        return r;

    r = _bf_program_load_log_map(prog);
    if (r)
        return r;

    if (bf_opts_is_verbose(BF_VERBOSE_DEBUG)) {
        log_buf = malloc(_BF_LOG_BUF_SIZE);
        if (!log_buf) {
            return bf_err_r(-ENOMEM,
                            "failed to allocate BPF_PROG_LOAD logs buffer");
        }
    }

    if (bf_opts_is_verbose(BF_VERBOSE_BYTECODE))
        bf_program_dump_bytecode(prog);

    r = bf_bpf_prog_load(
        prog->prog_name, bf_hook_to_bpf_prog_type(prog->runtime.chain->hook),
        prog->img, prog->img_size,
        bf_hook_to_bpf_attach_type(prog->runtime.chain->hook), log_buf,
        log_buf ? _BF_LOG_BUF_SIZE : 0, bf_ctx_token(), &prog->runtime.prog_fd);
    if (r) {
        return bf_err_r(r, "failed to load bf_program (%lu bytes):\n%s\nerrno:",
                        prog->img_size, log_buf ? log_buf : "<NO LOG BUFFER>");
    }

    return r;
}

int bf_program_attach(struct bf_program *prog, struct bf_hookopts **hookopts)
{
    int r;

    bf_assert(prog && hookopts);

    r = bf_link_attach(prog->link, prog->runtime.chain->hook, hookopts,
                       prog->runtime.prog_fd);
    if (r) {
        return bf_err_r(r, "failed to attach bf_link for %s program",
                        bf_flavor_to_str(prog->flavor));
    }

    return r;
}

void bf_program_detach(struct bf_program *prog)
{
    bf_assert(prog);

    bf_link_detach(prog->link);
}

void bf_program_unload(struct bf_program *prog)
{
    bf_assert(prog);

    closep(&prog->runtime.prog_fd);
    bf_link_detach(prog->link);
    bf_map_destroy(prog->cmap);
    bf_map_destroy(prog->pmap);
    bf_map_destroy(prog->lmap);
    bf_list_foreach (&prog->sets, map_node)
        bf_map_destroy(bf_list_node_get_data(map_node));
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

int bf_program_pin(struct bf_program *prog, int dir_fd)
{
    const char *name;
    int r;

    bf_assert(prog);

    name = prog->runtime.chain->name;

    r = bf_bpf_obj_pin(prog->prog_name, prog->runtime.prog_fd, dir_fd);
    if (r) {
        bf_err_r(r, "failed to pin BPF program for '%s'", name);
        goto err_unpin_all;
    }

    r = bf_map_pin(prog->cmap, dir_fd);
    if (r) {
        bf_err_r(r, "failed to pin BPF counters map for '%s'", name);
        goto err_unpin_all;
    }

    r = bf_map_pin(prog->pmap, dir_fd);
    if (r) {
        bf_err_r(r, "failed to pin BPF printer map for '%s'", name);
        goto err_unpin_all;
    }

    r = bf_map_pin(prog->lmap, dir_fd);
    if (r) {
        bf_err_r(r, "failed to pin BPF log map for '%s'", name);
        goto err_unpin_all;
    }

    bf_list_foreach (&prog->sets, set_node) {
        r = bf_map_pin(bf_list_node_get_data(set_node), dir_fd);
        if (r) {
            bf_err_r(r, "failed to pin BPF set map for '%s'", name);
            goto err_unpin_all;
        }
    }

    // If a link exists, pin it too.
    if (prog->link->hookopts) {
        r = bf_link_pin(prog->link, dir_fd);
        if (r) {
            bf_err_r(r, "failed to pin BPF link for '%s'", name);
            goto err_unpin_all;
        }
    }

    return 0;

err_unpin_all:
    bf_program_unpin(prog, dir_fd);
    return r;
}

void bf_program_unpin(struct bf_program *prog, int dir_fd)
{
    bf_assert(prog);

    bf_map_unpin(prog->cmap, dir_fd);
    bf_map_unpin(prog->pmap, dir_fd);
    bf_map_unpin(prog->lmap, dir_fd);

    bf_list_foreach (&prog->sets, set_node)
        bf_map_unpin(bf_list_node_get_data(set_node), dir_fd);

    bf_link_unpin(prog->link, dir_fd);

    unlinkat(dir_fd, prog->prog_name, 0);
}

size_t bf_program_chain_counter_idx(const struct bf_program *program)
{
    return bf_list_size(&program->runtime.chain->rules);
}

size_t bf_program_error_counter_idx(const struct bf_program *program)
{
    return bf_list_size(&program->runtime.chain->rules) + 1;
}
