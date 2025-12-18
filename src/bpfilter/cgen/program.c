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
#include "cgen/handle.h"
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
#include "opts.h"

#include "external/filter.h"

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
    int r;

    bf_assert(program && chain);

    _program = calloc(1, sizeof(*_program));
    if (!_program)
        return -ENOMEM;

    _program->flavor = bf_hook_to_flavor(chain->hook);
    _program->ops = bf_flavor_ops_get(_program->flavor);
    _program->chain = chain;
    _program->fixups = bf_list_default(bf_fixup_free, NULL);

    r = bf_handle_new(&_program->handle);
    if (r)
        return r;

    *program = TAKE_PTR(_program);

    return 0;
}

void bf_program_free(struct bf_program **program)
{
    if (!*program)
        return;

    bf_list_clean(&(*program)->fixups);
    freep((void *)&(*program)->img);
    bf_handle_free(&(*program)->handle);
    bf_printer_free(&(*program)->printer);

    freep((void *)program);
}

void bf_program_dump(const struct bf_program *program, prefix_t *prefix)
{
    bf_assert(program);
    bf_assert(prefix);

    DUMP(prefix, "struct bf_program at %p", program);

    bf_dump_prefix_push(prefix);

    if (program->printer) {
        DUMP(prefix, "printer: struct bf_printer *");
        bf_dump_prefix_push(prefix);
        bf_printer_dump(program->printer, bf_dump_prefix_last(prefix));
        bf_dump_prefix_pop(prefix);
    } else {
        DUMP(prefix, "printer: (struct bf_printer *)NULL");
    }

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

    DUMP(prefix, "ops: %p", program->ops);

    bf_handle_dump(program->handle, bf_dump_prefix_last(prefix));

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
            value = program->handle->counters->fd;
            break;
        case BF_FIXUP_TYPE_PRINTER_MAP_FD:
            insn_type = BF_FIXUP_INSN_IMM;
            value = program->handle->messages->fd;
            break;
        case BF_FIXUP_TYPE_LOG_MAP_FD:
            insn_type = BF_FIXUP_INSN_IMM;
            value = program->handle->logs->fd;
            break;
        case BF_FIXUP_TYPE_SET_MAP_FD:
            map = bf_list_get_at(&program->handle->sets, fixup->attr.set_index);
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
        case BF_MATCHER_META_FLOW_HASH:
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
        if (!program->ops->gen_inline_set_mark) {
            return bf_err_r(-ENOTSUP, "set mark is not supported by %s",
                            program->chain->name);
        }

        r = program->ops->gen_inline_set_mark(program, bf_rule_mark_get(rule));
        if (r) {
            return bf_err_r(r,
                            "failed to generate bytecode to set mark for '%s'",
                            program->chain->name);
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
        EMIT(program, BPF_MOV64_IMM(BPF_REG_0,
                                    program->ops->get_verdict(rule->verdict)));
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
            const struct bf_printer_msg *msg;

            struct bpf_insn ld_insn[2] = {
                BPF_LD_MAP_FD(BPF_REG_1, 0),
            };

            if (!program->printer) {
                r = bf_printer_new(&program->printer);
                if (r)
                    return r;
            }

            msg = bf_printer_add_msg(program->printer, pstr->str);
            if (!msg)
                return bf_err_r(-ENOMEM, "failed to add printer message");

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

int bf_program_emit_log(struct bf_program *program, const char *fmt)
{
    const struct bf_printer_msg *msg;
    struct bpf_insn ld_insn[2] = {
        BPF_LD_MAP_FD(BPF_REG_1, 0),
    };
    int r;

    assert(program);
    assert(fmt);

    if (!program->printer) {
        r = bf_printer_new(&program->printer);
        if (r)
            return r;
    }

    msg = bf_printer_add_msg((program)->printer, fmt);
    if (!msg)
        return bf_err_r(-ENOMEM, "failed to add printer message");

    ld_insn[0].src_reg = BPF_PSEUDO_MAP_VALUE;
    ld_insn[1].imm = (int)bf_printer_msg_offset(msg);

    r = bf_program_emit_fixup((program), BF_FIXUP_TYPE_PRINTER_MAP_FD,
                              ld_insn[0], NULL);
    if (r)
        return r;

    r = bf_program_emit((program), ld_insn[1]);
    if (r)
        return r;

    r = bf_program_emit(program,
                        BPF_MOV64_IMM(BPF_REG_2, bf_printer_msg_len(msg)));
    if (r)
        return r;

    r = bf_program_emit((program), BPF_EMIT_CALL(BPF_FUNC_trace_printk));
    if (r)
        return r;

    return 0;
}

static int _bf_program_generate(struct bf_program *program)
{
    const struct bf_chain *chain = program->chain;
    int r;

    // Save the program's argument into the context.
    EMIT(program,
         BPF_STX_MEM(BPF_DW, BPF_REG_10, BPF_REG_1, BF_PROG_CTX_OFF(arg)));

    // Reset the protocol ID registers
    EMIT(program, BPF_MOV64_IMM(BPF_REG_7, 0));
    EMIT(program, BPF_MOV64_IMM(BPF_REG_8, 0));

    // If at least one rule logs the matched packets, populate ctx->log_map
    if (chain->flags & BF_FLAG(BF_CHAIN_LOG)) {
        EMIT_LOAD_LOG_FD_FIXUP(program, BPF_REG_2);
        EMIT(program, BPF_STX_MEM(BPF_DW, BPF_REG_10, BPF_REG_2,
                                  BF_PROG_CTX_OFF(log_map)));
    }

    // Zeroing IPv6 extension headers
    if (chain->flags & BF_FLAG(BF_CHAIN_STORE_NEXTHDR)) {
        EMIT(program, BPF_STX_MEM(BPF_DW, BPF_REG_10, BPF_REG_7,
                                  BF_PROG_CTX_OFF(ipv6_eh)));
    }

    r = program->ops->gen_inline_prologue(program);
    if (r)
        return r;

    bf_list_foreach (&chain->rules, rule_node) {
        r = _bf_program_generate_rule(program,
                                      bf_list_node_get_data(rule_node));
        if (r)
            return r;
    }

    r = program->ops->gen_inline_epilogue(program);
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

    EMIT(program,
         BPF_MOV64_IMM(BPF_REG_0, program->ops->get_verdict(chain->policy)));
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
    _free_bf_map_ struct bf_map *messages = NULL;
    _cleanup_free_ void *pstr = NULL;
    size_t pstr_len;
    uint32_t key = 0;
    int r;

    bf_assert(program);

    if (program->handle->messages) {
        return bf_err_r(-EEXIST,
                        "messsages map already exists for the bf_program");
    }

    r = bf_printer_assemble(program->printer, &pstr, &pstr_len);
    if (r)
        return bf_err_r(r, "failed to assemble printer map string");

    r = bf_map_new(&messages, "printer_map", BF_MAP_TYPE_PRINTER,
                   sizeof(uint32_t), pstr_len, 1);
    if (r)
        return bf_err_r(r, "failed to create the printer bf_map object");

    r = bf_map_create(messages);
    if (r < 0)
        return r;

    r = bf_map_set_elem(messages, &key, pstr);
    if (r)
        return r;

    program->handle->messages = TAKE_PTR(messages);

    r = _bf_program_fixup(program, BF_FIXUP_TYPE_PRINTER_MAP_FD);
    if (r)
        return bf_err_r(r, "failed to fixup messages map FD");

    return 0;
}

static int _bf_program_load_counters_map(struct bf_program *program)
{
    _free_bf_map_ struct bf_map *counters = NULL;
    int r;

    bf_assert(program);

    if (program->handle->counters) {
        return bf_err_r(-EEXIST,
                        "counters map already exists for the bf_program");
    }

    r = bf_map_new(&counters, "counters_map", BF_MAP_TYPE_COUNTERS,
                   sizeof(uint32_t), sizeof(struct bf_counter),
                   bf_list_size(&program->chain->rules) + 2);
    if (r)
        return bf_err_r(r, "failed to create the counters bf_map object");

    r = bf_map_create(counters);
    if (r)
        return r;

    program->handle->counters = TAKE_PTR(counters);

    r = _bf_program_fixup(program, BF_FIXUP_TYPE_COUNTERS_MAP_FD);
    if (r)
        return bf_err_r(r, "failed to fixup counters map FD");

    return 0;
}

static int _bf_program_load_log_map(struct bf_program *program)
{
    _free_bf_map_ struct bf_map *logs = NULL;
    _cleanup_close_ int _fd = -1;
    int r;

    bf_assert(program);

    if (program->handle->logs)
        return bf_err_r(-EEXIST, "log map already exists for the bf_program");

    r = bf_map_new(&logs, "log_map", BF_MAP_TYPE_LOG, 0, 0, _BF_LOG_MAP_SIZE);
    if (r)
        return bf_err_r(r, "failed to create the log bf_map object");

    r = bf_map_create(logs);
    if (r)
        return r;

    program->handle->logs = TAKE_PTR(logs);

    r = _bf_program_fixup(program, BF_FIXUP_TYPE_LOG_MAP_FD);
    if (r)
        return bf_err_r(r, "failed to fixup log map FD");

    return 0;
}

static int _bf_program_load_sets_maps(struct bf_program *new_prog)
{
    _clean_bf_list_ bf_list sets;
    size_t set_idx = 0;
    int r;

    bf_assert(new_prog);

    if (!bf_list_is_empty(&new_prog->handle->sets))
        return bf_err_r(-EEXIST, "sets maps already exists for the bf_program");

    sets = bf_list_default_from(new_prog->handle->sets);

    // Fill the bf_map with the sets content
    bf_list_foreach (&new_prog->chain->sets, set_node) {
        _cleanup_free_ uint8_t *values = NULL;
        _cleanup_free_ uint8_t *keys = NULL;
        _free_bf_map_ struct bf_map *map = NULL;
        struct bf_set *set = bf_list_node_get_data(set_node);
        size_t nelems = bf_list_size(&set->elems);
        char name[BPF_OBJ_NAME_LEN];
        size_t idx = 0;

        (void)snprintf(name, BPF_OBJ_NAME_LEN, "set_%04x", (uint8_t)set_idx++);
        r = bf_map_new_from_set(&map, name, set);
        if (r)
            return r;

        r = bf_map_create(map);
        if (r)
            return bf_err_r(r, "failed to create BPF map for set");

        values = malloc(nelems);
        if (!values)
            return bf_err_r(errno, "failed to allocate map values");

        keys = malloc(set->elem_size * nelems);
        if (!keys)
            return bf_err_r(errno, "failed to allocate map keys");

        bf_list_foreach (&set->elems, elem_node) {
            void *elem = bf_list_node_get_data(elem_node);

            memcpy(keys + (idx * set->elem_size), elem, set->elem_size);
            values[idx] = 1;
            ++idx;
        }

        r = bf_bpf_map_update_batch(map->fd, keys, values, nelems, BPF_ANY);
        if (r)
            return bf_err_r(r, "failed to add set elements to the map");

        r = bf_list_push(&sets, (void **)&map);
        if (r)
            return bf_err_r(r, "failed to add set map to the program");

        set_node = bf_list_node_next(set_node);
    }

    bf_swap(new_prog->handle->sets, sets);

    r = _bf_program_fixup(new_prog, BF_FIXUP_TYPE_SET_MAP_FD);
    if (r)
        return r;

    return 0;
}

/**
 * @brief Load the BPF program into the kernel.
 *
 * Prior to loading the BPF program, multiple BPF maps are created to store
 * the counters, the debug strings, and the sets. If the program can't be
 * loaded, all the maps are destroyed.
 *
 * Once the loading succeeds, the program and the maps are pinned to the
 * filesystem, unless the daemon is in transient mode. If the BPF objects can't
 * be pinned, the program is unloaded and the maps destroyed.
 *
 * @param prog Program to load into the kernel. Can't be NULL and must contain
 *        instructions.
 * @return 0 on success, or negative error value on failure.
 */
static int _bf_program_load(struct bf_program *prog)
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
        BF_PROG_NAME, bf_hook_to_bpf_prog_type(prog->chain->hook), prog->img,
        prog->img_size, bf_hook_to_bpf_attach_type(prog->chain->hook), log_buf,
        log_buf ? _BF_LOG_BUF_SIZE : 0, bf_ctx_token(), &prog->handle->prog_fd);
    if (r) {
        return bf_err_r(r, "failed to load bf_program (%lu bytes):\n%s\nerrno:",
                        prog->img_size, log_buf ? log_buf : "<NO LOG BUFFER>");
    }

    bf_program_dump(prog, EMPTY_PREFIX);

    return r;
}

int bf_program_materialize(const struct bf_chain *chain,
                           struct bf_handle **handle)
{
    _free_bf_program_ struct bf_program *program = NULL;
    int r;

    bf_assert(chain);
    bf_assert(handle);

    r = bf_program_new(&program, chain);
    if (r)
        return r;

    r = _bf_program_generate(program);
    if (r)
        return r;

    r = _bf_program_load(program);
    if (r)
        return r;

    *handle = TAKE_PTR(program->handle);

    return 0;
}

int bf_cgen_set_counters(struct bf_program *program,
                         const struct bf_counter *counters)
{
    UNUSED(program);
    UNUSED(counters);

    return -ENOTSUP;
}

size_t bf_program_chain_counter_idx(const struct bf_program *program)
{
    return bf_list_size(&program->chain->rules);
}

size_t bf_program_error_counter_idx(const struct bf_program *program)
{
    return bf_list_size(&program->chain->rules) + 1;
}
