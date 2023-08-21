/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#include "generator/program.h"

#include <net/if.h>

#include <linux/bpf.h>
#include <linux/bpf_common.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/netfilter_ipv4/ip_tables.h>

#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "core/bpf.h"
#include "core/counter.h"
#include "core/flavor.h"
#include "core/logger.h"
#include "core/marsh.h"
#include "core/rule.h"
#include "core/target.h"
#include "external/filter.h"
#include "shared/helper.h"

#define _BF_PROGRAM_DEFAULT_IMG_SIZE (1 << 6)
#define _BF_PROGRAM_LOG_SIZE 65536
#define _BF_STACK_SCRATCH_OFFSET (-(short)sizeof(struct runtime_context))

#define _BF_STACK_RUNTIME_CTX_OFFSET(field)                                    \
    (-(short)(offsetof(struct runtime_context, field) +                        \
              sizeof(((struct runtime_context *)NULL)->field)))

struct runtime_context
{
    uint64_t data_size;
    void *l3;
    void *l4;
} bf_packed;

int bf_program_new(struct bf_program **program, int ifindex, enum bf_hook hook,
                   enum bf_front front)
{
    _cleanup_bf_program_ struct bf_program *_program = NULL;

    assert(ifindex);

    _program = calloc(1, sizeof(*_program));
    if (!_program)
        return -ENOMEM;

    _program->ifindex = ifindex;
    _program->hook = hook;
    _program->front = front;

    snprintf(_program->prog_name, BPF_OBJ_NAME_LEN, "bpfltr_%02d%02d%04d", hook,
             front, ifindex);
    snprintf(_program->map_name, BPF_OBJ_NAME_LEN, "bpfltr_%02d%02d%04d", hook,
             front, ifindex);
    snprintf(_program->prog_pin_path, PIN_PATH_LEN,
             "/sys/fs/bpf/bpfltr_p_%02d%02d%04d", hook, front, ifindex);
    snprintf(_program->map_pin_path, PIN_PATH_LEN,
             "/sys/fs/bpf/bpfltr_m_%02d%02d%04d", hook, front, ifindex);

    bf_list_init(&_program->fixups,
                 (bf_list_ops[]) {{.free = (bf_list_ops_free)bf_fixup_free}});

    *program = TAKE_PTR(_program);

    return 0;
}

void bf_program_free(struct bf_program **program)
{
    if (!*program)
        return;

    bf_list_clean(&(*program)->fixups);
    free((*program)->img);

    free(*program);
    *program = NULL;
}

int bf_program_marsh(const struct bf_program *program, struct bf_marsh **marsh)
{
    _cleanup_bf_marsh_ struct bf_marsh *_marsh = NULL;
    int r;

    assert(program);
    assert(marsh);

    r = bf_marsh_new(&_marsh, NULL, 0);
    if (r < 0)
        return r;

    r |= bf_marsh_add_child_raw(&_marsh, &program->ifindex,
                                sizeof(program->ifindex));
    r |= bf_marsh_add_child_raw(&_marsh, &program->hook, sizeof(program->hook));
    r |= bf_marsh_add_child_raw(&_marsh, &program->front,
                                sizeof(program->front));
    r |= bf_marsh_add_child_raw(&_marsh, &program->num_rules,
                                sizeof(program->num_rules));
    r |= bf_marsh_add_child_raw(&_marsh, program->img, program->img_size);
    if (r)
        return bf_err_code(r, "Failed to serialize program");

    *marsh = TAKE_PTR(_marsh);

    return 0;
}

int bf_program_unmarsh(const struct bf_marsh *marsh,
                       struct bf_program **program)
{
    int ifindex;
    enum bf_hook hook;
    enum bf_front front;
    _cleanup_bf_program_ struct bf_program *_program = NULL;
    struct bf_marsh *child = NULL;
    int r;

    assert(marsh);
    assert(program);

    if (!(child = bf_marsh_next_child(marsh, NULL)))
        return -EINVAL;
    memcpy(&ifindex, child->data, sizeof(ifindex));

    if (!(child = bf_marsh_next_child(marsh, child)))
        return -EINVAL;
    memcpy(&hook, child->data, sizeof(hook));

    if (!(child = bf_marsh_next_child(marsh, child)))
        return -EINVAL;
    memcpy(&front, child->data, sizeof(front));

    r = bf_program_new(&_program, ifindex, hook, front);
    if (r < 0)
        return r;

    if (!(child = bf_marsh_next_child(marsh, child)))
        return -EINVAL;
    memcpy(&_program->num_rules, child->data, sizeof(_program->num_rules));

    if (!(child = bf_marsh_next_child(marsh, child)))
        return -EINVAL;
    _program->img = bf_memdup(child->data, child->data_len);
    _program->img_size = child->data_len;
    _program->img_cap = child->data_len;

    if (bf_marsh_next_child(marsh, child))
        bf_warn("codegen marsh has more children than expected");

    *program = TAKE_PTR(_program);

    return 0;
}

void bf_program_dump(const struct bf_program *program, prefix_t *prefix)
{
    prefix_t _prefix = {};
    prefix = prefix ?: &_prefix;
    char ifname_buf[IF_NAMESIZE] = {};

    DUMP(prefix, "struct bf_program at %p", program);

    bf_dump_prefix_push(prefix);

    DUMP(prefix, "ifindex: %s", if_indextoname(program->ifindex, ifname_buf));
    DUMP(prefix, "hook: %s", bf_hook_to_str(program->hook));
    DUMP(prefix, "front: %s", bf_front_to_str(program->front));
    DUMP(prefix, "num_rules: %lu", program->num_rules);
    DUMP(prefix, "prog_name: %s", program->prog_name);
    DUMP(prefix, "map_name: %s", program->map_name);
    DUMP(prefix, "prog_pin_path: %s", program->prog_pin_path);
    DUMP(prefix, "map_pin_path: %s", program->map_pin_path);
    DUMP(prefix, "img: %p", program->img);
    DUMP(prefix, "img_size: %lu", program->img_size);
    DUMP(prefix, "img_cap: %lu", program->img_cap);

    bf_dump_prefix_pop(prefix);
}

static inline size_t _round_next_power_of_2(size_t x)
{
    x--;
    x |= x >> 1;
    x |= x >> 2;
    x |= x >> 4;
    x |= x >> 8;
    x |= x >> 16;

    return ++x;
}

int bf_program_grow_img(struct bf_program *program)
{
    size_t new_cap;
    int r;

    assert(program);

    if (!program->img) {
        new_cap = _BF_PROGRAM_DEFAULT_IMG_SIZE * sizeof(struct bpf_insn);
    } else {
        new_cap = _round_next_power_of_2(program->img_cap << 1) *
                  sizeof(struct bpf_insn);
    }

    r = bf_realloc((void **)&program->img, new_cap);
    if (r < 0) {
        return bf_err_code(r, "failed to grow program img from %lu to %lu",
                           program->img_cap, new_cap);
    }

    program->img_cap = new_cap;

    return 0;
}

static void _bf_program_fixup_insn(struct bpf_insn *insn,
                                   enum bf_fixup_insn_type type, int32_t v)
{
    switch (type) {
    case BF_CODEGEN_FIXUP_INSN_OFF:
        assert(!insn->off);
        insn->off = v;
        break;
    case BF_CODEGEN_FIXUP_INSN_IMM:
        assert(!insn->imm);
        insn->imm = v;
        break;
    default:
        assert(0);
    }
}

static int _bf_program_fixup(struct bf_program *program,
                             enum bf_fixup_type type,
                             const union bf_fixup_attr *attr)
{
    assert(program);
    assert(type >= 0 && type < _BF_CODEGEN_FIXUP_MAX);

    bf_list_foreach (&program->fixups, fixup_node) {
        enum bf_fixup_insn_type insn_type = _BF_CODEGEN_FIXUP_INSN_MAX_MAX;
        int32_t v;
        struct bf_fixup *fixup = bf_list_node_get_data(fixup_node);
        struct bpf_insn *insn = &program->img[fixup->insn];

        if (type != fixup->type)
            continue;

        switch (type) {
        case BF_CODEGEN_FIXUP_NEXT_RULE:
        case BF_CODEGEN_FIXUP_END_OF_CHAIN:
            insn_type = BF_CODEGEN_FIXUP_INSN_OFF;
            v = program->img_size - fixup->insn - 1;
            break;
        case BF_CODEGEN_FIXUP_MAP_FD:
            insn_type = BF_CODEGEN_FIXUP_INSN_IMM;
            v = attr->map_fd;
            break;
        case BF_CODEGEN_FIXUP_FUNCTION_CALL:
            insn_type = BF_CODEGEN_FIXUP_INSN_IMM;
            v = program->functions_location[fixup->function] - fixup->insn - 1;
            break;
        case BF_CODEGEN_FIXUP_JUMP_TO_CHAIN:
        case BF_CODEGEN_FIXUP_COUNTERS_INDEX:
            bf_err(
                "BF_CODEGEN_FIXUP_JUMP_TO_CHAIN and BF_CODEGEN_FIXUP_COUNTERS_INDEX are not supported yet");
            return -ENOTSUP;
        default:
            // Avoid `enumeration value not handled` warning, this should never
            // happen as we check the type is valid before the switch.
            assert(0);
            break;
        }

        _bf_program_fixup_insn(insn, insn_type, v);
        bf_list_delete(&program->fixups, fixup_node);
    }

    return 0;
}

static int _bf_program_generate_rule(struct bf_program *program,
                                     struct bf_rule *rule)
{
    const struct bf_target_ops *target_ops;
    int r;

    assert(program);
    assert(rule);

    if (!rule->src_mask && !rule->src) {
        if (rule->invflags & IPT_INV_SRCIP)
            return 0;
    }

    if (!rule->dst_mask && !rule->dst) {
        if (rule->invflags & IPT_INV_DSTIP)
            return 0;
    }

    if (rule->src_mask || rule->src) {
        EMIT(program, BPF_LDX_MEM(BPF_W, CODEGEN_REG_SCRATCH1, CODEGEN_REG_L3,
                                  offsetof(struct iphdr, saddr)));
        EMIT(program,
             BPF_ALU32_IMM(BPF_AND, CODEGEN_REG_SCRATCH1, rule->src_mask));
        EMIT_FIXUP(
            program, BF_CODEGEN_FIXUP_NEXT_RULE,
            BPF_JMP_IMM(rule->invflags & IPT_INV_SRCIP ? BPF_JEQ : BPF_JNE,
                        CODEGEN_REG_SCRATCH1, rule->src, 0));
    }

    if (rule->dst_mask || rule->dst) {
        EMIT(program, BPF_LDX_MEM(BPF_W, CODEGEN_REG_SCRATCH2, CODEGEN_REG_L3,
                                  offsetof(struct iphdr, daddr)));
        EMIT(program,
             BPF_ALU32_IMM(BPF_AND, CODEGEN_REG_SCRATCH2, rule->dst_mask));
        EMIT_FIXUP(
            program, BF_CODEGEN_FIXUP_NEXT_RULE,
            BPF_JMP_IMM(rule->invflags & IPT_INV_DSTIP ? BPF_JEQ : BPF_JNE,
                        CODEGEN_REG_SCRATCH2, rule->dst, 0));
    }

    if (rule->protocol) {
        EMIT(program, BPF_LDX_MEM(BPF_B, CODEGEN_REG_SCRATCH4, CODEGEN_REG_L3,
                                  offsetof(struct iphdr, protocol)));
        EMIT_FIXUP(
            program, BF_CODEGEN_FIXUP_NEXT_RULE,
            BPF_JMP_IMM(BPF_JNE, CODEGEN_REG_SCRATCH4, rule->protocol, 0));

        EMIT(program, BPF_LDX_MEM(BPF_B, CODEGEN_REG_SCRATCH4, CODEGEN_REG_L3,
                                  offsetof(struct iphdr, protocol)));
        EMIT(program, BPF_MOV64_REG(CODEGEN_REG_L4, CODEGEN_REG_L3));
        EMIT(program,
             BPF_LDX_MEM(BPF_B, CODEGEN_REG_SCRATCH1, CODEGEN_REG_L3, 0));
        EMIT(program, BPF_ALU32_IMM(BPF_AND, CODEGEN_REG_SCRATCH1, 0x0f));
        EMIT(program, BPF_ALU32_IMM(BPF_LSH, CODEGEN_REG_SCRATCH1, 2));
        EMIT(program,
             BPF_ALU64_REG(BPF_ADD, CODEGEN_REG_L4, CODEGEN_REG_SCRATCH1));
    }

    /// @todo do matches too!

    EMIT_FIXUP(program, BF_CODEGEN_FIXUP_MAP_FD,
               BPF_MOV64_IMM(BPF_REG_ARG1, 0));
    EMIT(program, BPF_MOV32_IMM(BPF_REG_ARG2, program->num_rules));
    EMIT(program, BPF_MOV64_REG(BPF_REG_ARG3, CODEGEN_REG_RUNTIME_CTX));
    EMIT(program,
         // Copy the packet size into REG3.
         BPF_LDX_MEM(BPF_DW, BPF_REG_ARG3, CODEGEN_REG_RUNTIME_CTX,
                     _BF_STACK_RUNTIME_CTX_OFFSET(data_size)));

    EMIT_FIXUP_CALL(program, BF_CODEGEN_FIXUP_FUNCTION_ADD_COUNTER);

    target_ops = bf_target_ops_get(rule->target->type);
    r = target_ops->generate(program, rule->target);
    if (r)
        return r;

    r = _bf_program_fixup(program, BF_CODEGEN_FIXUP_NEXT_RULE, NULL);
    if (r)
        return bf_err_code(r, "failed to generate next rule fixups");

    ++program->num_rules;

    return 0;
}

static int _bf_program_generate_add_counter(struct bf_program *program)
{
    EMIT(program,
         // Save packet size away from function arguments.
         BPF_MOV64_REG(BPF_REG_7, BPF_REG_ARG3));

    EMIT_LOAD_FD_FIXUP(program, BPF_REG_ARG1);

    EMIT(program,
         // Store the rule's map key before the runtime context.
         BPF_STX_MEM(BPF_W, BPF_REG_FP, BPF_REG_ARG2,
                     _BF_STACK_SCRATCH_OFFSET - 4));
    EMIT(program,
         // Store BPF_REG_FP address into ARG2.
         BPF_MOV64_REG(BPF_REG_ARG2, BPF_REG_10));
    EMIT(program,
         // Substract proper offset so ARG2 contains the address to the key.
         BPF_ALU64_IMM(BPF_ADD, BPF_REG_ARG2, _BF_STACK_SCRATCH_OFFSET - 4));
    EMIT(program,
         // Call BPF_FUNC_map_lookup_elem(&map, &key).
         BPF_EMIT_CALL(BPF_FUNC_map_lookup_elem));

    /// @todo Verifiy at compile time if the jump offset is correct
    /// @todo Add fixup to jump to a function's end.
    EMIT(program,
         // If the return value is NULL, jump after the counters processing.
         BPF_JMP_IMM(BPF_JEQ, BPF_REG_0, 0, 6));

    EMIT(program,
         // Copy packets count into REG1.
         BPF_LDX_MEM(BPF_DW, BPF_REG_1, BPF_REG_0, 0));
    EMIT(program,
         // Increment packets counter by 1.
         BPF_ALU64_IMM(BPF_ADD, BPF_REG_1, 1));
    EMIT(program,
         // Copy the packets counter back to the counters structure.
         BPF_STX_MEM(BPF_DW, BPF_REG_0, BPF_REG_1, 0));

    EMIT(program,
         // Copy bytes count into REG1.
         BPF_LDX_MEM(BPF_DW, BPF_REG_1, BPF_REG_0, 8));
    EMIT(program,
         // Add the current packet's size to the bytes counter.
         BPF_ALU64_REG(BPF_ADD, BPF_REG_1, BPF_REG_7));
    EMIT(program,
         // Copy the bytes counter back to the counters structure.
         BPF_STX_MEM(BPF_DW, BPF_REG_0, BPF_REG_1, 8));

    EMIT(program,
         // Tell BPF we update an existing element in the map.
         BPF_MOV32_IMM(BPF_REG_0, 0));
    EMIT(program, BPF_EXIT_INSN());

    return 0;
}

static int _bf_program_generate_functions(struct bf_program *program)
{
    int r;

    assert(program);

    bf_list_foreach (&program->fixups, fixup_node) {
        struct bf_fixup *fixup = bf_list_node_get_data(fixup_node);
        size_t off = program->img_size;

        if (fixup->type != BF_CODEGEN_FIXUP_FUNCTION_CALL)
            continue;

        assert(fixup->function >= 0 &&
               fixup->function < _BF_CODEGEN_FIXUP_FUNCTION_MAX);

        // Only generate each function once
        if (program->functions_location[fixup->function])
            continue;

        switch (fixup->function) {
        case BF_CODEGEN_FIXUP_FUNCTION_ADD_COUNTER:
            r = _bf_program_generate_add_counter(program);
            if (r)
                return r;
            break;
        default:
            // Avoid `enumeration value not handled` warning, this should never
            // happen as we check the type is valid before the switch.
            assert(0);
            break;
        }

        program->functions_location[fixup->function] = off;
    }

    return 0;
}

static int _bf_program_load_counters_map(struct bf_program *program, int *fd)
{
    _cleanup_close_ int _fd = -1;
    union bf_fixup_attr bf_attr = {};
    int r;

    assert(program);

    r = bf_bpf_map_create(program->map_name, BPF_MAP_TYPE_ARRAY,
                          sizeof(uint32_t), sizeof(struct bf_counter),
                          program->num_rules, &_fd);
    if (r < 0)
        return bf_err_code(errno, "failed to create counters map");

    bf_attr.map_fd = _fd;
    _bf_program_fixup(program, BF_CODEGEN_FIXUP_MAP_FD, &bf_attr);

    *fd = TAKE_FD(_fd);

    return 0;
}

int bf_program_emit(struct bf_program *program, struct bpf_insn insn)
{
    int r;

    assert(program);

    if (program->img_size == program->img_cap) {
        r = bf_program_grow_img(program);
        if (r)
            return r;
    }

    program->img[program->img_size++] = insn;

    return 0;
}

int bf_program_emit_fixup(struct bf_program *program, enum bf_fixup_type type,
                          struct bpf_insn insn)
{
    _cleanup_bf_fixup_ struct bf_fixup *fixup = NULL;
    int r;

    assert(program);

    if (program->img_size == program->img_cap) {
        bf_err("Codegen buffer overflow");
        return -EOVERFLOW;
    }

    r = bf_fixup_new(&fixup);
    if (r)
        return r;

    fixup->type = type;
    fixup->insn = program->img_size;

    r = bf_list_add_tail(&program->fixups, fixup);
    if (r)
        return r;

    TAKE_PTR(fixup);

    /* This call could fail and return an error, in which case it is not
     * properly handled. However, this shouldn't be an issue as we previously
     * test whether enough room is available in codegen.img, which is currently
     * the only reason for EMITC() to fail. */
    EMIT(program, insn);

    return 0;
}

int bf_program_emit_fixup_call(struct bf_program *program,
                               enum bf_fixup_function function)
{
    _cleanup_bf_fixup_ struct bf_fixup *fixup = NULL;
    int r;

    assert(program);

    if (program->img_size == program->img_cap) {
        bf_err("Codegen buffer overflow");
        return -EOVERFLOW;
    }

    r = bf_fixup_new(&fixup);
    if (r)
        return r;

    fixup->type = BF_CODEGEN_FIXUP_FUNCTION_CALL;
    fixup->insn = program->img_size;
    fixup->function = function;

    r = bf_list_add_tail(&program->fixups, fixup);
    if (r)
        return r;

    TAKE_PTR(fixup);

    /* This call could fail and return an error, in which case it is not
     * properly handled. However, this shouldn't be an issue as we previously
     * test whether enough room is available in codegen.img, which is currently
     * the only reason for EMITC() to fail. */
    EMIT(program, BPF_CALL_REL(0));

    return 0;
}

int bf_program_generate(struct bf_program *program, bf_list *rules)
{
    const struct bf_flavor_ops *ops =
        bf_flavor_ops_get(bf_hook_to_flavor(program->hook));
    char ifname_buf[IFNAMSIZ] = {};
    int r;

    bf_info("generating program for %s::%s::%s",
            bf_front_to_str(program->front), bf_hook_to_str(program->hook),
            if_indextoname(program->ifindex, ifname_buf));

    EMIT(program, BPF_MOV32_IMM(BPF_REG_0, 0));

    r = ops->gen_inline_prologue(program);
    if (r)
        return r;

    r = ops->load_packet_data(program, CODEGEN_REG_L3);
    if (r)
        return r;

    r = ops->load_packet_data_end(program, CODEGEN_REG_DATA_END);
    if (r)
        return r;

    EMIT(program, BPF_MOV64_REG(CODEGEN_REG_SCRATCH2, CODEGEN_REG_DATA_END));
    EMIT(program, BPF_ALU64_REG(BPF_SUB, CODEGEN_REG_SCRATCH2, CODEGEN_REG_L3));
    EMIT(program,
         BPF_STX_MEM(BPF_DW, CODEGEN_REG_RUNTIME_CTX, CODEGEN_REG_SCRATCH2,
                     _BF_STACK_RUNTIME_CTX_OFFSET(data_size)));

    EMIT(program, BPF_ALU64_IMM(BPF_ADD, CODEGEN_REG_L3, ETH_HLEN));

    EMIT_FIXUP(program, BF_CODEGEN_FIXUP_END_OF_CHAIN,
               BPF_JMP_REG(BPF_JGT, CODEGEN_REG_L3, CODEGEN_REG_DATA_END, 0));

    EMIT(program, BPF_MOV64_REG(CODEGEN_REG_SCRATCH1, CODEGEN_REG_L3));
    EMIT(program,
         BPF_ALU64_IMM(BPF_ADD, CODEGEN_REG_SCRATCH1, sizeof(struct iphdr)));
    EMIT_FIXUP(
        program, BF_CODEGEN_FIXUP_END_OF_CHAIN,
        BPF_JMP_REG(BPF_JGT, CODEGEN_REG_SCRATCH1, CODEGEN_REG_DATA_END, 0));

    bf_list_foreach (rules, rule_node) {
        struct bf_rule *rule = bf_list_node_get_data(rule_node);

        if (rule->ifindex != 0 && rule->ifindex != program->ifindex)
            continue;

        r = _bf_program_generate_rule(program, rule);
        if (r)
            return r;
    }

    if (!program->num_rules) {
        bf_info("No rules for %s::%s::%s, skipping",
                bf_front_to_str(program->front), bf_hook_to_str(program->hook),
                ifname_buf);
        return 0;
    }

    r = _bf_program_fixup(program, BF_CODEGEN_FIXUP_END_OF_CHAIN, NULL);
    if (r)
        return bf_err_code(r, "failed to generate end of chain fixups");

    r = ops->gen_inline_epilogue(program);
    if (r)
        return r;

    r = _bf_program_generate_functions(program);
    if (r)
        return r;

    r = _bf_program_fixup(program, BF_CODEGEN_FIXUP_FUNCTION_CALL, NULL);
    if (r)
        return bf_err_code(r, "failed to generate function call fixups");

    return 0;
}

int bf_program_load(struct bf_program *program)
{
    const struct bf_flavor_ops *ops =
        bf_flavor_ops_get(bf_hook_to_flavor(program->hook));
    _cleanup_free_ char *log = NULL;
    _cleanup_close_ int map_fd = -1;
    _cleanup_close_ int fd = -1;
    int r;

    assert(program);

    r = _bf_program_load_counters_map(program, &map_fd);
    if (r)
        return r;

    log = malloc(_BF_PROGRAM_LOG_SIZE);
    if (!log)
        return bf_err_code(ENOMEM, "failed to allocate log buffer");

    r = bf_bpf_prog_load(program->prog_name,
                         bf_hook_to_bpf_prog_type(program->hook), program->img,
                         program->img_size, log, _BF_PROGRAM_LOG_SIZE, &fd);
    if (r < 0)
        return bf_err_code(errno, "failed to load BPF program:\n%s", log);

    r = ops->load_img(program, fd);
    if (r)
        return r;

    // Pin program
    r = bf_bpf_obj_pin(program->prog_pin_path, fd);
    if (r < 0) {
        return bf_err_code(errno, "failed to pin program fd to %s",
                           program->prog_pin_path);
    }

    // Pin map
    r = bf_bpf_obj_pin(program->map_pin_path, map_fd);
    if (r < 0) {
        return bf_err_code(errno, "failed to pin map fd to %s",
                           program->map_pin_path);
    }

    bf_dbg("loaded %s codegen image to %s", bf_front_to_str(program->front),
           bf_hook_to_str(program->hook));
    bf_dbg("  prog pin path: %s", program->prog_pin_path);
    bf_dbg("  map pin path: %s", program->map_pin_path);

    return 0;
}

int bf_program_unload(struct bf_program *program)
{
    const struct bf_flavor_ops *ops =
        bf_flavor_ops_get(bf_hook_to_flavor(program->hook));
    int r;

    assert(program);

    r = ops->unload_img(program);
    if (r)
        return r;

    unlink(program->prog_pin_path);
    unlink(program->map_pin_path);

    bf_dbg("unloaded %s codegen image to %s", bf_front_to_str(program->front),
           bf_hook_to_str(program->hook));
    bf_dbg("  prog pin path: %s", program->prog_pin_path);
    bf_dbg("  map pin path: %s", program->map_pin_path);

    return 0;
}

int bf_program_get_counters(const struct bf_program *program,
                            const struct bf_rule *rule,
                            struct bf_counter *counters)
{
    _cleanup_close_ int fd = -1;
    int r;

    r = bf_bpf_obj_get(program->map_pin_path, &fd);
    if (r < 0)
        return bf_err_code(r, "failed to open counters map");

    r = bf_bpf_map_lookup_elem(fd, &rule->index, counters);
    if (r < 0)
        return bf_err_code(errno, "failed to lookup counters map");

    return 0;
}

int bf_codegen_set_counters(struct bf_program *program,
                            const struct bf_counter *counters)
{
    UNUSED(program);
    UNUSED(counters);

    return -ENOTSUP;
}
