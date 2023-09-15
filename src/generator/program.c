/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#include "generator/program.h"

#include <net/if.h>

#include <linux/bpf.h>
#include <linux/bpf_common.h>
#include <linux/if_ether.h>
#include <linux/netfilter_ipv4/ip_tables.h>

#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "core/bpf.h"
#include "core/btf.h"
#include "core/counter.h"
#include "core/flavor.h"
#include "core/logger.h"
#include "core/marsh.h"
#include "core/rule.h"
#include "core/target.h"
#include "generator/stub.h"
#include "shared/helper.h"

#include "external/filter.h"

#define _BF_PROGRAM_DEFAULT_IMG_SIZE (1 << 6)

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
    r |= bf_marsh_add_child_raw(&_marsh, &program->num_rules_total,
                                sizeof(program->num_rules_total));
    r |= bf_marsh_add_child_raw(&_marsh, program->img,
                                program->img_size * sizeof(struct bpf_insn));
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
    memcpy(&_program->num_rules_total, child->data,
           sizeof(_program->num_rules_total));

    if (!(child = bf_marsh_next_child(marsh, child)))
        return -EINVAL;
    _program->img = bf_memdup(child->data, child->data_len);
    _program->img_size = child->data_len / sizeof(struct bpf_insn);
    _program->img_cap = child->data_len / sizeof(struct bpf_insn);

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
    DUMP(bf_dump_prefix_last(prefix), "img_cap: %lu", program->img_cap);

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
    size_t new_cap = _BF_PROGRAM_DEFAULT_IMG_SIZE;
    int r;

    assert(program);

    if (program->img)
        new_cap = _round_next_power_of_2(program->img_cap << 1);

    r = bf_realloc((void **)&program->img, new_cap * sizeof(struct bpf_insn));
    if (r < 0) {
        return bf_err_code(r, "failed to grow program img from %lu to %lu insn",
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
            insn_type = BF_CODEGEN_FIXUP_INSN_OFF;
            v = (int)(program->img_size - fixup->insn - 1U);
            break;
        case BF_CODEGEN_FIXUP_END_OF_CHAIN:
            insn_type = BF_CODEGEN_FIXUP_INSN_OFF;
            v = (int)(program->img_size - fixup->insn - 2U);
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
        EMIT(program, BPF_LDX_MEM(BPF_W, BF_REG_1, BF_REG_L3,
                                  offsetof(struct iphdr, saddr)));
        EMIT(program, BPF_ALU32_IMM(BPF_AND, BF_REG_1, rule->src_mask));
        EMIT_FIXUP(
            program, BF_CODEGEN_FIXUP_NEXT_RULE,
            BPF_JMP_IMM(rule->invflags & IPT_INV_SRCIP ? BPF_JEQ : BPF_JNE,
                        BF_REG_1, rule->src, 0));
    }

    if (rule->dst_mask || rule->dst) {
        EMIT(program, BPF_LDX_MEM(BPF_W, BF_REG_2, BF_REG_L3,
                                  offsetof(struct iphdr, daddr)));
        EMIT(program, BPF_ALU32_IMM(BPF_AND, BF_REG_2, rule->dst_mask));
        EMIT_FIXUP(
            program, BF_CODEGEN_FIXUP_NEXT_RULE,
            BPF_JMP_IMM(rule->invflags & IPT_INV_DSTIP ? BPF_JEQ : BPF_JNE,
                        BF_REG_2, rule->dst, 0));
    }

    if (rule->protocol) {
        EMIT(program, BPF_LDX_MEM(BPF_B, BF_REG_4, BF_REG_L3,
                                  offsetof(struct iphdr, protocol)));
        EMIT_FIXUP(program, BF_CODEGEN_FIXUP_NEXT_RULE,
                   BPF_JMP_IMM(BPF_JNE, BF_REG_4, rule->protocol, 0));
    }

    /// @todo do matches too!

    // BF_ARG_1: counters map file descriptor.
    EMIT_FIXUP(program, BF_CODEGEN_FIXUP_MAP_FD, BPF_MOV64_IMM(BF_ARG_1, 0));

    // BF_ARG_2: index of the current rule in counters map.
    EMIT(program, BPF_MOV32_IMM(BF_ARG_2, rule->index));

    // BF_ARG_3: packet size, from the context.
    EMIT(program,
         BPF_LDX_MEM(BPF_DW, BF_ARG_3, BF_REG_CTX, BF_PROG_CTX_OFF(pkt_size)));

    EMIT_FIXUP_CALL(program, BF_CODEGEN_FIXUP_FUNCTION_ADD_COUNTER);

    target_ops = bf_target_ops_get(rule->target->type);
    r = target_ops->generate(program, rule->target);
    if (r)
        return r;

    r = _bf_program_fixup(program, BF_CODEGEN_FIXUP_NEXT_RULE, NULL);
    if (r)
        return bf_err_code(r, "failed to generate next rule fixups");

    return 0;
}

/**
 * @brief Generate a function to update the packets counter
 *
 * Assuming:
 * - BF_ARG_1: file descriptor of the counters map.
 * - BF_ARG_2: index of the rule in the counters map.
 * - BF_ARG_3: packet size
 *
 * @todo Random jump into the bytecode should be calculated by the daemon,
 * not the developer.
 * @todo Create a fixup to jump to the end of a function.
 * @todo Set BF_REG_0 to !0 on failure, so we don't drop the packet.
 *
 * @param program Program to emit the function into. Can not be NULL.
 * @return 0 on success, or negative errno value on error.
 */
static int _bf_program_generate_add_counter(struct bf_program *program)
{
    // Load the map into BF_ARG_1.
    EMIT_LOAD_FD_FIXUP(program, BF_ARG_1);

    // Store the rule's key before the runtime context.
    EMIT(program, BPF_STX_MEM(BPF_W, BF_REG_FP, BF_ARG_2, -8));

    // Store the packet size before the rule's key
    EMIT(program, BPF_STX_MEM(BPF_DW, BF_REG_FP, BF_ARG_3, -16));

    // BF_ARG_2: address of the rule's counters map key.
    EMIT(program, BPF_MOV64_REG(BF_ARG_2, BF_REG_FP));
    EMIT(program, BPF_ALU64_IMM(BPF_ADD, BF_ARG_2, -8));

    EMIT(program, BPF_EMIT_CALL(BPF_FUNC_map_lookup_elem));

    // If we can't find the entry, return.
    EMIT(program, BPF_JMP_IMM(BPF_JEQ, BF_REG_0, 0, 7));

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

    /// @todo: remove conditional on num_rules
    r = bf_bpf_map_create(program->map_name, BPF_MAP_TYPE_ARRAY,
                          sizeof(uint32_t), sizeof(struct bf_counter),
                          program->num_rules_total, &_fd);
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

int bf_program_emit_kfunc_call(struct bf_program *program, const char *name)
{
    int r;

    assert(program);
    assert(name);

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
                          struct bpf_insn insn)
{
    _cleanup_bf_fixup_ struct bf_fixup *fixup = NULL;
    int r;

    assert(program);

    if (program->img_size == program->img_cap) {
        r = bf_program_grow_img(program);
        if (r)
            return r;
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
     * the only reason for EMIT() to fail. */
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
     * the only reason for EMIT() to fail. */
    EMIT(program, BPF_CALL_REL(0));

    return 0;
}

static int _bf_program_generate_runtime_init(struct bf_program *program)
{
    int r;

    // Store the context's address in BF_REG_CTX.
    EMIT(program, BPF_MOV64_REG(BF_REG_CTX, BF_REG_FP));
    EMIT(program, BPF_ALU64_IMM(BPF_ADD, BF_REG_CTX,
                                -(int)sizeof(struct bf_program_context)));

    // Initialise the context to 0.
    r = bf_stub_memclear(program, BF_REG_CTX,
                         sizeof(struct bf_program_context));
    if (r)
        return r;

    // Save the program's argument into the context.
    EMIT(program,
         BPF_STX_MEM(BPF_DW, BF_REG_CTX, BF_ARG_1, BF_PROG_CTX_OFF(arg)));

    // Set slices registers to 0
    EMIT(program, BPF_MOV64_IMM(BF_REG_L2, 0));
    EMIT(program, BPF_MOV64_IMM(BF_REG_L3, 0));
    EMIT(program, BPF_MOV64_IMM(BF_REG_L4, 0));

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

    r = _bf_program_generate_runtime_init(program);
    if (r)
        return r;

    // Set default return value to ACCEPT.
    EMIT(program, BPF_MOV64_IMM(BF_REG_RET, ops->convert_return_code(
                                                BF_TARGET_STANDARD_ACCEPT)));

    r = ops->gen_inline_prologue(program);
    if (r)
        return r;

    bf_list_foreach (rules, rule_node) {
        struct bf_rule *rule = bf_list_node_get_data(rule_node);

        if (rule->ifindex != 0 && rule->ifindex != program->ifindex)
            continue;

        r = _bf_program_generate_rule(program, rule);
        if (r)
            return r;

        ++program->num_rules;
    }

    r = ops->gen_inline_epilogue(program);
    if (r)
        return r;

    r = _bf_program_fixup(program, BF_CODEGEN_FIXUP_END_OF_CHAIN, NULL);
    if (r)
        return bf_err_code(r, "failed to generate end of chain fixups");

    r = _bf_program_generate_functions(program);
    if (r)
        return r;

    r = _bf_program_fixup(program, BF_CODEGEN_FIXUP_FUNCTION_CALL, NULL);
    if (r)
        return bf_err_code(r, "failed to generate function call fixups");

    return 0;
}

int bf_program_load(struct bf_program *program, struct bf_program *prev_program)
{
    const struct bf_flavor_ops *ops =
        bf_flavor_ops_get(bf_hook_to_flavor(program->hook));
    union bf_flavor_attach_attr attr;
    _cleanup_close_ int map_fd = -1;
    _cleanup_close_ int prog_fd = -1;
    int r;

    assert(program);

    r = _bf_program_load_counters_map(program, &map_fd);
    if (r)
        return r;

    r = bf_bpf_prog_load(program->prog_name,
                         bf_hook_to_bpf_prog_type(program->hook), program->img,
                         program->img_size,
                         bf_hook_to_attach_type(program->hook), &prog_fd);
    if (r < 0)
        return r;

    r = ops->attach_prog_pre_unload(program, &prog_fd, &attr);
    if (r)
        return r;

    if (prev_program)
        bf_program_unload(prev_program);

    r = ops->attach_prog_post_unload(program, &prog_fd, &attr);
    if (r)
        return r;

    // Pin program
    r = bf_bpf_obj_pin(program->prog_pin_path, prog_fd);
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

    r = ops->detach_prog(program);
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
