/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#include "generator/program.h"

#include <net/if.h>

#include <linux/bpf.h>
#include <linux/bpf_common.h>
#include <linux/if_ether.h>
#include <linux/netfilter_ipv4/ip_tables.h>

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "core/bpf.h"
#include "core/btf.h"
#include "core/context.h"
#include "core/counter.h"
#include "core/flavor.h"
#include "core/logger.h"
#include "core/marsh.h"
#include "core/rule.h"
#include "core/verdict.h"
#include "generator/jmp.h"
#include "generator/matcher/ip.h"
#include "generator/matcher/tcp.h"
#include "generator/matcher/udp.h"
#include "generator/stub.h"
#include "shared/helper.h"

#define _BF_PROGRAM_DEFAULT_IMG_SIZE (1 << 6)

int bf_program_new(struct bf_program **program, int ifindex, enum bf_hook hook,
                   enum bf_front front)
{
    _cleanup_bf_program_ struct bf_program *_program = NULL;
    int r;

    bf_assert(ifindex);

    _program = calloc(1, sizeof(*_program));
    if (!_program)
        return -ENOMEM;

    _program->ifindex = ifindex;
    _program->hook = hook;
    _program->front = front;
    _program->runtime.ops = bf_flavor_ops_get(bf_hook_to_flavor(hook));

    snprintf(_program->prog_name, BPF_OBJ_NAME_LEN, "bf_prog_%02x%02x%02x",
             hook, front, ifindex);
    snprintf(_program->cmap_name, BPF_OBJ_NAME_LEN, "bf_cmap_%02x%02x%02x",
             hook, front, ifindex);
    snprintf(_program->pmap_name, BPF_OBJ_NAME_LEN, "bf_pmap_%02x%02x%02x",
             hook, front, ifindex);
    snprintf(_program->prog_pin_path, PIN_PATH_LEN,
             "/sys/fs/bpf/bf_prog_%02x%02x%02x", hook, front, ifindex);
    snprintf(_program->cmap_pin_path, PIN_PATH_LEN,
             "/sys/fs/bpf/bf_cmap_%02x%02x%02x", hook, front, ifindex);
    snprintf(_program->pmap_pin_path, PIN_PATH_LEN,
             "/sys/fs/bpf/bf_pmap_%02x%02x%02x", hook, front, ifindex);

    r = bf_printer_new(&_program->printer);
    if (r)
        return r;

    bf_list_init(&_program->fixups,
                 (bf_list_ops[]) {{.free = (bf_list_ops_free)bf_fixup_free}});

    _program->runtime.cmap_fd = -1;
    _program->runtime.prog_fd = -1;
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
    closep(&(*program)->runtime.cmap_fd);
    closep(&(*program)->runtime.pmap_fd);

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

    r |= bf_marsh_add_child_raw(&_marsh, &program->ifindex,
                                sizeof(program->ifindex));
    r |= bf_marsh_add_child_raw(&_marsh, &program->hook, sizeof(program->hook));
    r |= bf_marsh_add_child_raw(&_marsh, &program->front,
                                sizeof(program->front));

    {
        // Serialise bf_program.printer
        _cleanup_bf_marsh_ struct bf_marsh *child = NULL;

        r = bf_printer_marsh(program->printer, &child);
        if (r)
            return bf_err_code(r, "failed to marsh bf_printer object");

        r = bf_marsh_add_child_obj(&_marsh, child);
        if (r)
            return bf_err_code(r, "failed to append object to marsh");
    }

    r |= bf_marsh_add_child_raw(&_marsh, &program->num_counters,
                                sizeof(program->num_counters));
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

    bf_assert(marsh);
    bf_assert(program);

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

    // Unmarsh bf_program.printer
    child = bf_marsh_next_child(marsh, child);
    if (!child)
        return bf_err_code(-EINVAL, "failed to find valid child");

    freep(&_program->printer);
    r = bf_printer_new_from_marsh(&_program->printer, child);
    if (r)
        return bf_err_code(r, "failed to restore bf_printer object");

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

    r = bf_bpf_obj_get(_program->cmap_pin_path, &_program->runtime.cmap_fd);
    if (r < 0)
        return bf_err_code(r, "failed to get counter map fd");

    r = bf_bpf_obj_get(_program->prog_pin_path, &_program->runtime.prog_fd);
    if (r < 0)
        return bf_err_code(r, "failed to get prog fd");

    r = bf_bpf_obj_get(_program->pmap_pin_path, &_program->runtime.pmap_fd);
    if (r < 0)
        return bf_err_code(r, "failed to get printer map fd");

    *program = TAKE_PTR(_program);

    return 0;
}

void bf_program_dump(const struct bf_program *program, prefix_t *prefix)
{
    char ifname_buf[IF_NAMESIZE] = {};

    bf_assert(program);
    bf_assert(prefix);

    DUMP(prefix, "struct bf_program at %p", program);

    bf_dump_prefix_push(prefix);

    DUMP(prefix, "ifindex: %s", if_indextoname(program->ifindex, ifname_buf));
    DUMP(prefix, "hook: %s", bf_hook_to_str(program->hook));
    DUMP(prefix, "front: %s", bf_front_to_str(program->front));
    DUMP(prefix, "num_counters: %lu", program->num_counters);
    DUMP(prefix, "prog_name: %s", program->prog_name);
    DUMP(prefix, "cmap_name: %s", program->cmap_name);
    DUMP(prefix, "pmap_name: %s", program->pmap_name);
    DUMP(prefix, "prog_pin_path: %s",
         bf_opts_transient() ? "<transient>" : program->prog_pin_path);
    DUMP(prefix, "cmap_pin_path: %s",
         bf_opts_transient() ? "<transient>" : program->cmap_pin_path);
    DUMP(prefix, "pmap_pin_path: %s",
         bf_opts_transient() ? "<transient>" : program->pmap_pin_path);

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
    DUMP(prefix, "cmap_fd: %d", program->runtime.cmap_fd);
    DUMP(prefix, "pmap_fd: %d", program->runtime.pmap_fd);
    DUMP(bf_dump_prefix_last(prefix), "ops: %p", program->runtime.ops);
    bf_dump_prefix_pop(prefix);

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

    bf_assert(program);

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
        bf_assert(!insn->off);
        insn->off = v;
        break;
    case BF_CODEGEN_FIXUP_INSN_IMM:
        bf_assert(!insn->imm);
        insn->imm = v;
        break;
    default:
        bf_assert(0);
    }
}

static int _bf_program_fixup(struct bf_program *program,
                             enum bf_fixup_type type,
                             const union bf_fixup_attr *attr)
{
    bf_assert(program);
    bf_assert(type >= 0 && type < _BF_CODEGEN_FIXUP_MAX);

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
        case BF_CODEGEN_FIXUP_MAP_FD:
        case BF_CODEGEN_FIXUP_PRINTER_MAP_FD:
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
            bf_assert(0);
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
    int r;

    bf_assert(program);
    bf_assert(rule);

    bf_list_foreach (&rule->matchers, matcher_node) {
        struct bf_matcher *matcher = bf_list_node_get_data(matcher_node);

        switch (matcher->type) {
        case BF_MATCHER_IP_SRC_ADDR:
        case BF_MATCHER_IP_DST_ADDR:
        case BF_MATCHER_IP_PROTO:
            r = bf_matcher_generate_ip(program, matcher);
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
            return bf_err_code(-EINVAL, "unknown matcher type %d",
                               matcher->type);
        };
    }

    // BF_ARG_1: counters map file descriptor.
    if (rule->counters) {
        EMIT_FIXUP(program, BF_CODEGEN_FIXUP_MAP_FD,
                   BPF_MOV64_IMM(BF_ARG_1, 0));

        // BF_ARG_2: index of the current rule in counters map.
        EMIT(program, BPF_MOV32_IMM(BF_ARG_2, rule->index));

        // BF_ARG_3: packet size, from the context.
        EMIT(program, BPF_LDX_MEM(BPF_DW, BF_ARG_3, BF_REG_CTX,
                                  BF_PROG_CTX_OFF(pkt_size)));

        EMIT_FIXUP_CALL(program, BF_CODEGEN_FIXUP_FUNCTION_ADD_COUNTER);
    }

    EMIT(program, BPF_MOV64_IMM(BF_REG_RET, program->runtime.ops->get_verdict(
                                                rule->verdict)));
    EMIT(program, BPF_EXIT_INSN());

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
    {
        _cleanup_bf_jmpctx_ struct bf_jmpctx _ =
            bf_jmpctx_get(program, BPF_JMP_IMM(BPF_JNE, BF_REG_0, 0, 0));

        if (bf_opts_debug())
            EMIT_PRINT(program, "failed to fetch the rule's counters");

        EMIT(program, BPF_MOV32_IMM(BF_REG_0, 0));
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

        if (fixup->type != BF_CODEGEN_FIXUP_FUNCTION_CALL)
            continue;

        bf_assert(fixup->function >= 0 &&
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
            bf_assert(0);
            break;
        }

        program->functions_location[fixup->function] = off;
    }

    return 0;
}

static int _bf_program_load_counters_map(struct bf_program *program)
{
    _cleanup_close_ int _fd = -1;
    union bf_fixup_attr bf_attr = {};
    int r;

    bf_assert(program);

    r = bf_bpf_map_create(program->cmap_name, BPF_MAP_TYPE_ARRAY,
                          sizeof(uint32_t), sizeof(struct bf_counter),
                          program->num_counters, 0, &_fd);
    if (r < 0)
        return bf_err_code(errno, "failed to create counters map");

    bf_attr.map_fd = _fd;
    _bf_program_fixup(program, BF_CODEGEN_FIXUP_MAP_FD, &bf_attr);

    program->runtime.cmap_fd = TAKE_FD(_fd);

    return 0;
}

static int _bf_program_load_printer_map(struct bf_program *program)
{
    _cleanup_free_ void *pstr = NULL;
    _cleanup_close_ int fd = -1;
    size_t pstr_len;
    union bf_fixup_attr fixup_attr = {};
    int r;

    bf_assert(program);

    r = bf_printer_assemble(program->printer, &pstr, &pstr_len);
    if (r)
        return bf_err_code(r, "failed to assemble printer map string");

    r = bf_bpf_map_create(program->pmap_name, BPF_MAP_TYPE_ARRAY,
                          sizeof(uint32_t), pstr_len, 1, BPF_F_RDONLY_PROG,
                          &fd);
    if (r)
        return bf_err_code(r, "failed to create printer map");

    r = bf_bpf_map_update_elem(fd, (void *)(uint32_t[]) {0}, pstr);
    if (r)
        return bf_err_code(r, "failed to insert messages in printer map");

    fixup_attr.map_fd = fd;
    r = _bf_program_fixup(program, BF_CODEGEN_FIXUP_PRINTER_MAP_FD,
                          &fixup_attr);
    if (r)
        return bf_err_code(r, "can't update instruction with printer map fd");

    program->runtime.pmap_fd = TAKE_FD(fd);

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
                          struct bpf_insn insn)
{
    _cleanup_bf_fixup_ struct bf_fixup *fixup = NULL;
    int r;

    bf_assert(program);

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

    bf_assert(program);

    if (program->img_size == program->img_cap) {
        r = bf_program_grow_img(program);
        if (r)
            return r;
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

int bf_program_generate(struct bf_program *program, bf_list *rules,
                        enum bf_verdict policy)
{
    char ifname_buf[IFNAMSIZ] = {};
    int r;

    bf_info("generating %s program for %s::%s::%s",
            bf_flavor_to_str(bf_hook_to_flavor(program->hook)),
            bf_front_to_str(program->front), bf_hook_to_str(program->hook),
            if_indextoname(program->ifindex, ifname_buf));

    r = _bf_program_generate_runtime_init(program);
    if (r)
        return r;

    // Set default return value to ACCEPT.
    EMIT(program, BPF_MOV64_IMM(BF_REG_RET, program->runtime.ops->get_verdict(
                                                BF_VERDICT_ACCEPT)));

    r = program->runtime.ops->gen_inline_prologue(program);
    if (r)
        return r;

    bf_list_foreach (rules, rule_node) {
        struct bf_rule *rule = bf_list_node_get_data(rule_node);

        if (rule->ifindex != 0 && rule->ifindex != program->ifindex)
            continue;

        r = _bf_program_generate_rule(program, rule);
        if (r)
            return r;
    }

    r = program->runtime.ops->gen_inline_epilogue(program);
    if (r)
        return r;

    // BF_ARG_1: counters map file descriptor.
    EMIT_FIXUP(program, BF_CODEGEN_FIXUP_MAP_FD, BPF_MOV64_IMM(BF_ARG_1, 0));

    // BF_ARG_2: index of the current rule in counters map.
    EMIT(program, BPF_MOV32_IMM(BF_ARG_2, bf_list_size(rules)));

    // BF_ARG_3: packet size, from the context.
    EMIT(program,
         BPF_LDX_MEM(BPF_DW, BF_ARG_3, BF_REG_CTX, BF_PROG_CTX_OFF(pkt_size)));

    EMIT_FIXUP_CALL(program, BF_CODEGEN_FIXUP_FUNCTION_ADD_COUNTER);

    EMIT(program,
         BPF_MOV64_IMM(BF_REG_RET, program->runtime.ops->get_verdict(policy)));
    EMIT(program, BPF_EXIT_INSN());

    r = _bf_program_generate_functions(program);
    if (r)
        return r;

    r = _bf_program_fixup(program, BF_CODEGEN_FIXUP_FUNCTION_CALL, NULL);
    if (r)
        return bf_err_code(r, "failed to generate function call fixups");

    // Add 1 to the number of counters for the policy counter.
    program->num_counters = bf_list_size(rules) + 1;

    return 0;
}

/**
 * Pin the BPF objects that should survive the daemon's lifetime.
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
        return bf_err_code(r, "failed to pin program fd to %s",
                           program->prog_pin_path);
    }

    r = bf_bpf_obj_pin(program->cmap_pin_path, program->runtime.cmap_fd);
    if (r < 0) {
        return bf_err_code(r, "failed to pin counter map fd to %s",
                           program->cmap_pin_path);
    }

    r = bf_bpf_obj_pin(program->pmap_pin_path, program->runtime.pmap_fd);
    if (r < 0) {
        return bf_err_code(r, "failed to pin printer map fd to %s",
                           program->pmap_pin_path);
    }
    return 0;
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
    unlink(program->cmap_pin_path);
    unlink(program->pmap_pin_path);
}

int bf_program_load(struct bf_program *new_prog, struct bf_program *old_prog)
{
    int r;

    bf_assert(new_prog);

    r = _bf_program_load_counters_map(new_prog);
    if (r)
        return r;

    r = _bf_program_load_printer_map(new_prog);
    if (r)
        return r;

    r = new_prog->runtime.ops->attach_prog(new_prog, old_prog);
    if (r)
        return r;

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
    closep(&program->runtime.cmap_fd);
    closep(&program->runtime.pmap_fd);

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

    r = bf_bpf_map_lookup_elem(program->runtime.cmap_fd, &counter_idx, counter);
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
