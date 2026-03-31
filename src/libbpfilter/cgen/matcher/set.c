/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2022 Meta Platforms, Inc. and affiliates.
 */

#include "cgen/matcher/set.h"

#include <bpfilter/chain.h>
#include <bpfilter/matcher.h>
#include <bpfilter/set.h>

#include "cgen/program.h"
#include "cgen/stub.h"

int bf_set_generate_map_lookup(struct bf_program *program,
                               const struct bf_matcher *matcher, int key_offset)
{
    assert(program);
    assert(matcher);

    EMIT_LOAD_SET_FD_FIXUP(program, BPF_REG_1,
                           *(uint32_t *)bf_matcher_payload(matcher));
    EMIT(program, BPF_MOV64_REG(BPF_REG_2, BPF_REG_10));
    EMIT(program, BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, key_offset));
    EMIT(program, BPF_EMIT_CALL(BPF_FUNC_map_lookup_elem));

    // Jump to the next rule if map_lookup_elem returned 0
    EMIT_FIXUP_JMP_NEXT_RULE(program, BPF_JMP_IMM(BPF_JEQ, BPF_REG_0, 0, 0));

    return 0;
}

int bf_set_generate_trie_lookup(struct bf_program *program,
                                const struct bf_matcher *matcher,
                                size_t src_offset, size_t addr_size)
{
    int r;

    assert(program);
    assert(matcher);

    EMIT(program, BPF_MOV64_IMM(BPF_REG_1, (uint32_t)(addr_size * 8)));
    EMIT(program,
         BPF_STX_MEM(BPF_W, BPF_REG_10, BPF_REG_1, BF_PROG_SCR_OFF(4)));

    r = bf_stub_load(program, src_offset, addr_size, BF_PROG_SCR_OFF(8));
    if (r)
        return r;

    return bf_set_generate_map_lookup(program, matcher, BF_PROG_SCR_OFF(4));
}

int bf_matcher_generate_set(struct bf_program *program,
                            const struct bf_matcher *matcher)
{
    assert(program);
    assert(matcher);

    const struct bf_set *set =
        bf_chain_get_set_for_matcher(program->runtime.chain, matcher);
    size_t offset = 0;
    int r;

    if (!set) {
        return bf_err_r(-ENOENT, "set #%u not found in %s",
                        *(uint32_t *)bf_matcher_payload(matcher),
                        program->runtime.chain->name);
    }

    if (set->use_trie) {
        const struct bf_matcher_meta *meta = bf_matcher_get_meta(set->key[0]);

        r = bf_stub_rule_check_protocol(program, meta);
        if (r)
            return bf_err_r(r, "failed to check for protocol");

        r = bf_stub_load_header(program, meta, BPF_REG_6);
        if (r)
            return bf_err_r(r, "failed to load protocol header into BPF_REG_6");

        return bf_set_generate_trie_lookup(
            program, matcher, meta->hdr_payload_offset, meta->hdr_payload_size);
    }

    // Ensure the packet uses the required protocols
    for (size_t i = 0; i < set->n_comps; ++i) {
        enum bf_matcher_type type = set->key[i];
        const struct bf_matcher_meta *meta = bf_matcher_get_meta(type);

        if (!meta) {
            return bf_err_r(-ENOENT, "meta for '%s' not found",
                            bf_matcher_type_to_str(type));
        }

        r = bf_stub_rule_check_protocol(program, meta);
        if (r)
            return bf_err_r(r, "failed to check for protocol");
    }

    // Generate the bytecode to build the set key
    for (size_t i = 0; i < set->n_comps; ++i) {
        enum bf_matcher_type type = set->key[i];
        const struct bf_matcher_meta *meta = bf_matcher_get_meta(type);

        if (!meta) {
            return bf_err_r(-ENOENT, "meta for '%s' not found",
                            bf_matcher_type_to_str(type));
        }

        r = bf_stub_load_header(program, meta, BPF_REG_6);
        if (r)
            return bf_err_r(r, "failed to load protocol header into BPF_REG_6");

        r = bf_stub_stx_payload(program, meta, offset);
        if (r) {
            return bf_err_r(r,
                            "failed to generate bytecode to load packet data");
        }

        offset += meta->hdr_payload_size;
    }

    return bf_set_generate_map_lookup(program, matcher, 0);
}
