// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#include "bpfilter/btf.h"

#include <linux/btf.h>

#include <bpf/btf.h>
#include <errno.h>
#include <limits.h>
#include <stddef.h>
#include <stdlib.h>

#include "bpfilter/helper.h"
#include "bpfilter/logger.h"

static struct btf *_bf_btf = NULL;

int bf_btf_setup(void)
{
    _bf_btf = btf__load_vmlinux_btf();
    if (!_bf_btf)
        return bf_err_r(errno, "failed to load vmlinux BTF");

    return 0;
}

void bf_btf_teardown(void)
{
    btf__free(_bf_btf);
    _bf_btf = NULL;
}

int bf_btf_get_id(const char *name)
{
    int id;

    assert(name);

    id = btf__find_by_name(_bf_btf, name);
    if (id < 0)
        return bf_err_r(errno, "failed to find BTF type for \"%s\"", name);

    return id;
}

const char *bf_btf_get_name(int id)
{
    const struct btf_type *type;

    type = btf__type_by_id(_bf_btf, id);
    if (!type) {
        bf_warn("can't find BTF type ID %d", id);
        return NULL;
    }

    return btf__name_by_offset(_bf_btf, type->name_off);
}

int bf_btf_kernel_has_token(void)
{
    int bpf_attr_id;
    const struct btf_type *bpf_attr_type;
    const struct btf_member *bpf_attr_members;

    bpf_attr_id = btf__find_by_name_kind(_bf_btf, "bpf_attr", BTF_KIND_UNION);
    if (bpf_attr_id < 0) {
        return bf_err_r(bpf_attr_id,
                        "can't find structure 'bpf_attr' in kernel BTF");
    }

    bpf_attr_type = btf__type_by_id(_bf_btf, bpf_attr_id);
    if (!bpf_attr_type)
        return bf_err_r(-EINVAL, "failed to request 'bpf_attr' BTF type");

    bpf_attr_members = btf_members(bpf_attr_type);
    // Iterate through union members
    for (unsigned short i = 0; i < btf_vlen(bpf_attr_type); i++) {
        const struct btf_type *member_type =
            btf__type_by_id(_bf_btf, bpf_attr_members[i].type);
        const struct btf_member *m_members = btf_members(member_type);

        // We are looking for an anonymous structure
        if (!btf_is_struct(member_type) || bpf_attr_members[i].name_off != 0)
            continue;

        for (int j = 0; j < btf_vlen(member_type); j++) {
            const char *member_name =
                btf__name_by_offset(_bf_btf, m_members[j].name_off);

            if (member_name && bf_streq(member_name, "prog_token_fd"))
                return 0;
        }
    }

    return -ENOENT;
}

#define _bf_btf_type_is_compound(type)                                         \
    (BTF_INFO_KIND((type)->info) == BTF_KIND_UNION ||                          \
     BTF_INFO_KIND((type)->info) == BTF_KIND_STRUCT)

/**
 * @brief Find the offset of `field_name` in BTF type ID `compound_id`.
 *
 * @param compound_id Compound BTF type id.
 * @param field_name Name of the field to find the offset of. Can't be NULL.
 * @return Offset (in bits) of `field_name` in `compound_id` BTF type.
 */
static ssize_t _bf_btf_offset_in_compound(uint32_t compound_id,
                                          const char *field_name)
{
    ssize_t offset;
    const struct btf_type *compound_type, *member_type;
    const struct btf_member *member;

    assert(field_name);

    compound_type = btf__type_by_id(_bf_btf, compound_id);
    if (!compound_type)
        return -errno;

    if (!_bf_btf_type_is_compound(compound_type))
        return -ENOTSUP;

    member = (const struct btf_member *)(compound_type + 1);
    for (size_t i = 0; i < BTF_INFO_VLEN(compound_type->info); ++i, ++member) {
        const char *name = btf__name_by_offset(_bf_btf, member->name_off);

        member_type = btf__type_by_id(_bf_btf, member->type);
        if (!member_type)
            return -errno;

        // Member is an anonymous compound type? Check its members
        if (*name == '\0' && _bf_btf_type_is_compound(member_type)) {
            offset = _bf_btf_offset_in_compound(member->type, field_name);
            if (offset < 0)
                continue;

            if (BTF_MEMBER_BIT_OFFSET(member->offset) % 8) {
                // Assuming this is not possible, but who knows
                return bf_err_r(-ENOTSUP,
                                "anonymous compound parent is a bitfield");
            }

            if (BTF_INFO_KFLAG(compound_type->info))
                offset += BTF_MEMBER_BIT_OFFSET(member->offset);
            else
                offset += member->offset;

            return offset;
        }

        if (!bf_streq(name, field_name))
            continue;

        offset = (ssize_t)member->offset;
        if (BTF_INFO_KFLAG(compound_type->info))
            offset = BTF_MEMBER_BIT_OFFSET(member->offset);

        return offset;
    }

    return -EINVAL;
}

static int _bf_btf_get_compound_type_id(const char *name)
{
    int compound_id;

    compound_id = btf__find_by_name_kind(_bf_btf, name, BTF_KIND_STRUCT);
    if (compound_id < 0 && compound_id != -ENOENT)
        return compound_id;
    if (compound_id >= 0)
        return compound_id;

    compound_id = btf__find_by_name_kind(_bf_btf, name, BTF_KIND_UNION);
    if (compound_id < 0 && compound_id != -ENOENT)
        return compound_id;

    return compound_id;
}

int bf_btf_get_field_off(const char *struct_name, const char *field_name)
{
    int id;
    ssize_t offset;

    assert(struct_name);
    assert(field_name);

    id = _bf_btf_get_compound_type_id(struct_name);
    if (id < 0)
        return bf_err_r(id, "failed to find BTF type ID for '%s'", struct_name);

    offset = _bf_btf_offset_in_compound(id, field_name);
    if (offset < 0) {
        return bf_err_r((int)offset, "failed to find offset of %s.%s",
                        struct_name, field_name);
    }
    if (offset % 8) {
        return bf_err_r(-EINVAL, "%s.%s has a bit offset", struct_name,
                        field_name);
    }
    if (offset / 8 > INT_MAX) {
        return bf_err_r(-E2BIG, "%s.%s has an offset bigger than %d",
                        struct_name, field_name, INT_MAX);
    }

    return (int)(offset / 8);
}
