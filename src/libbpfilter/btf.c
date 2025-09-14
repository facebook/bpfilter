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

    bf_assert(name);

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

int bf_btf_get_field_off(const char *struct_name, const char *field_name)
{
    int offset = -1;
    int struct_id;
    struct btf_member *member;
    const struct btf_type *type;

    struct_id = btf__find_by_name_kind(_bf_btf, struct_name, BTF_KIND_STRUCT);
    if (struct_id < 0) {
        return bf_err_r(struct_id, "can't find structure '%s' in kernel BTF",
                        struct_name);
    }

    type = btf__type_by_id(_bf_btf, struct_id);
    if (!type)
        return bf_err_r(errno, "can't get btf_type for '%s'", struct_name);

    member = (struct btf_member *)(type + 1);
    for (size_t i = 0; i < BTF_INFO_VLEN(type->info); ++i, ++member) {
        const char *cur_name = btf__name_by_offset(_bf_btf, member->name_off);
        if (!cur_name || !bf_streq(cur_name, field_name))
            continue;

        if (BTF_INFO_KFLAG(type->info)) {
            offset = BTF_MEMBER_BIT_OFFSET(member->offset);
        } else {
            if (member->offset > INT_MAX) {
                return bf_err_r(-E2BIG, "BTF member offset is too big: %u",
                                member->offset);
            }
            offset = (int)member->offset;
        }

        break;
    }

    if (offset < 0 || offset % 8)
        return -ENOENT;

    return offset / 8;
}
