// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#include "core/btf.h"

#include <bpf/btf.h>
#include <errno.h>
#include <stdlib.h>

#include "core/helper.h"
#include "core/logger.h"

static struct btf *_btf = NULL;

int bf_btf_setup(void)
{
    _btf = btf__load_vmlinux_btf();
    if (!_btf)
        return bf_err_code(errno, "failed to load vmlinux BTF");

    return 0;
}

void bf_btf_teardown(void)
{
    btf__free(_btf);
    _btf = NULL;
}

int bf_btf_get_id(const char *name)
{
    int id;

    bf_assert(name);

    id = btf__find_by_name(_btf, name);
    if (id < 0)
        return bf_err_code(errno, "failed to find BTF type for \"%s\"", name);

    return id;
}

int bf_btf_get_field_off(const char *struct_name, const char *field_name)
{
    int offset = -1;
    int struct_id;
    struct btf_member *member;
    const struct btf_type *type;

    struct_id = btf__find_by_name_kind(_btf, struct_name, BTF_KIND_STRUCT);
    if (struct_id < 0) {
        return bf_err_code(struct_id, "can't find structure '%s' in kernel BTF",
                           struct_name);
    }

    type = btf__type_by_id(_btf, struct_id);
    if (!type)
        return bf_err_code(errno, "can't get btf_type for '%s'", struct_name);

    member = (struct btf_member *)(type + 1);
    for (size_t i = 0; i < BTF_INFO_VLEN(type->info); ++i, ++member) {
        const char *cur_name = btf__name_by_offset(_btf, member->name_off);
        if (!cur_name || !bf_streq(cur_name, field_name))
            continue;

        if (BTF_INFO_KFLAG(type->info))
            offset = BTF_MEMBER_BIT_OFFSET(member->offset);
        else
            offset = member->offset;

        break;
    }

    if (offset < 0 || offset % 8)
        return -ENOENT;

    return offset / 8;
}
