// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#include "core/btf.h"

#include <bpf/btf.h>
#include <errno.h>
#include <stdlib.h>

#include "core/logger.h"
#include "shared/helper.h"

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
