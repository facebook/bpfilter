// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2022 Meta Platforms, Inc. and affiliates.
 */

#include "bpfilter/cgen/prog/link.h"

#include <linux/bpf.h>
#include <linux/if_link.h>

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "core/bpf.h"
#include "core/dump.h"
#include "core/flavor.h"
#include "core/helper.h"
#include "core/hook.h"
#include "core/logger.h"
#include "core/pack.h"

int bf_link_new(struct bf_link **link, const char *name)
{
    _free_bf_link_ struct bf_link *_link = NULL;

    bf_assert(link && name);
    bf_assert(name[0] != '\0');

    _link = malloc(sizeof(*_link));
    if (!_link)
        return -ENOMEM;

    bf_strncpy(_link->name, BPF_OBJ_NAME_LEN, name);

    _link->hookopts = NULL;
    _link->fd = -1;

    *link = TAKE_PTR(_link);

    return 0;
}

int bf_link_new_from_pack(struct bf_link **link, int dir_fd,
                          bf_rpack_node_t node)
{
    _free_bf_link_ struct bf_link *_link = NULL;
    _cleanup_free_ char *name = NULL;
    bf_rpack_node_t child;
    int r;

    bf_assert(link);

    r = bf_rpack_kv_str(node, "name", &name);
    if (r)
        return bf_rpack_key_err(r, "bf_link.name");

    r = bf_link_new(&_link, name);
    if (r)
        return bf_err_r(r, "failed to create bf_link from pack");

    r = bf_rpack_kv_node(node, "hookopts", &child);
    if (r)
        return bf_rpack_key_err(r, "bf_link.hookopts");
    if (!bf_rpack_is_nil(child)) {
        r = bf_hookopts_new_from_pack(&_link->hookopts, child);
        if (r)
            return r;
    }

    if (dir_fd != -1) {
        r = bf_bpf_obj_get(_link->name, dir_fd, &_link->fd);
        if (r) {
            return bf_err_r(r, "failed to open pinned BPF link '%s'",
                            _link->name);
        }
    }

    *link = TAKE_PTR(_link);

    return 0;
}

void bf_link_free(struct bf_link **link)
{
    bf_assert(link);

    if (!*link)
        return;

    bf_hookopts_free(&(*link)->hookopts);
    closep(&(*link)->fd);
    freep((void *)link);
}

int bf_link_pack(const struct bf_link *link, bf_wpack_t *pack)
{
    bf_assert(link);
    bf_assert(pack);

    bf_wpack_kv_str(pack, "name", link->name);

    if (link->hookopts) {
        bf_wpack_open_object(pack, "hookopts");
        bf_hookopts_pack(link->hookopts, pack);
        bf_wpack_close_object(pack);
    } else {
        bf_wpack_kv_nil(pack, "hookopts");
    }

    return bf_wpack_is_valid(pack) ? 0 : -EINVAL;
}

void bf_link_dump(const struct bf_link *link, prefix_t *prefix)
{
    bf_assert(link && prefix);

    DUMP(prefix, "struct bf_link at %p", link);

    bf_dump_prefix_push(prefix);
    DUMP(prefix, "name: %s", link->name);

    if (link->hookopts) {
        DUMP(prefix, "hookopts: struct bf_hookopts *");
        bf_dump_prefix_push(prefix);
        bf_hookopts_dump(link->hookopts, prefix);
        bf_dump_prefix_pop(prefix);
    } else {
        DUMP(prefix, "hookopts: struct bf_hookopts * (NULL)");
    }

    DUMP(bf_dump_prefix_last(prefix), "fd: %d", link->fd);
    bf_dump_prefix_pop(prefix);
}

int bf_link_attach(struct bf_link *link, enum bf_hook hook,
                   struct bf_hookopts **hookopts, int prog_fd)
{
    bf_assert(link && hookopts);

    _cleanup_close_ int cgroup_fd = -1;
    struct bf_hookopts *_hookopts = *hookopts;
    int r;

    switch (bf_hook_to_flavor(hook)) {
    case BF_FLAVOR_XDP:
        r = bf_bpf_link_create(prog_fd, _hookopts->ifindex, hook, _hookopts,
                               XDP_FLAGS_SKB_MODE);
        break;
    case BF_FLAVOR_TC:
        r = bf_bpf_link_create(prog_fd, _hookopts->ifindex, hook, _hookopts, 0);
        break;
    case BF_FLAVOR_CGROUP:
        cgroup_fd = open(_hookopts->cgpath, O_DIRECTORY | O_RDONLY);
        if (cgroup_fd < 0) {
            return bf_err_r(errno, "failed to open cgroup '%s'",
                            _hookopts->cgpath);
        }

        r = bf_bpf_link_create(prog_fd, cgroup_fd, hook, _hookopts, 0);
        break;
    case BF_FLAVOR_NF:
        r = bf_bpf_link_create(prog_fd, 0, hook, _hookopts, 0);
        break;
    default:
        return -ENOTSUP;
    }

    if (r < 0)
        return r;

    link->fd = r;
    link->hookopts = TAKE_PTR(*hookopts);

    return 0;
}

static int _bf_link_update_nf(struct bf_link *link, enum bf_hook hook,
                              int prog_fd)
{
    bf_assert(link);

    _cleanup_close_ int new_link_fd = -1;
    struct bf_hookopts opts = *link->hookopts;

    opts.priorities[0] = link->hookopts->priorities[1];
    opts.priorities[1] = link->hookopts->priorities[0];

    new_link_fd = bf_bpf_link_create(prog_fd, 0, hook, &opts, 0);
    if (new_link_fd < 0)
        return new_link_fd;

    // Swap priorities, so priorities[0] is the one currently used
    link->hookopts->priorities[0] = opts.priorities[0];
    link->hookopts->priorities[1] = opts.priorities[1];

    return 0;
}

int bf_link_update(struct bf_link *link, enum bf_hook hook, int prog_fd)
{
    bf_assert(link);

    int r;

    switch (bf_hook_to_flavor(hook)) {
    case BF_FLAVOR_XDP:
    case BF_FLAVOR_TC:
    case BF_FLAVOR_CGROUP:
        r = bf_bpf_link_update(link->fd, prog_fd);
        break;
    case BF_FLAVOR_NF:
        r = _bf_link_update_nf(link, hook, prog_fd);
        break;
    default:
        return -ENOTSUP;
    }

    return r;
}

void bf_link_detach(struct bf_link *link)
{
    bf_assert(link);

    int r;

    r = bf_bpf_link_detach(link->fd);
    if (r) {
        bf_warn_r(
            r,
            "call to BPF_LINK_DETACH failed, closing the file descriptor and assuming the link is destroyed");
    }

    bf_hookopts_free(&link->hookopts);
    closep(&link->fd);
}

int bf_link_pin(struct bf_link *link, int dir_fd)
{
    int r;

    bf_assert(link);
    bf_assert(dir_fd > 0);

    r = bf_bpf_obj_pin(link->name, link->fd, dir_fd);
    if (r)
        return bf_err_r(r, "failed to pin BPF link '%s'", link->name);

    return 0;
}

void bf_link_unpin(struct bf_link *link, int dir_fd)
{
    int r;

    bf_assert(link);
    bf_assert(dir_fd > 0);

    r = unlinkat(dir_fd, link->name, 0);
    if (r < 0 && errno != ENOENT) {
        // Do not warn on ENOENT, we want the file to be gone!
        bf_warn_r(
            errno,
            "failed to unlink BPF link '%s', assuming the link is not pinned",
            link->name);
    }
}
