// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2022 Meta Platforms, Inc. and affiliates.
 */

#include "cgen/prog/link.h"

#include <linux/bpf.h>
#include <linux/if_link.h>

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include <bpfilter/bpf.h>
#include <bpfilter/dump.h>
#include <bpfilter/flavor.h>
#include <bpfilter/helper.h>
#include <bpfilter/hook.h>
#include <bpfilter/logger.h>
#include <bpfilter/pack.h>

int bf_link_new(struct bf_link **link, const char *name)
{
    _free_bf_link_ struct bf_link *_link = NULL;

    assert(link);
    assert(name);
    assert(name[0] != '\0');

    _link = malloc(sizeof(*_link));
    if (!_link)
        return -ENOMEM;

    bf_strncpy(_link->name, BPF_OBJ_NAME_LEN, name);

    _link->hookopts = NULL;
    _link->fd = -1;
    _link->fd_extra = -1;

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

    assert(link);

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
        r = bf_bpf_obj_get("bf_link", dir_fd, &_link->fd);
        if (r)
            return bf_err_r(r, "failed to open pinned BPF link 'bf_link'");

        r = bf_bpf_obj_get("bf_link_extra", dir_fd, &_link->fd_extra);
        if (r && r != -ENOENT) {
            return bf_err_r(
                r, "failed to open pinned extra BPF link 'bf_link_extra'");
        }
    }

    *link = TAKE_PTR(_link);

    return 0;
}

void bf_link_free(struct bf_link **link)
{
    assert(link);

    if (!*link)
        return;

    bf_hookopts_free(&(*link)->hookopts);
    closep(&(*link)->fd);
    closep(&(*link)->fd_extra);
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
    assert(link);
    assert(prefix);

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
    DUMP(bf_dump_prefix_last(prefix), "fd_extra: %d", link->fd_extra);
    bf_dump_prefix_pop(prefix);
}

int bf_link_attach(struct bf_link *link, enum bf_hook hook,
                   struct bf_hookopts **hookopts, int prog_fd)
{
    _cleanup_close_ int fd = -1;
    _cleanup_close_ int fd_extra = -1;
    _cleanup_close_ int cgroup_fd = -1;
    struct bf_hookopts *_hookopts = *hookopts;
    int r;

    assert(link);
    assert(hookopts);

    switch (bf_hook_to_flavor(hook)) {
    case BF_FLAVOR_XDP:
        r = bf_bpf_link_create(prog_fd, _hookopts->ifindex, hook,
                               XDP_FLAGS_SKB_MODE, 0, 0);
        if (r < 0)
            return bf_err_r(r, "failed to create XDP BPF link");

        fd = r;
        break;
    case BF_FLAVOR_TC:
        r = bf_bpf_link_create(prog_fd, _hookopts->ifindex, hook, 0, 0, 0);
        if (r < 0)
            return bf_err_r(r, "failed to create TC BPF link");

        fd = r;
        break;
    case BF_FLAVOR_CGROUP:
        cgroup_fd = open(_hookopts->cgpath, O_DIRECTORY | O_RDONLY);
        if (cgroup_fd < 0) {
            return bf_err_r(errno, "failed to open cgroup '%s'",
                            _hookopts->cgpath);
        }

        r = bf_bpf_link_create(prog_fd, cgroup_fd, hook, 0, 0, 0);
        if (r < 0)
            return bf_err_r(r, "failed to create cgroup BPF link");

        fd = r;
        break;
    case BF_FLAVOR_NF:
        r = bf_bpf_link_create(prog_fd, 0, hook, 0, PF_INET,
                               _hookopts->priorities[0]);
        if (r < 0)
            return bf_err_r(r, "failed to create nf_inet BPF link");

        fd = r;

        r = bf_bpf_link_create(prog_fd, 0, hook, 0, PF_INET6,
                               _hookopts->priorities[0]);
        if (r < 0)
            return bf_err_r(r, "failed to create nf_inet6 BPF link");

        fd_extra = r;
        break;
    default:
        return -ENOTSUP;
    }

    link->fd = TAKE_FD(fd);
    link->fd_extra = TAKE_FD(fd_extra);
    link->hookopts = TAKE_PTR(*hookopts);

    return 0;
}

static int _bf_link_update_nf(struct bf_link *link, enum bf_hook hook,
                              int prog_fd)
{
    _cleanup_close_ int new_inet_fd = -1;
    _cleanup_close_ int new_inet6_fd = -1;
    struct bf_hookopts opts = *link->hookopts;
    int r;

    assert(link);

    // Attach new program to both inet4 and inet6 using the unused priority
    // This ensures the network is never left unfiltered
    r = bf_bpf_link_create(prog_fd, 0, hook, 0, PF_INET, opts.priorities[1]);
    if (r < 0)
        return bf_err_r(r, "failed to create nf_inet BPF link");
    new_inet_fd = r;

    r = bf_bpf_link_create(prog_fd, 0, hook, 0, PF_INET6, opts.priorities[1]);
    if (r < 0)
        return bf_err_r(r, "failed to create nf_inet6 BPF link");
    new_inet6_fd = r;

    // Detach old links - safe now that new ones are active
    closep(&link->fd);
    closep(&link->fd_extra);

    // Update link with new file descriptors
    link->fd = TAKE_FD(new_inet_fd);
    link->fd_extra = TAKE_FD(new_inet6_fd);

    // Swap priorities so priorities[0] reflects the currently active priority
    link->hookopts->priorities[0] = opts.priorities[1];
    link->hookopts->priorities[1] = opts.priorities[0];

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

    if (link->fd_extra > 0) {
        r = bf_bpf_link_detach(link->fd_extra);
        if (r) {
            bf_warn_r(
                r,
                "call to BPF_LINK_DETACH for extra link failed, closing the file descriptor and assuming the link is destroyed");
        }
    }

    bf_hookopts_free(&link->hookopts);
    closep(&link->fd);
    closep(&link->fd_extra);
}

int bf_link_pin(struct bf_link *link, int dir_fd)
{
    int r;

    bf_assert(link);
    bf_assert(dir_fd > 0);

    r = bf_bpf_obj_pin("bf_link", link->fd, dir_fd);
    if (r)
        return bf_err_r(r, "failed to pin BPF link");

    if (link->fd_extra > 0) {
        r = bf_bpf_obj_pin("bf_link_extra", link->fd_extra, dir_fd);
        if (r) {
            bf_link_unpin(link, dir_fd);
            return bf_err_r(r, "failed to pin extra BPF link");
        }
    }

    return 0;
}

void bf_link_unpin(struct bf_link *link, int dir_fd)
{
    int r;

    assert(link);
    assert(dir_fd > 0);

    (void)link;

    r = unlinkat(dir_fd, "bf_link", 0);
    if (r < 0 && errno != ENOENT) {
        // Do not warn on ENOENT, we want the file to be gone!
        bf_warn_r(errno,
                  "failed to unlink BPF link, assuming the link is not pinned");
    }

    r = unlinkat(dir_fd, "bf_link_extra", 0);
    if (r < 0 && errno != ENOENT) {
        // Do not warn on ENOENT, we want the file to be gone!
        bf_warn_r(
            errno,
            "failed to unlink extra BPF link, assuming the link is not pinned");
    }
}
