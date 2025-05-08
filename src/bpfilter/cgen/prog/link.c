// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2022 Meta Platforms, Inc. and affiliates.
 */

#include "bpfilter/cgen/prog/link.h"

#include <linux/bpf.h>

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
#include "core/marsh.h"

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

int bf_link_new_from_marsh(struct bf_link **link, int dir_fd,
                           const struct bf_marsh *marsh)
{
    _free_bf_link_ struct bf_link *_link = NULL;
    _free_bf_hookopts_ struct bf_hookopts *hookopts = NULL;
    struct bf_marsh *child = NULL;
    int r;

    bf_assert(link && marsh);

    _link = malloc(sizeof(*_link));
    if (!_link)
        return -ENOMEM;

    _link->hookopts = NULL;
    _link->fd = -1;

    if (!(child = bf_marsh_next_child(marsh, child)))
        return -EINVAL;
    memcpy(&_link->name, child->data, BPF_OBJ_NAME_LEN);

    if (!(child = bf_marsh_next_child(marsh, child)))
        return -EINVAL;
    if (!bf_marsh_is_empty(child)) {
        r = bf_hookopts_new_from_marsh(&_link->hookopts, child);
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

int bf_link_marsh(const struct bf_link *link, struct bf_marsh **marsh)
{
    _cleanup_bf_marsh_ struct bf_marsh *_marsh = NULL;
    int r;

    bf_assert(link && marsh);

    r = bf_marsh_new(&_marsh, NULL, 0);
    if (r)
        return r;

    r = bf_marsh_add_child_raw(&_marsh, &link->name, BPF_OBJ_NAME_LEN);
    if (r)
        return r;

    // Serialize link.hookopts
    if (link->hookopts) {
        _cleanup_bf_marsh_ struct bf_marsh *hookopts_elem = NULL;

        r = bf_hookopts_marsh(link->hookopts, &hookopts_elem);
        if (r < 0)
            return r;

        r = bf_marsh_add_child_obj(&_marsh, hookopts_elem);
        if (r < 0)
            return r;
    } else {
        r = bf_marsh_add_child_raw(&_marsh, NULL, 0);
        if (r)
            return r;
    }

    *marsh = TAKE_PTR(_marsh);

    return 0;
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

static int _bf_link_attach_xdp(struct bf_link *link, enum bf_hook hook,
                               const struct bf_hookopts *hookopts, int prog_fd)
{
    union bpf_attr attr;
    int r;

    UNUSED(hook);

    memset(&attr, 0, sizeof(attr));

    attr.link_create.prog_fd = prog_fd;
    attr.link_create.target_fd = hookopts->ifindex;
    attr.link_create.attach_type = BPF_XDP;
    attr.link_create.flags = BF_XDP_MODE_SKB;

    r = bf_bpf(BPF_LINK_CREATE, &attr);
    if (r < 0)
        return r;

    link->fd = r;

    return 0;
}

static int _bf_link_attach_tc(struct bf_link *link, enum bf_hook hook,
                              const struct bf_hookopts *hookopts, int prog_fd)
{
    union bpf_attr attr;
    int r;

    UNUSED(hook);

    memset(&attr, 0, sizeof(attr));

    attr.link_create.prog_fd = prog_fd;
    attr.link_create.target_fd = hookopts->ifindex;
    attr.link_create.attach_type = bf_hook_to_bpf_attach_type(hook);

    r = bf_bpf(BPF_LINK_CREATE, &attr);
    if (r < 0)
        return r;

    link->fd = r;

    return 0;
}

static int _bf_link_attach_nf(struct bf_link *link, enum bf_hook hook,
                              const struct bf_hookopts *hookopts, int prog_fd)
{
    union bpf_attr attr;
    int r;

    memset(&attr, 0, sizeof(attr));

    attr.link_create.prog_fd = prog_fd;
    attr.link_create.attach_type = BPF_NETFILTER;
    attr.link_create.netfilter.pf = hookopts->family;
    attr.link_create.netfilter.hooknum = bf_hook_to_nf_hook(hook);
    attr.link_create.netfilter.priority = hookopts->priorities[0];

    r = bf_bpf(BPF_LINK_CREATE, &attr);
    if (r < 0)
        return r;

    link->fd = r;

    return 0;
}

static int _bf_link_attach_cgroup(struct bf_link *link, enum bf_hook hook,
                                  const struct bf_hookopts *hookopts,
                                  int prog_fd)
{
    _cleanup_close_ int cgroup_fd = -1;
    union bpf_attr attr;
    int r;

    memset(&attr, 0, sizeof(attr));

    attr.link_create.prog_fd = prog_fd;
    attr.link_create.attach_type = bf_hook_to_bpf_attach_type(hook);

    cgroup_fd = open(hookopts->cgpath, O_DIRECTORY | O_RDONLY);
    if (cgroup_fd < 0)
        return bf_err_r(errno, "failed to open cgroup '%s'", hookopts->cgpath);

    attr.link_create.target_fd = cgroup_fd;

    r = bf_bpf(BPF_LINK_CREATE, &attr);
    if (r < 0)
        return r;

    link->fd = r;

    return 0;
}

int bf_link_attach(struct bf_link *link, enum bf_hook hook,
                   struct bf_hookopts **hookopts, int prog_fd)
{
    int r;

    bf_assert(link && hookopts);

    switch (bf_hook_to_flavor(hook)) {
    case BF_FLAVOR_XDP:
        r = _bf_link_attach_xdp(link, hook, *hookopts, prog_fd);
        break;
    case BF_FLAVOR_TC:
        r = _bf_link_attach_tc(link, hook, *hookopts, prog_fd);
        break;
    case BF_FLAVOR_CGROUP:
        r = _bf_link_attach_cgroup(link, hook, *hookopts, prog_fd);
        break;
    case BF_FLAVOR_NF:
        r = _bf_link_attach_nf(link, hook, *hookopts, prog_fd);
        break;
    default:
        return -ENOTSUP;
    }

    if (r)
        return r;

    link->hookopts = TAKE_PTR(*hookopts);

    return 0;
}

static int _bf_link_update(struct bf_link *link, enum bf_hook hook, int prog_fd)
{
    union bpf_attr attr;

    UNUSED(hook);

    bf_assert(link);

    memset(&attr, 0, sizeof(attr));

    attr.link_update.link_fd = link->fd;
    attr.link_update.new_prog_fd = prog_fd;

    return bf_bpf(BPF_LINK_UPDATE, &attr);
}

static int _bf_link_update_nf(struct bf_link *link, enum bf_hook hook,
                              int prog_fd)
{
    _cleanup_close_ int new_link_fd = -1;
    union bpf_attr attr;
    int priorities[2];

    bf_assert(link);

    memset(&attr, 0, sizeof(attr));

    attr.link_create.prog_fd = prog_fd;
    attr.link_create.attach_type = BPF_NETFILTER;

    memcpy(priorities, link->hookopts->priorities, sizeof(priorities));

    attr.link_create.netfilter.pf = link->hookopts->family;
    attr.link_create.netfilter.hooknum = bf_hook_to_nf_hook(hook);
    attr.link_create.netfilter.priority = priorities[1];

    new_link_fd = bf_bpf(BPF_LINK_CREATE, &attr);
    if (new_link_fd < 0)
        return new_link_fd;

    // Swap priorities, so priorities[0] is the one currently used
    link->hookopts->priorities[0] = priorities[1];
    link->hookopts->priorities[1] = priorities[0];

    return 0;
}

int bf_link_update(struct bf_link *link, enum bf_hook hook, int prog_fd)
{
    int r;

    bf_assert(link);

    switch (bf_hook_to_flavor(hook)) {
    case BF_FLAVOR_XDP:
    case BF_FLAVOR_TC:
    case BF_FLAVOR_CGROUP:
        r = _bf_link_update(link, hook, prog_fd);
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
    union bpf_attr attr;
    int r;

    bf_assert(link);

    memset(&attr, 0, sizeof(attr));

    attr.link_detach.link_fd = link->fd;

    r = bf_bpf(BPF_LINK_DETACH, &attr);
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
