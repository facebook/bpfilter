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
#include "core/helper.h"
#include "core/hook.h"
#include "core/logger.h"
#include "core/marsh.h"

int bf_link_new(struct bf_link **link, const char *name, enum bf_hook hook)
{
    _cleanup_bf_link_ struct bf_link *_link = NULL;

    bf_assert(link && name);
    bf_assert(name[0] != '\0');

    _link = malloc(sizeof(*_link));
    if (!_link)
        return -ENOMEM;

    bf_strncpy(_link->name, BPF_OBJ_NAME_LEN, name);

    _link->fd = -1;
    _link->hook = hook;

    *link = TAKE_PTR(_link);

    return 0;
}

int bf_link_new_from_marsh(struct bf_link **link, int dir_fd,
                           const struct bf_marsh *marsh)
{
    _cleanup_bf_link_ struct bf_link *_link = NULL;
    struct bf_marsh *elem = NULL;
    int r;

    bf_assert(link && marsh);

    _link = malloc(sizeof(*_link));
    if (!_link)
        return -ENOMEM;

    _link->fd = -1;

    if (!(elem = bf_marsh_next_child(marsh, elem)))
        return -EINVAL;
    memcpy(&_link->name, elem->data, BPF_OBJ_NAME_LEN);

    if (!(elem = bf_marsh_next_child(marsh, elem)))
        return -EINVAL;
    memcpy(&_link->hook, elem->data, sizeof(_link->hook));

    if (bf_marsh_next_child(marsh, elem))
        return bf_err_r(-E2BIG, "too many elements in bf_link marsh");

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

    r = bf_marsh_add_child_raw(&_marsh, &link->hook, sizeof(link->hook));
    if (r)
        return r;

    *marsh = TAKE_PTR(_marsh);

    return 0;
}

void bf_link_dump(const struct bf_link *link, prefix_t *prefix)
{
    bf_assert(link && prefix);

    DUMP(prefix, "struct bf_link at %p", link);

    bf_dump_prefix_push(prefix);
    DUMP(prefix, "name: %s", link->name);
    DUMP(prefix, "fd: %d", link->fd);
    DUMP(bf_dump_prefix_last(prefix), "hook: %s", bf_hook_to_str(link->hook));
    bf_dump_prefix_pop(prefix);
}

int bf_link_attach_xdp(struct bf_link *link, int prog_fd, unsigned int ifindex,
                       enum bf_xdp_attach_mode mode)
{
    union bpf_attr attr = {
        .link_create =
            {
                .prog_fd = prog_fd,
                .target_fd = ifindex,
                .attach_type = BPF_XDP,
                .flags = mode,
            },
    };
    int r;

    r = bf_bpf(BPF_LINK_CREATE, &attr);
    if (r < 0)
        return r;

    link->fd = r;

    return 0;
}

int bf_link_attach_tc(struct bf_link *link, int prog_fd, unsigned int ifindex)
{
    union bpf_attr attr = {
        .link_create =
            {
                .prog_fd = prog_fd,
                .target_fd = ifindex,
                .attach_type = bf_hook_to_attach_type(link->hook),
            },
    };
    int r;

    r = bf_bpf(BPF_LINK_CREATE, &attr);
    if (r < 0)
        return r;

    link->fd = r;

    return 0;
}

int bf_link_attach_nf(struct bf_link *link, int prog_fd, unsigned int family,
                      int priority)
{
    union bpf_attr attr = {
        .link_create =
            {
                .prog_fd = prog_fd,
                .attach_type = BPF_NETFILTER,
                .netfilter =
                    {
                        .pf = family,
                        .hooknum = bf_hook_to_nf_hook(link->hook),
                        .priority = priority,
                    },
            },
    };
    int r;

    r = bf_bpf(BPF_LINK_CREATE, &attr);
    if (r < 0)
        return r;

    link->fd = r;

    return 0;
}

int bf_link_attach_cgroup(struct bf_link *link, int prog_fd,
                          const char *cgroup_path)
{
    _cleanup_close_ int cgroup_fd = -1;
    union bpf_attr attr = {
        .link_create =
            {
                .prog_fd = prog_fd,
                .attach_type = bf_hook_to_attach_type(link->hook),
            },
    };
    int r;

    cgroup_fd = open(cgroup_path, O_DIRECTORY | O_RDONLY);
    if (cgroup_fd < 0)
        return bf_err_r(errno, "failed to open cgroup '%s'", cgroup_path);

    attr.link_create.target_fd = cgroup_fd;

    r = bf_bpf(BPF_LINK_CREATE, &attr);
    if (r < 0)
        return r;

    link->fd = r;

    return 0;
}

int bf_link_update(struct bf_link *link, int new_prog_fd)
{
    union bpf_attr attr = {
        .link_update.link_fd = link->fd,
        .link_update.new_prog_fd = new_prog_fd,
    };

    return bf_bpf(BPF_LINK_UPDATE, &attr);
}

int bf_link_detach(struct bf_link *link)
{
    union bpf_attr attr = {
        .link_detach.link_fd = link->fd,
    };
    int r;

    r = bf_bpf(BPF_LINK_DETACH, &attr);
    if (r)
        return r;

    closep(&link->fd);

    return 0;
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

int bf_link_get_info(struct bf_link *link, struct bpf_link_info *info)
{
    union bpf_attr attr = {};

    bf_assert(link && info);

    if (link->fd == -1)
        return -ENOENT;

    attr.info.bpf_fd = link->fd;
    attr.info.info_len = sizeof(*info);
    attr.info.info = bf_ptr_to_u64(info);

    return bf_bpf(BPF_OBJ_GET_INFO_BY_FD, &attr);
}
