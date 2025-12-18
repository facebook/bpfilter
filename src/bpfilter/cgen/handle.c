/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#include "cgen/handle.h"

#include <errno.h>
#include <stdlib.h>
#include <unistd.h>

#include <bpfilter/bpf.h>
#include <bpfilter/helper.h>
#include <bpfilter/list.h>

#include "cgen/prog/link.h"
#include "cgen/prog/map.h"

int bf_handle_new(struct bf_handle **handle)
{
    assert(handle);

    *handle = calloc(1, sizeof(struct bf_handle));
    if (!*handle)
        return -ENOMEM;

    (*handle)->prog_fd = -1;
    (*handle)->sets = bf_list_default(bf_map_free, bf_map_pack);

    return 0;
}

int bf_handle_new_from_pack(struct bf_handle **handle, int dir_fd,
                            bf_rpack_node_t node)
{
    _free_bf_handle_ struct bf_handle *_handle = NULL;
    bf_rpack_node_t child, array_node;
    int r;

    assert(handle);

    r = bf_handle_new(&_handle);
    if (r)
        return r;

    r = bf_bpf_obj_get(BF_PROG_NAME, dir_fd, &_handle->prog_fd);
    if (r < 0)
        return bf_err_r(r, "failed to restore bf_handle.prog_fd");

    r = bf_rpack_kv_node(node, "link", &child);
    if (r)
        return bf_rpack_key_err(r, "bf_handle.link");
    if (!bf_rpack_is_nil(child)) {
        r = bf_link_new_from_pack(&_handle->link, dir_fd, child);
        if (r)
            return bf_err_r(r, "failed to restore bf_handle.link");
    }

    r = bf_rpack_kv_node(node, "counters", &child);
    if (r)
        return bf_rpack_key_err(r, "bf_handle.counters");
    if (!bf_rpack_is_nil(child)) {
        r = bf_map_new_from_pack(&_handle->counters, dir_fd, child);
        if (r)
            return r;
    }

    r = bf_rpack_kv_node(node, "logs", &child);
    if (r)
        return bf_rpack_key_err(r, "bf_handle.logs");
    if (!bf_rpack_is_nil(child)) {
        r = bf_map_new_from_pack(&_handle->logs, dir_fd, child);
        if (r)
            return r;
    }

    r = bf_rpack_kv_node(node, "messages", &child);
    if (r)
        return bf_rpack_key_err(r, "bf_handle.messages");
    if (!bf_rpack_is_nil(child)) {
        r = bf_map_new_from_pack(&_handle->messages, dir_fd, child);
        if (r)
            return r;
    }

    r = bf_rpack_kv_array(node, "sets", &child);
    if (r)
        return bf_rpack_key_err(r, "bf_handle.sets");
    bf_rpack_array_foreach (child, array_node) {
        _free_bf_map_ struct bf_map *map = NULL;

        r = bf_list_emplace(&_handle->sets, bf_map_new_from_pack, map, dir_fd,
                            array_node);
        if (r)
            return bf_err_r(r, "failed to unpack bf_map into bf_handle.sets");
    }

    *handle = TAKE_PTR(_handle);

    return 0;
}

void bf_handle_free(struct bf_handle **handle)
{
    assert(handle);

    if (!*handle)
        return;

    /* Close the file descriptors if they are still open. If --transient is
     * used, then the file descriptors are already closed (as
     * bf_handle_unload() has been called). Otherwise, bf_handle_unload()
     * won't be called, but the programs are pinned, so they can be closed
     * safely. */
    closep(&(*handle)->prog_fd);

    bf_link_free(&(*handle)->link);
    bf_map_free(&(*handle)->counters);
    bf_map_free(&(*handle)->logs);
    bf_map_free(&(*handle)->messages);
    bf_list_clean(&(*handle)->sets);

    freep((void *)handle);
}

int bf_handle_pack(const struct bf_handle *handle, bf_wpack_t *pack)
{
    assert(handle);
    assert(pack);

    if (handle->link) {
        bf_wpack_open_object(pack, "link");
        bf_link_pack(handle->link, pack);
        bf_wpack_close_object(pack);
    } else {
        bf_wpack_kv_nil(pack, "link");
    }

    if (handle->counters) {
        bf_wpack_open_object(pack, "counters");
        bf_map_pack(handle->counters, pack);
        bf_wpack_close_object(pack);
    } else {
        bf_wpack_kv_nil(pack, "counters");
    }

    if (handle->logs) {
        bf_wpack_open_object(pack, "logs");
        bf_map_pack(handle->logs, pack);
        bf_wpack_close_object(pack);
    } else {
        bf_wpack_kv_nil(pack, "logs");
    }

    if (handle->messages) {
        bf_wpack_open_object(pack, "messages");
        bf_map_pack(handle->messages, pack);
        bf_wpack_close_object(pack);
    } else {
        bf_wpack_kv_nil(pack, "messages");
    }

    bf_wpack_kv_list(pack, "sets", &handle->sets);

    return bf_wpack_is_valid(pack) ? 0 : -EINVAL;
}

void bf_handle_dump(const struct bf_handle *handle, prefix_t *prefix)
{
    assert(handle);
    assert(prefix);

    DUMP(prefix, "struct bf_handle at %p", handle);

    bf_dump_prefix_push(prefix);

    DUMP(prefix, "prog_fd: %d", handle->prog_fd);

    if (handle->link) {
        DUMP(prefix, "link: struct bf_link *");
        bf_dump_prefix_push(prefix);
        bf_link_dump(handle->link, bf_dump_prefix_last(prefix));
        bf_dump_prefix_pop(prefix);
    } else {
        DUMP(prefix, "link: (struct bf_link *)NULL");
    }

    if (handle->counters) {
        DUMP(prefix, "counters: struct bf_map *");
        bf_dump_prefix_push(prefix);
        bf_map_dump(handle->counters, bf_dump_prefix_last(prefix));
        bf_dump_prefix_pop(prefix);
    } else {
        DUMP(prefix, "counters: (struct bf_map *)NULL");
    }

    if (handle->logs) {
        DUMP(prefix, "logs: struct bf_map *");
        bf_dump_prefix_push(prefix);
        bf_map_dump(handle->logs, bf_dump_prefix_last(prefix));
        bf_dump_prefix_pop(prefix);
    } else {
        DUMP(prefix, "logs: (struct bf_map *)NULL");
    }

    if (handle->messages) {
        DUMP(prefix, "messages: struct bf_map *");
        bf_dump_prefix_push(prefix);
        bf_map_dump(handle->messages, bf_dump_prefix_last(prefix));
        bf_dump_prefix_pop(prefix);
    } else {
        DUMP(prefix, "messages: (struct bf_map *)NULL");
    }

    DUMP(bf_dump_prefix_last(prefix), "sets: bf_list<bf_map>[%lu]",
         bf_list_size(&handle->sets));
    bf_dump_prefix_push(prefix);
    bf_list_foreach (&handle->sets, map_node) {
        struct bf_map *map = bf_list_node_get_data(map_node);

        if (bf_list_is_tail(&handle->sets, map_node))
            bf_dump_prefix_last(prefix);

        bf_map_dump(map, prefix);
    }
    bf_dump_prefix_pop(prefix);

    bf_dump_prefix_pop(prefix);
}

int bf_handle_pin(struct bf_handle *handle, int dir_fd)
{
    int r;

    assert(handle);

    r = bf_bpf_obj_pin(BF_PROG_NAME, handle->prog_fd, dir_fd);
    if (r) {
        bf_handle_unpin(handle, dir_fd);
        return bf_err_r(r, "failed to pin BPF program");
    }

    if (handle->link) {
        r = bf_link_pin(handle->link, dir_fd);
        if (r) {
            bf_handle_unpin(handle, dir_fd);
            return bf_err_r(r, "failed to pin BPF link");
        }
    }

    if (handle->counters) {
        r = bf_map_pin(handle->counters, dir_fd);
        if (r) {
            bf_handle_unpin(handle, dir_fd);
            return bf_err_r(r, "failed to pin BPF counters map");
        }
    }

    if (handle->messages) {
        r = bf_map_pin(handle->messages, dir_fd);
        if (r) {
            bf_handle_unpin(handle, dir_fd);
            return bf_err_r(r, "failed to pin BPF printer map");
        }
    }

    if (handle->logs) {
        r = bf_map_pin(handle->logs, dir_fd);
        if (r) {
            bf_handle_unpin(handle, dir_fd);
            return bf_err_r(r, "failed to pin BPF log map");
        }
    }

    bf_list_foreach (&handle->sets, set_node) {
        r = bf_map_pin(bf_list_node_get_data(set_node), dir_fd);
        if (r) {
            bf_handle_unpin(handle, dir_fd);
            return bf_err_r(r, "failed to pin BPF set map");
        }
    }

    return 0;
}

void bf_handle_unpin(struct bf_handle *handle, int dir_fd)
{
    assert(handle);

    unlinkat(dir_fd, BF_PROG_NAME, 0);

    if (handle->link)
        bf_link_unpin(handle->link, dir_fd);

    if (handle->counters)
        bf_map_unpin(handle->counters, dir_fd);
    if (handle->messages)
        bf_map_unpin(handle->messages, dir_fd);
    if (handle->logs)
        bf_map_unpin(handle->logs, dir_fd);

    bf_list_foreach (&handle->sets, set_node)
        bf_map_unpin(bf_list_node_get_data(set_node), dir_fd);
}

void bf_handle_unload(struct bf_handle *handle)
{
    assert(handle);

    closep(&handle->prog_fd);

    if (handle->link)
        bf_link_detach(handle->link);

    if (handle->counters)
        bf_map_destroy(handle->counters);
    if (handle->messages)
        bf_map_destroy(handle->messages);
    if (handle->logs)
        bf_map_destroy(handle->logs);

    bf_list_foreach (&handle->sets, map_node)
        bf_map_destroy(bf_list_node_get_data(map_node));
}

int bf_handle_attach(struct bf_handle *handle, enum bf_hook hook,
                     struct bf_hookopts **hookopts)
{
    int r;

    assert(handle);
    assert(hookopts);

    r = bf_link_new(&handle->link, "bf_link");
    if (r)
        return bf_err_r(r, "failed to create bf_link for program");

    r = bf_link_attach(handle->link, hook, hookopts, handle->prog_fd);
    if (r)
        return bf_err_r(r, "failed to attach bf_link for program");

    return r;
}

void bf_handle_detach(struct bf_handle *handle)
{
    assert(handle);

    if (!handle->link)
        return;

    bf_link_detach(handle->link);
}
