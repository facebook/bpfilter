// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2022 Meta Platforms, Inc. and affiliates.
 */

#include "generator/printer.h"

#include <stdlib.h>

#include "core/bpf.h"
#include "core/list.h"
#include "core/logger.h"
#include "core/marsh.h"
#include "shared/helper.h"

/**
 * @struct bf_printer_msg
 *
 * Represents a message to be printed by a generated BPF program.
 */
struct bf_printer_msg
{
    /// Offset of the message, in the concatenated messages string.
    size_t offset;
    // Length of the message, including the nul termination character.
    size_t len;
    /// Message.
    const char *str;
};

/**
 * @struct bf_printer
 *
 * The printer context. It stores all the messages to be printed by any of the
 * generated BPF program, and the runtime data required to maintain the
 * log messages BPF map.
 */
struct bf_printer
{
    /// List of messages.
    bf_list msgs;
    /// File descriptor of the BPF map containing the messages. Contains -1 if
    /// no map has been created yet.
    int fd;
};

#define _cleanup_bf_printer_msg_                                               \
    __attribute__((__cleanup__(_bf_printer_msg_free)))

/// Path to the pinned messages map on the system.
static const char *_bf_printer_pin_path = "/sys/fs/bpf/bf_printer";

static void _bf_printer_msg_free(struct bf_printer_msg **msg);

/**
 * @brief Allocate and initialise a new printer message.
 *
 * @param msg On success, points to the newly allocated and initialised
 *  printer message. Can't be NULL.
 * @return 0 on success, or negative errno value on error.
 */
static int _bf_printer_msg_new(struct bf_printer_msg **msg)
{
    _cleanup_bf_printer_msg_ struct bf_printer_msg *_msg = NULL;

    bf_assert(msg);

    _msg = calloc(1, sizeof(*_msg));
    if (!_msg)
        return -ENOMEM;

    *msg = TAKE_PTR(_msg);

    return 0;
}

/**
 * @brief Allocate a new printer message and initialise it from serialized
 *  data.
 *
 * @param msg On success, points to the newly allocated and initialised
 *  printer message. Can't be NULL.
 * @param marsh Serialized data to use to initialise the printer message.
 * @return 0 on success, or negative errno value on error.
 */
static int _bf_printer_msg_new_from_marsh(struct bf_printer_msg **msg,
                                          const struct bf_marsh *marsh)
{
    _cleanup_bf_printer_msg_ struct bf_printer_msg *_msg = NULL;
    struct bf_marsh *child = NULL;
    int r;

    bf_assert(msg);
    bf_assert(marsh);

    r = _bf_printer_msg_new(&_msg);
    if (r)
        return bf_err_code(r, "failed to allocate a new bf_printer_msg object");

    if (!(child = bf_marsh_next_child(marsh, child)))
        return -EINVAL;
    memcpy(&_msg->offset, child->data, sizeof(_msg->offset));

    if (!(child = bf_marsh_next_child(marsh, child)))
        return -EINVAL;
    memcpy(&_msg->len, child->data, sizeof(_msg->len));

    if (!(child = bf_marsh_next_child(marsh, child)))
        return -EINVAL;
    _msg->str = strndup(child->data, _msg->len - 1);
    if (!_msg->str)
        return -ENOMEM;

    *msg = TAKE_PTR(_msg);

    return 0;
}

/**
 * @brief Deinitialise and deallocate a printer message.
 *
 * @param msg Printer message. Can't be NULL.
 */
static void _bf_printer_msg_free(struct bf_printer_msg **msg)
{
    bf_assert(msg);

    if (!*msg)
        return;

    // Compiler will complain if str is const
    free((char *)(*msg)->str);

    free(*msg);
    *msg = NULL;
}

/**
 * @brief Serialize a printer message.
 *
 * The message's string is serialized with its trailing '/0'.
 *
 * @param msg Printer message to serialise. Can't be NULL.
 * @param marsh On success, contains the serialised printer message. Can't be
 *  NULL.
 * @return 0 on success, or negative errno value on failure.
 */
static int _bf_printer_msg_marsh(const struct bf_printer_msg *msg,
                                 struct bf_marsh **marsh)
{
    _cleanup_bf_marsh_ struct bf_marsh *_marsh = NULL;
    int r;

    bf_assert(msg);
    bf_assert(marsh);

    r = bf_marsh_new(&_marsh, NULL, 0);
    if (r)
        return r;

    r |= bf_marsh_add_child_raw(&_marsh, &msg->offset, sizeof(msg->offset));
    r |= bf_marsh_add_child_raw(&_marsh, &msg->len, sizeof(msg->len));
    r |= bf_marsh_add_child_raw(&_marsh, msg->str, msg->len);
    if (r)
        return bf_err_code(r, "failed to serialize bf_printer_msg object");

    *marsh = TAKE_PTR(_marsh);

    return 0;
}

static void _bf_printer_msg_dump(const struct bf_printer_msg *msg,
                                 prefix_t *prefix)
{
    bf_assert(msg);
    bf_assert(prefix);

    DUMP(prefix, "struct bf_printer_msg at %p", msg);

    bf_dump_prefix_push(prefix);
    DUMP(prefix, "offset: %lu", msg->offset);
    DUMP(prefix, "len: %lu", msg->len);
    DUMP(bf_dump_prefix_last(prefix), "str: '%s'", msg->str);
    bf_dump_prefix_pop(prefix);
}

size_t bf_printer_msg_offset(const struct bf_printer_msg *msg)
{
    bf_assert(msg);
    return msg->offset;
}

size_t bf_printer_msg_len(const struct bf_printer_msg *msg)
{
    bf_assert(msg);
    return msg->len;
}

int bf_printer_new(struct bf_printer **printer)
{
    _cleanup_bf_printer_ struct bf_printer *_printer;

    bf_assert(printer);

    _printer = malloc(sizeof(*_printer));
    if (!_printer)
        return -ENOMEM;

    bf_list_init(
        &_printer->msgs,
        (bf_list_ops[]) {{.free = (bf_list_ops_free)_bf_printer_msg_free}});
    _printer->fd = -1;

    *printer = TAKE_PTR(_printer);

    return 0;
}

int bf_printer_new_from_marsh(struct bf_printer **printer,
                              const struct bf_marsh *marsh)
{
    _cleanup_bf_printer_ struct bf_printer *_printer = NULL;
    struct bf_marsh *child = NULL;
    int r;

    bf_assert(printer);
    bf_assert(marsh);

    r = bf_printer_new(&_printer);
    if (r)
        return bf_err_code(r, "failed to allocate a new bf_printer object");

    while ((child = bf_marsh_next_child(marsh, child))) {
        _cleanup_bf_printer_msg_ struct bf_printer_msg *msg = NULL;

        r = _bf_printer_msg_new_from_marsh(&msg, child);
        if (r)
            return r;

        r = bf_list_add_tail(&_printer->msgs, msg);
        TAKE_PTR(msg);
    }

    if (!bf_list_is_empty(&_printer->msgs)) {
        r = bf_bpf_obj_get(_bf_printer_pin_path, &_printer->fd);
        if (r < 0)
            return bf_err_code(r, "failed to get printer map fd");
    }

    *printer = TAKE_PTR(_printer);

    return 0;
}

void bf_printer_free(struct bf_printer **printer)
{
    bf_assert(printer);

    if (!*printer)
        return;

    bf_list_clean(&(*printer)->msgs);
    closep(&(*printer)->fd);

    free(*printer);
    *printer = NULL;
}

int bf_printer_marsh(const struct bf_printer *printer, struct bf_marsh **marsh)
{
    _cleanup_bf_marsh_ struct bf_marsh *_marsh = NULL;
    int r;

    bf_assert(printer);
    bf_assert(marsh);

    r = bf_marsh_new(&_marsh, NULL, 0);
    if (r)
        return r;

    bf_list_foreach (&printer->msgs, msg_node) {
        _cleanup_bf_marsh_ struct bf_marsh *child = NULL;
        struct bf_printer_msg *msg = bf_list_node_get_data(msg_node);

        r = _bf_printer_msg_marsh(msg, &child);
        if (r)
            return r;

        r = bf_marsh_add_child_obj(&_marsh, child);
        if (r)
            return r;
    }

    *marsh = TAKE_PTR(_marsh);

    return 0;
}

void bf_printer_dump(const struct bf_printer *printer, prefix_t *prefix)
{
    bf_assert(printer);
    bf_assert(prefix);

    DUMP(prefix, "struct bf_printer at %p", printer);

    bf_dump_prefix_push(prefix);
    DUMP(prefix, "msgs: bf_list<bf_printer_msg>[%lu]",
         bf_list_size(&printer->msgs));
    bf_dump_prefix_push(prefix);
    bf_list_foreach (&printer->msgs, msg_node) {
        struct bf_printer_msg *msg = bf_list_node_get_data(msg_node);

        if (bf_list_is_tail(&printer->msgs, msg_node))
            bf_dump_prefix_last(prefix);

        _bf_printer_msg_dump(msg, prefix);
    }
    bf_dump_prefix_pop(prefix);

    if (bf_opts_transient()) {
        DUMP(bf_dump_prefix_last(prefix), "fd: <transient>");
    } else {
        DUMP(bf_dump_prefix_last(prefix), "fd: %d", printer->fd);
    }

    bf_dump_prefix_pop(prefix);
}

/**
 * @brief Get the total size of the concatenated messages.
 *
 * @param printer Printer context. Can't be NULL.
 * @return Total size of the concatenated messages.
 */
static size_t _bf_printer_total_size(const struct bf_printer *printer)
{
    bf_list_node *last_msg_node;
    struct bf_printer_msg *last_msg;

    bf_assert(printer);

    if (!(last_msg_node = bf_list_get_tail(&printer->msgs)))
        return 0;

    last_msg = bf_list_node_get_data(last_msg_node);

    return last_msg->offset + last_msg->len;
}

int bf_printer_get_fd(const struct bf_printer *printer)
{
    bf_assert(printer);
    return printer->fd;
}

const struct bf_printer_msg *bf_printer_add_msg(struct bf_printer *printer,
                                                const char *str)
{
    _cleanup_bf_printer_msg_ struct bf_printer_msg *msg = NULL;
    int r;

    bf_assert(printer);
    bf_assert(str);

    // Check if an identical message is already stored in the context.
    bf_list_foreach (&printer->msgs, msg_node) {
        struct bf_printer_msg *msg = bf_list_node_get_data(msg_node);

        if (bf_streq(msg->str, str))
            return msg;
    }

    // Otherwise, create a new message.
    r = _bf_printer_msg_new(&msg);
    if (r) {
        bf_err("failed to create a new bf_printer_msg object");
        return NULL;
    }

    msg->len = strlen(str) + 1;
    // Next expected offset is equal to the current total size of the
    // concatenated string
    msg->offset = _bf_printer_total_size(printer);
    msg->str = strdup(str);
    if (!msg->str)
        return NULL;

    r = bf_list_add_tail(&printer->msgs, msg);
    if (r) {
        bf_err("failed to add a new printer message to the printer context");
        return NULL;
    }

    return TAKE_PTR(msg);
}

int bf_printer_publish(struct bf_printer *printer)
{
    _cleanup_free_ char *strings = NULL;
    _cleanup_close_ int fd = -1;
    size_t total_size;
    int r;

    bf_assert(printer);

    // If there are no messages in the printer, assume it's published.
    if (bf_list_is_empty(&printer->msgs))
        return 0;

    // Create the concatenated string of messages
    total_size = _bf_printer_total_size(printer);

    strings = malloc(total_size);
    if (!strings)
        return -ENOMEM;

    bf_list_foreach (&printer->msgs, msg_node) {
        struct bf_printer_msg *msg = bf_list_node_get_data(msg_node);
        memcpy(strings + msg->offset, msg->str, msg->len);
    }

    fd = printer->fd;

    // If no map has been created yet, do it now
    if (fd == -1) {
        r = bf_bpf_map_create("bf_printer", BPF_MAP_TYPE_ARRAY,
                              sizeof(uint32_t), total_size, 1,
                              BPF_F_RDONLY_PROG, &fd);
        if (r < 0)
            return bf_err_code(r, "failed to create the BPF map 'bf_printer'");
    }

    // Replace the existing messages in the map
    r = bf_bpf_map_update_elem(fd, (void *)(uint32_t[]) {0}, strings);
    if (r < 0) {
        // Do not destroy the existing map if we can't replace the fist element
        TAKE_FD(fd);
        return bf_err_code(
            r, "failed to insert the messages into the BPF map 'bf_printer'");
    }

    // Pin and save the map file descriptor if needed
    if (printer->fd == -1) {
        if (!bf_opts_transient()) {
            r = bf_bpf_obj_pin(_bf_printer_pin_path, fd);
            if (r < 0)
                return bf_err_code(r, "failed to pin the printer map");
        }
    }

    printer->fd = TAKE_FD(fd);

    return 0;
}
