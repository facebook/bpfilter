// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2022 Meta Platforms, Inc. and affiliates.
 */

#include "cgen/printer.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include <bpfilter/dump.h>
#include <bpfilter/helper.h>
#include <bpfilter/list.h>
#include <bpfilter/logger.h>
#include <bpfilter/pack.h>

/**
 * @struct bf_printer_msg
 *
 * Represents a message to be printed by a generated BPF program.
 */
struct bf_printer_msg
{
    /// Offset of the message, in the concatenated messages string.
    size_t offset;
    /// Length of the message, including the nul termination character.
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
};

#define _free_bf_printer_msg_ __attribute__((__cleanup__(_bf_printer_msg_free)))

static void _bf_printer_msg_free(struct bf_printer_msg **msg);

/**
 * Allocate and initialise a new printer message.
 *
 * @param msg On success, points to the newly allocated and initialised
 *        printer message. Can't be NULL.
 * @return 0 on success, or negative errno value on error.
 */
static int _bf_printer_msg_new(struct bf_printer_msg **msg)
{
    _free_bf_printer_msg_ struct bf_printer_msg *_msg = NULL;

    assert(msg);

    _msg = calloc(1, sizeof(*_msg));
    if (!_msg)
        return -ENOMEM;

    *msg = TAKE_PTR(_msg);

    return 0;
}

/**
 * @brief Allocate and initialize a new printer message from serialized data.
 *
 * @param msg Printer message object to allocate and initialize from the
 *        serialized data. The caller will own the object. On failure, `*msg`
 *        is unchanged. Can't be NULL.
 * @param node Node containing the serialized message.
 * @return 0 on success, or a negative errno value on failure.
 */
static int _bf_printer_msg_new_from_pack(struct bf_printer_msg **msg,
                                         bf_rpack_node_t node)
{
    _free_bf_printer_msg_ struct bf_printer_msg *_msg = NULL;
    int r;

    assert(msg);

    r = _bf_printer_msg_new(&_msg);
    if (r)
        return bf_err_r(r, "failed to create bf_printer_msg from pack");

    r = bf_rpack_kv_u64(node, "offset", &_msg->offset);
    if (r)
        return bf_rpack_key_err(r, "bf_printer_msg.offset");

    r = bf_rpack_kv_u64(node, "len", &_msg->len);
    if (r)
        return bf_rpack_key_err(r, "bf_printer_msg.len");

    r = bf_rpack_kv_str(node, "str", (char **)&_msg->str);
    if (r)
        return bf_rpack_key_err(r, "bf_printer_msg.str");

    *msg = TAKE_PTR(_msg);

    return 0;
}

/**
 * Deinitialise and deallocate a printer message.
 *
 * @param msg Printer message. Can't be NULL.
 */
static void _bf_printer_msg_free(struct bf_printer_msg **msg)
{
    assert(msg);

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
 * @param msg Printer message to serialize. Can't be NULL.
 * @param pack `bf_wpack_t` object to serialize the printer message into.
 *        Can't be NULL.
 * @return 0 on success, or a negative error value on failure.
 */
static int _bf_printer_msg_pack(const struct bf_printer_msg *msg,
                                bf_wpack_t *pack)
{
    assert(msg);
    assert(pack);

    bf_wpack_kv_u64(pack, "offset", msg->offset);
    bf_wpack_kv_u64(pack, "len", msg->len);
    bf_wpack_kv_str(pack, "str", msg->str);

    return bf_wpack_is_valid(pack) ? 0 : -EINVAL;
}

static void _bf_printer_msg_dump(const struct bf_printer_msg *msg,
                                 prefix_t *prefix)
{
    assert(msg);
    assert(prefix);

    DUMP(prefix, "struct bf_printer_msg at %p", msg);

    bf_dump_prefix_push(prefix);
    DUMP(prefix, "offset: %lu", msg->offset);
    DUMP(prefix, "len: %lu", msg->len);
    DUMP(bf_dump_prefix_last(prefix), "str: '%s'", msg->str);
    bf_dump_prefix_pop(prefix);
}

size_t bf_printer_msg_offset(const struct bf_printer_msg *msg)
{
    assert(msg);
    return msg->offset;
}

size_t bf_printer_msg_len(const struct bf_printer_msg *msg)
{
    assert(msg);
    return msg->len;
}

int bf_printer_new(struct bf_printer **printer)
{
    _free_bf_printer_ struct bf_printer *_printer = NULL;

    assert(printer);

    _printer = malloc(sizeof(*_printer));
    if (!_printer)
        return -ENOMEM;

    _printer->msgs =
        bf_list_default(_bf_printer_msg_free, _bf_printer_msg_pack);

    *printer = TAKE_PTR(_printer);

    return 0;
}

int bf_printer_new_from_pack(struct bf_printer **printer, bf_rpack_node_t node)
{
    _free_bf_printer_ struct bf_printer *_printer = NULL;
    bf_rpack_node_t child, m_node;
    int r;

    assert(printer);

    r = bf_printer_new(&_printer);
    if (r)
        return bf_err_r(r, "failed to create a bf_printer from pack");

    r = bf_rpack_kv_array(node, "msgs", &child);
    if (r)
        return bf_rpack_key_err(r, "bf_printer.msgs");
    bf_rpack_array_foreach (child, m_node) {
        _free_bf_printer_msg_ struct bf_printer_msg *msg = NULL;

        r = bf_list_emplace(&_printer->msgs, _bf_printer_msg_new_from_pack, msg,
                            m_node);
        if (r) {
            return bf_err_r(
                r, "failed to unpack bf_printer_msg into bf_printer.msgs");
        }
    }

    *printer = TAKE_PTR(_printer);

    return 0;
}

void bf_printer_free(struct bf_printer **printer)
{
    assert(printer);

    if (!*printer)
        return;

    bf_list_clean(&(*printer)->msgs);

    free(*printer);
    *printer = NULL;
}

int bf_printer_pack(const struct bf_printer *printer, bf_wpack_t *pack)
{
    assert(printer);
    assert(pack);

    bf_wpack_kv_list(pack, "msgs", &printer->msgs);

    return bf_wpack_is_valid(pack) ? 0 : -EINVAL;
}

void bf_printer_dump(const struct bf_printer *printer, prefix_t *prefix)
{
    assert(printer);
    assert(prefix);

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

    bf_dump_prefix_pop(prefix);
}

/**
 * Get the total size of the concatenated messages.
 *
 * @param printer Printer context. Can't be NULL.
 * @return Total size of the concatenated messages.
 */
static size_t _bf_printer_total_size(const struct bf_printer *printer)
{
    bf_list_node *last_msg_node;
    struct bf_printer_msg *last_msg;

    assert(printer);

    if (!(last_msg_node = bf_list_get_tail(&printer->msgs)))
        return 0;

    last_msg = bf_list_node_get_data(last_msg_node);

    return last_msg->offset + last_msg->len;
}

const struct bf_printer_msg *bf_printer_add_msg(struct bf_printer *printer,
                                                const char *str)
{
    _free_bf_printer_msg_ struct bf_printer_msg *msg = NULL;
    int r;

    assert(printer);
    assert(str);

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

int bf_printer_assemble(const struct bf_printer *printer, void **str,
                        size_t *str_len)
{
    _cleanup_free_ char *_str = NULL;
    size_t _str_len;

    assert(printer);
    assert(str);
    assert(str_len);

    _str_len = _bf_printer_total_size(printer);

    // If the printer doesn't contain any message, the string should only
    // contain \0.
    if (_str_len == 0) {
        _str = malloc(1);
        if (!_str)
            return -ENOMEM;

        *_str = '\0';
        _str_len = 1;
    } else {
        _str_len = _bf_printer_total_size(printer);
        _str = malloc(_str_len);
        if (!_str)
            return -ENOMEM;

        bf_list_foreach (&printer->msgs, msg_node) {
            struct bf_printer_msg *msg = bf_list_node_get_data(msg_node);
            memcpy(_str + msg->offset, msg->str, msg->len);
        }
    }

    *str = TAKE_PTR(_str);
    *str_len = _str_len;

    return 0;
}
