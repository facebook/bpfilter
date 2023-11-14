/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2022 Meta Platforms, Inc. and affiliates.
 */

#include "xlate/nft/nlmsg.h"

#include <errno.h>
#include <limits.h>
#include <netlink/msg.h>

#include "shared/response.h"
#include "xlate/nft/nlpart.h"

struct bf_nlmsg
{
    bf_list parts;
};

int bf_nlmsg_new(struct bf_nlmsg **msg)
{
    _cleanup_bf_nlmsg_ struct bf_nlmsg *_msg = NULL;

    _msg = calloc(1, sizeof(*_msg));
    if (!_msg)
        return -ENOMEM;

    bf_list_init(&_msg->parts, &(bf_list_ops) {
                                   .free = (bf_list_ops_free)bf_nlpart_free,
                               });

    *msg = TAKE_PTR(_msg);

    return 0;
}

int bf_nlmsg_new_from_stream(struct bf_nlmsg **msg, struct nlmsghdr *nlh,
                             size_t length)
{
    bf_assert(msg);
    bf_assert(nlh);
    bf_assert(length <
              INT_MAX); // nlmsg_ok() takes an int. length should not be larger
                        // than INT_MAX, but we check anyway to be safe.

    _cleanup_bf_nlmsg_ struct bf_nlmsg *_msg = NULL;
    int len = (int)length;
    int r;

    r = bf_nlmsg_new(&_msg);
    if (r < 0)
        return r;

    while (nlmsg_ok(nlh, len)) {
        _cleanup_bf_nlpart_ struct bf_nlpart *part = NULL;

        if (nlh->nlmsg_type == NFNL_MSG_BATCH_BEGIN ||
            nlh->nlmsg_type == NFNL_MSG_BATCH_END) {
            // Skip batch messages.
            nlh = nlmsg_next(nlh, &len);
            continue;
        }

        r = bf_nlpart_new_from_nlmsghdr(&part, nlh);
        if (r < 0)
            return r;

        r = bf_nlmsg_add_part(_msg, part);
        if (r < 0)
            return r;

        TAKE_PTR(part);

        nlh = nlmsg_next(nlh, &len);
    }

    *msg = TAKE_PTR(_msg);

    return 0;
}

void bf_nlmsg_free(struct bf_nlmsg **msg)
{
    bf_assert(msg);

    if (!*msg)
        return;

    bf_list_clean(&(*msg)->parts);
    free(*msg);
    *msg = NULL;
}

const bf_list *bf_nlmsg_parts(const struct bf_nlmsg *msg)
{
    bf_assert(msg);

    return &msg->parts;
}

size_t bf_nlmsg_size(const struct bf_nlmsg *msg)
{
    bf_assert(msg);

    size_t size = 0;

    bf_list_foreach (&msg->parts, part_node) {
        struct bf_nlpart *part = bf_list_node_get_data(part_node);
        size += bf_nlpart_padded_size(part);
    }

    return size;
}

bool bf_nlmsg_is_empty(const struct bf_nlmsg *msg)
{
    return bf_list_is_empty(&msg->parts);
}

int bf_nlmsg_add_part(struct bf_nlmsg *msg, struct bf_nlpart *part)
{
    bf_assert(msg);
    bf_assert(part);

    return bf_list_add_tail(&msg->parts, part);
}

int bf_nlmsg_add_new_part(struct bf_nlmsg *msg, struct bf_nlpart **part,
                          uint16_t family, uint16_t command, uint16_t flags,
                          uint16_t seqnr)
{
    bf_assert(msg);

    _cleanup_bf_nlpart_ struct bf_nlpart *_part = NULL;
    int r;

    r = bf_nlpart_new(&_part, family, command, flags, seqnr);
    if (r < 0)
        return r;

    r = bf_nlmsg_add_part(msg, _part);
    if (r < 0)
        return r;

    if (part)
        *part = TAKE_PTR(_part);
    else
        TAKE_PTR(_part);

    return 0;
}

int bf_nlmsg_to_response(const struct bf_nlmsg *msg, struct bf_response **resp)
{
    bf_assert(msg);
    bf_assert(resp);

    _cleanup_bf_response_ struct bf_response *_resp = NULL;
    size_t size = bf_nlmsg_size(msg);
    void *payload;
    int r;

    r = bf_response_new_raw(&_resp, size);
    if (r < 0)
        return r;

    _resp->type = BF_RES_SUCCESS;
    _resp->data_len = 0;
    payload = _resp->data;

    bf_list_foreach (&msg->parts, part_node) {
        struct bf_nlpart *part = bf_list_node_get_data(part_node);

        memcpy(payload, bf_nlpart_hdr(part), bf_nlpart_size(part));

        payload += bf_nlpart_padded_size(part);
        _resp->data_len += bf_nlpart_padded_size(part);
    }

    *resp = TAKE_PTR(_resp);

    return 0;
}

void bf_nlmsg_dump(const struct bf_nlmsg *msg, size_t extra_hdr_len,
                   prefix_t *prefix)
{
    bf_assert(msg);

    struct bf_list_node *last_part_node = bf_list_get_tail(&msg->parts);
    prefix_t _prefix = {};
    prefix = prefix ?: &_prefix;

    DUMP(prefix, "struct bf_nlmsg at %p", msg);
    bf_dump_prefix_push(prefix);

    bf_list_foreach (&msg->parts, part_node) {
        struct bf_nlpart *part = bf_list_node_get_data(part_node);

        bf_nlpart_dump(
            part, extra_hdr_len,
            part_node == last_part_node ? bf_dump_prefix_last(prefix) : prefix);
    }

    bf_dump_prefix_pop(prefix);
}
