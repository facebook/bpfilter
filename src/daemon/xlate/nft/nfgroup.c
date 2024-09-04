/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2022 Meta Platforms, Inc. and affiliates.
 */

#include "daemon/xlate/nft/nfgroup.h"

#include <linux/netfilter/nfnetlink.h>
#include <linux/netlink.h>

#include <errno.h>
#include <limits.h>
#include <netlink/msg.h>

#include "core/list.h"
#include "core/response.h"
#include "daemon/xlate/nft/nfmsg.h"

struct bf_nfgroup
{
    bf_list messages;
};

int bf_nfgroup_new(struct bf_nfgroup **group)
{
    bf_assert(group);

    _cleanup_bf_nfgroup_ struct bf_nfgroup *_group = NULL;

    _group = calloc(1, sizeof(*_group));
    if (!_group)
        return -ENOMEM;

    bf_list_init(&_group->messages, &(bf_list_ops) {
                                        .free = (bf_list_ops_free)bf_nfmsg_free,
                                    });

    *group = TAKE_PTR(_group);

    return 0;
}

int bf_nfgroup_new_from_stream(struct bf_nfgroup **group, struct nlmsghdr *nlh,
                               size_t length)
{
    bf_assert(group);
    bf_assert(nlh);
    bf_assert(length < INT_MAX);
    /* nlmsg_ok() takes an int. length should not be larger than INT_MAX, but
     * we check anyway to be safe. */

    _cleanup_bf_nfgroup_ struct bf_nfgroup *_group = NULL;
    int len = (int)length;
    int r;

    r = bf_nfgroup_new(&_group);
    if (r < 0)
        return r;

    while (nlmsg_ok(nlh, len)) {
        _cleanup_bf_nfmsg_ struct bf_nfmsg *msg = NULL;

        if (nlh->nlmsg_type == NFNL_MSG_BATCH_BEGIN ||
            nlh->nlmsg_type == NFNL_MSG_BATCH_END) {
            // Skip batch messages.
            nlh = nlmsg_next(nlh, &len);
            continue;
        }

        r = bf_nfmsg_new_from_nlmsghdr(&msg, nlh);
        if (r < 0)
            return r;

        r = bf_nfgroup_add_message(_group, msg);
        if (r < 0)
            return r;

        TAKE_PTR(msg);

        nlh = nlmsg_next(nlh, &len);
    }

    *group = TAKE_PTR(_group);

    return 0;
}

void bf_nfgroup_free(struct bf_nfgroup **group)
{
    bf_assert(group);

    if (!*group)
        return;

    bf_list_clean(&(*group)->messages);
    free(*group);
    *group = NULL;
}

const bf_list *bf_nfgroup_messages(const struct bf_nfgroup *group)
{
    bf_assert(group);

    return &group->messages;
}

size_t bf_nfgroup_size(const struct bf_nfgroup *group)
{
    bf_assert(group);

    size_t size = 0;

    bf_list_foreach (&group->messages, msg_node)
        size += bf_nfmsg_len(bf_list_node_get_data(msg_node));

    return size;
}

bool bf_nfgroup_is_empty(const struct bf_nfgroup *group)
{
    bf_assert(group);

    return bf_list_is_empty(&group->messages);
}

int bf_nfgroup_add_message(struct bf_nfgroup *group, struct bf_nfmsg *msg)
{
    bf_assert(group);
    bf_assert(msg);

    return bf_list_add_tail(&group->messages, msg);
}

int bf_nfgroup_add_new_message(struct bf_nfgroup *group, struct bf_nfmsg **msg,
                               uint16_t command, uint16_t seqnr)
{
    bf_assert(group);

    _cleanup_bf_nfmsg_ struct bf_nfmsg *_msg = NULL;
    int r;

    r = bf_nfmsg_new(&_msg, command, seqnr);
    if (r < 0)
        return r;

    r = bf_nfgroup_add_message(group, _msg);
    if (r < 0)
        return r;

    if (msg)
        *msg = TAKE_PTR(_msg);
    else
        TAKE_PTR(_msg);

    return 0;
}

int bf_nfgroup_to_response(const struct bf_nfgroup *group,
                           struct bf_response **resp)
{
    bf_assert(group);
    bf_assert(resp);

    _cleanup_bf_response_ struct bf_response *_resp = NULL;
    _cleanup_bf_nfmsg_ struct bf_nfmsg *done = NULL;
    size_t size = bf_nfgroup_size(group);
    bool is_multipart = bf_list_size(&group->messages) != 1;
    void *payload;
    int r;

    if (is_multipart) {
        r = bf_nfmsg_new_done(&done);
        if (r < 0)
            return r;

        size += bf_nfmsg_len(done);
    }

    r = bf_response_new_raw(&_resp, size);
    if (r < 0)
        return r;

    _resp->type = BF_RES_SUCCESS;
    _resp->data_len = size;
    payload = _resp->data;

    bf_list_foreach (&group->messages, msg_node) {
        struct bf_nfmsg *msg = bf_list_node_get_data(msg_node);

        memcpy(payload, bf_nfmsg_hdr(msg), bf_nfmsg_len(msg));

        if (is_multipart)
            ((struct nlmsghdr *)payload)->nlmsg_flags |= NLM_F_MULTI;

        payload += bf_nfmsg_len(msg);
    }

    if (is_multipart)
        memcpy(payload, bf_nfmsg_hdr(done), bf_nfmsg_len(done));

    *resp = TAKE_PTR(_resp);

    return 0;
}
