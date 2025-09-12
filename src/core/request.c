/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#include "core/request.h"

#include <errno.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "core/dynbuf.h"
#include "core/helper.h"
#include "core/pack.h"

/**
 * @struct bf_request
 *
 * Generic request format sent by the client to the daemon.
 *
 * @var bf_request::front
 *  Front this request is targeted to.
 * @var bf_request::cmd
 *  Command.
 * @var bf_request::ipt_cmd
 *  Custom command for the IPT front.
 * @var bf_request::data_len
 *  Length of the client-specific data.
 * @var bf_request::data
 *  Client-specific data.
 */
struct bf_request
{
    enum bf_front front;
    enum bf_request_cmd cmd;

    /** Namespaces the request is coming from. This field will be automatically
     * populated by the daemon when receiving the request. */
    struct bf_ns *ns;

    /** File descriptor of the receiver socket. This field is automatically
     * populated by the daemon when receiving the request. The request doesn't
     * own the file descriptor. */
    int fd;

    union
    {
        int ipt_cmd;
    };

    size_t data_len;
    char data[];
};

int bf_request_new(struct bf_request **request, enum bf_front front,
                   enum bf_request_cmd cmd, const void *data, size_t data_len)
{
    _free_bf_request_ struct bf_request *_request = NULL;

    bf_assert(request);
    bf_assert(!(!!data ^ !!data_len));

    _request = calloc(1, sizeof(*_request) + data_len);
    if (!_request)
        return -ENOMEM;

    if (data) {
        memcpy(_request->data, data, data_len);
        _request->data_len = data_len;
    }

    _request->front = front;
    _request->cmd = cmd;

    *request = TAKE_PTR(_request);

    return 0;
}

int bf_request_new_from_dynbuf(struct bf_request **request,
                               struct bf_dynbuf *dynbuf)
{
    struct bf_request *tmpreq;

    bf_assert(request);
    bf_assert(dynbuf);

    if (dynbuf->len < sizeof(*tmpreq))
        return -EINVAL;

    tmpreq = dynbuf->data;
    if (bf_request_size(tmpreq) != dynbuf->len)
        return -EINVAL;

    *request = bf_dynbuf_take(dynbuf);

    return 0;
}

int bf_request_new_from_pack(struct bf_request **request, enum bf_front front,
                             enum bf_request_cmd cmd, bf_wpack_t *pack)
{
    const void *data;
    size_t data_len;
    int r;

    bf_assert(request);
    bf_assert(pack);

    if (!bf_wpack_is_valid(pack))
        return -EINVAL;

    r = bf_wpack_get_data(pack, &data, &data_len);
    if (r)
        return r;

    return bf_request_new(request, front, cmd, data, data_len);
}

int bf_request_copy(struct bf_request **dest, const struct bf_request *src)
{
    _free_bf_request_ struct bf_request *_request = NULL;

    bf_assert(dest);
    bf_assert(src);

    _request = bf_memdup(src, bf_request_size(src));
    if (!_request)
        return -ENOMEM;

    *dest = TAKE_PTR(_request);

    return 0;
}

void bf_request_free(struct bf_request **request)
{
    free(*request);
    *request = NULL;
}

enum bf_front bf_request_front(const struct bf_request *request)
{
    bf_assert(request);
    return request->front;
}

enum bf_request_cmd bf_request_cmd(const struct bf_request *request)
{
    bf_assert(request);
    return request->cmd;
}

struct bf_ns *bf_request_ns(const struct bf_request *request)
{
    bf_assert(request);
    return request->ns;
}

int bf_request_fd(const struct bf_request *request)
{
    bf_assert(request);
    return request->fd;
}

const void *bf_request_data(const struct bf_request *request)
{
    bf_assert(request);
    return request->data;
}

size_t bf_request_data_len(const struct bf_request *request)
{
    bf_assert(request);
    return request->data_len;
}

size_t bf_request_size(const struct bf_request *request)
{
    bf_assert(request);

    return sizeof(struct bf_request) + request->data_len;
}

int bf_request_ipt_cmd(const struct bf_request *request)
{
    bf_assert(request);
    return request->ipt_cmd;
}

void bf_request_set_ns(struct bf_request *request, struct bf_ns *ns)
{
    bf_assert(request);
    request->ns = ns;
}

void bf_request_set_fd(struct bf_request *request, int fd)
{
    bf_assert(request);
    request->fd = fd;
}

void bf_request_set_ipt_cmd(struct bf_request *request, int ipt_cmd)
{
    bf_assert(request);
    request->ipt_cmd = ipt_cmd;
}

const char *bf_request_cmd_to_str(enum bf_request_cmd cmd)
{
    static const char *cmd_strs[] = {
        [BF_REQ_RULESET_FLUSH] = "BF_REQ_RULESET_FLUSH",
        [BF_REQ_RULESET_GET] = "BF_REQ_RULESET_GET",
        [BF_REQ_RULESET_SET] = "BF_REQ_RULESET_SET",
        [BF_REQ_CHAIN_SET] = "BF_REQ_CHAIN_SET",
        [BF_REQ_CHAIN_GET] = "BF_REQ_CHAIN_GET",
        [BF_REQ_CHAIN_LOAD] = "BF_REQ_CHAIN_LOAD",
        [BF_REQ_CHAIN_ATTACH] = "BF_REQ_CHAIN_ATTACH",
        [BF_REQ_CHAIN_UPDATE] = "BF_REQ_CHAIN_UPDATE",
        [BF_REQ_CHAIN_PROG_FD] = "BF_REQ_CHAIN_PROG_FD",
        [BF_REQ_CHAIN_LOGS_FD] = "BF_REQ_CHAIN_LOGS_FD",
        [BF_REQ_CHAIN_FLUSH] = "BF_REQ_CHAIN_FLUSH",
        [BF_REQ_COUNTERS_SET] = "BF_REQ_COUNTERS_SET",
        [BF_REQ_COUNTERS_GET] = "BF_REQ_COUNTERS_GET",
        [BF_REQ_CUSTOM] = "BF_REQ_CUSTOM",
    };

    static_assert(ARRAY_SIZE(cmd_strs) == _BF_REQ_CMD_MAX,
                  "missing entries in bf_request_cmd array");

    return cmd_strs[cmd];
}
