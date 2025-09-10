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

#include "core/helper.h"
#include "core/pack.h"

int bf_request_new(struct bf_request **request, const void *data,
                   size_t data_len)
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

    *request = TAKE_PTR(_request);

    return 0;
}

int bf_request_new_from_pack(struct bf_request **request, bf_wpack_t *pack)
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

    return bf_request_new(request, data, data_len);
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
