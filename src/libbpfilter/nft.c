/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#include <linux/netlink.h>

#include <errno.h>
#include <stdio.h>
#include <string.h>

#include "core/front.h"
#include "core/request.h"
#include "core/response.h"
#include "libbpfilter/generic.h"

int bf_nft_send(const void *data, size_t len)
{
    _free_bf_request_ struct bf_request *request = NULL;
    _free_bf_response_ struct bf_response *response = NULL;
    int r;

    if (!data || !len)
        return -EINVAL;

    r = bf_request_new(&request, data, len);
    if (r < 0)
        return r;

    request->front = BF_FRONT_NFT;

    r = bf_send(request, &response);
    if (r < 0)
        return r;

    return response->status;
}

int bf_nft_sendrecv(const struct nlmsghdr *req, size_t req_len,
                    struct nlmsghdr *res, size_t *res_len)
{
    _free_bf_request_ struct bf_request *request = NULL;
    _free_bf_response_ struct bf_response *response = NULL;
    int r;

    if (!req || !req_len || !res || !res_len)
        return -EINVAL;

    if (req_len != req->nlmsg_len)
        return -EINVAL;

    r = bf_request_new(&request, req, req_len);
    if (r < 0)
        return r;

    request->front = BF_FRONT_NFT;

    r = bf_send(request, &response);
    if (r < 0)
        return r;

    if (response->status != 0)
        return response->status;

    // The response should be a netlink message
    if (response->data_len < NLMSG_HDRLEN)
        return -EMSGSIZE;

    if (((struct nlmsghdr *)response->data)->nlmsg_len != response->data_len)
        return -EMSGSIZE;

    if (response->data_len > *res_len) {
        *res_len = response->data_len;
        return -EMSGSIZE;
    }

    memcpy(res, response->data, response->data_len);
    *res_len = response->data_len;

    return 0;
}
