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

    r = bf_request_new(&request, BF_FRONT_NFT, 0, data, len);
    if (r < 0)
        return r;

    r = bf_send(request, &response);
    if (r < 0)
        return r;

    return bf_response_status(response);
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

    r = bf_request_new(&request, BF_FRONT_NFT, 0, req, req_len);
    if (r < 0)
        return r;

    r = bf_send(request, &response);
    if (r < 0)
        return r;

    if (bf_response_status(response) != 0)
        return bf_response_status(response);

    // The response should be a netlink message
    if (bf_response_data_len(response) < NLMSG_HDRLEN)
        return -EMSGSIZE;

    if (((const struct nlmsghdr *)bf_response_data(response))->nlmsg_len !=
        bf_response_data_len(response))
        return -EMSGSIZE;

    if (bf_response_data_len(response) > *res_len) {
        *res_len = bf_response_data_len(response);
        return -EMSGSIZE;
    }

    memcpy(res, bf_response_data(response), bf_response_data_len(response));
    *res_len = bf_response_data_len(response);

    return 0;
}
