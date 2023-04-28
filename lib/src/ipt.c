/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#include <linux/netfilter_ipv4/ip_tables.h>

#include <bpfilter/bpfilter.h>
#include <stddef.h>
#include <stdio.h>

#define ipt_replace_size(ipt_replace)                                          \
    (sizeof(struct ipt_replace) + ipt_replace->size)

int bf_ipt_replace(struct ipt_replace *ipt_replace)
{
    __cleanup_bf_request__ struct bf_request *request = NULL;
    __cleanup_bf_response__ struct bf_response *response = NULL;
    int r;

    assert(ipt_replace);

    r = bf_request_new(&request, ipt_replace_size(ipt_replace), ipt_replace);
    if (r < 0)
        return r;

    request->type = BF_REQ_IPT;

    r = bf_send(request, &response);
    if (r < 0)
        return r;

    return response->type == BF_RES_FAILURE ? response->error : 0;
}
