/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#include <linux/netfilter/x_tables.h>
#include <linux/netfilter_ipv4/ip_tables.h>

#include <errno.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>

#include "core/front.h"
#include "core/helper.h"
#include "core/logger.h"
#include "core/request.h"
#include "core/response.h"
#include "libbpfilter/generic.h"

/**
 * Get size of an ipt_get_entries structure.
 *
 * @param ipt_get_entries_ptr Pointer to a valid ipt_get_entries structure.
 * @return Size of the structure, including variable length entries field.
 */
#define bf_ipt_get_entries_size(ipt_get_entries_ptr)                           \
    (sizeof(struct ipt_get_entries) + (ipt_get_entries_ptr)->size)

/**
 * Get size of an xt_counters_info structure.
 *
 * @param xt_counters_info_ptr Pointer to a valid xt_counters_info structure.
 * @return Size of the structure, including variable length counters field.
 */
#define bf_xt_counters_info_size(xt_counters_info_ptr)                         \
    (sizeof(struct xt_counters_info) +                                         \
     ((xt_counters_info_ptr)->num_counters * sizeof(struct xt_counters)))
/**
 * Get size of an ipt_replace structure.
 *
 * @param ipt_replace_ptr Pointer to a valid ipt_replace structure.
 * @return Size of the structure, including variable length entries field.
 */
#define bf_ipt_replace_size(ipt_replace_ptr)                                   \
    (sizeof(struct ipt_replace) + (ipt_replace_ptr)->size)

int bf_ipt_replace(struct ipt_replace *ipt_replace)
{
    _cleanup_bf_request_ struct bf_request *request = NULL;
    _cleanup_bf_response_ struct bf_response *response = NULL;
    int r;

    bf_assert(ipt_replace);

    r = bf_request_new(&request, ipt_replace, bf_ipt_replace_size(ipt_replace));
    if (r < 0)
        return r;

    request->front = BF_FRONT_IPT;
    request->cmd = BF_REQ_SET_RULES;

    r = bf_send(request, &response);
    if (r < 0)
        return r;

    if (response->type == BF_RES_SUCCESS) {
        if (response->data_len != request->data_len) {
            return bf_err_r(EINVAL,
                            "bpfilter: response size is %lu, expected %lu",
                            response->data_len, request->data_len);
        }

        memcpy(ipt_replace, response->data, response->data_len);
    }

    return response->type == BF_RES_FAILURE ? response->error : 0;
}

int bf_ipt_add_counters(struct xt_counters_info *counters)
{
    _cleanup_bf_request_ struct bf_request *request = NULL;
    _cleanup_bf_response_ struct bf_response *response = NULL;
    int r;

    bf_assert(counters);

    r = bf_request_new(&request, counters, bf_xt_counters_info_size(counters));
    if (r < 0)
        return r;

    request->front = BF_FRONT_IPT;
    request->cmd = BF_REQ_SET_COUNTERS;

    r = bf_send(request, &response);
    if (r < 0)
        return r;

    if (response->type == BF_RES_SUCCESS) {
        if (response->data_len != request->data_len) {
            return bf_err_r(EINVAL,
                            "bpfilter: response size is %lu, expected %lu",
                            response->data_len, request->data_len);
        }

        memcpy(counters, response->data, response->data_len);
    }

    return response->type == BF_RES_FAILURE ? response->error : 0;
}

int bf_ipt_get_info(struct ipt_getinfo *info)
{
    _cleanup_bf_request_ struct bf_request *request = NULL;
    _cleanup_bf_response_ struct bf_response *response = NULL;
    int r;

    bf_assert(info);

    r = bf_request_new(&request, info, sizeof(*info));
    if (r < 0)
        return r;

    request->front = BF_FRONT_IPT;
    request->cmd = BF_REQ_CUSTOM;
    request->ipt_cmd = IPT_SO_GET_INFO;

    r = bf_send(request, &response);
    if (r < 0)
        return r;

    if (response->type == BF_RES_SUCCESS) {
        if (response->data_len != request->data_len) {
            return bf_err_r(EINVAL,
                            "bpfilter: response size is %lu, expected %lu",
                            response->data_len, request->data_len);
        }

        memcpy(info, response->data, response->data_len);
    }

    return response->type == BF_RES_FAILURE ? response->error : 0;
}

int bf_ipt_get_entries(struct ipt_get_entries *entries)
{
    _cleanup_bf_request_ struct bf_request *request = NULL;
    _cleanup_bf_response_ struct bf_response *response = NULL;
    int r;

    bf_assert(entries);

    r = bf_request_new(&request, entries, bf_ipt_get_entries_size(entries));
    if (r < 0)
        return r;

    request->front = BF_FRONT_IPT;
    request->cmd = BF_REQ_CUSTOM;
    request->ipt_cmd = IPT_SO_GET_ENTRIES;

    r = bf_send(request, &response);
    if (r < 0)
        return r;

    if (response->type == BF_RES_SUCCESS) {
        if (response->data_len != request->data_len) {
            return bf_err_r(EINVAL,
                            "bpfilter: response size is %lu, expected %lu",
                            response->data_len, request->data_len);
        }

        memcpy(entries, response->data, response->data_len);
    }

    return response->type == BF_RES_FAILURE ? response->error : 0;
}
