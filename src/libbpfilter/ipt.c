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

#include "bpfilter/front.h"
#include "bpfilter/helper.h"
#include "bpfilter/io.h"
#include "bpfilter/logger.h"
#include "bpfilter/request.h"
#include "bpfilter/response.h"

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
    _cleanup_close_ int fd = -1;
    _free_bf_request_ struct bf_request *request = NULL;
    _free_bf_response_ struct bf_response *response = NULL;
    int r;

    bf_assert(ipt_replace);

    r = bf_request_new(&request, BF_FRONT_IPT, BF_REQ_RULESET_SET, ipt_replace,
                       bf_ipt_replace_size(ipt_replace));
    if (r < 0)
        return r;

    fd = bf_connect_to_daemon();
    if (fd < 0)
        return bf_err_r(fd, "failed to connect to the daemon");

    r = bf_send(fd, request, &response, NULL);
    if (r < 0)
        return r;

    if (bf_response_status(response) == 0) {
        if (bf_response_data_len(response) != bf_request_data_len(request)) {
            return bf_err_r(
                EINVAL, "bpfilter: response size is %lu, expected %lu",
                bf_response_data_len(response), bf_request_data_len(request));
        }

        memcpy(ipt_replace, bf_response_data(response),
               bf_response_data_len(response));
    }

    return bf_response_status(response);
}

int bf_ipt_add_counters(struct xt_counters_info *counters)
{
    _cleanup_close_ int fd = -1;
    _free_bf_request_ struct bf_request *request = NULL;
    _free_bf_response_ struct bf_response *response = NULL;
    int r;

    bf_assert(counters);

    r = bf_request_new(&request, BF_FRONT_IPT, BF_REQ_COUNTERS_SET, counters,
                       bf_xt_counters_info_size(counters));
    if (r < 0)
        return r;

    fd = bf_connect_to_daemon();
    if (fd < 0)
        return bf_err_r(fd, "failed to connect to the daemon");

    r = bf_send(fd, request, &response, NULL);
    if (r < 0)
        return r;

    if (bf_response_status(response) == 0) {
        if (bf_response_data_len(response) != bf_request_data_len(request)) {
            return bf_err_r(
                EINVAL, "bpfilter: response size is %lu, expected %lu",
                bf_response_data_len(response), bf_request_data_len(request));
        }

        memcpy(counters, bf_response_data(response),
               bf_response_data_len(response));
    }

    return bf_response_status(response);
}

int bf_ipt_get_info(struct ipt_getinfo *info)
{
    _cleanup_close_ int fd = -1;
    _free_bf_request_ struct bf_request *request = NULL;
    _free_bf_response_ struct bf_response *response = NULL;
    int r;

    bf_assert(info);

    r = bf_request_new(&request, BF_FRONT_IPT, BF_REQ_CUSTOM, info,
                       sizeof(*info));
    if (r < 0)
        return r;

    bf_request_set_ipt_cmd(request, IPT_SO_GET_INFO);

    fd = bf_connect_to_daemon();
    if (fd < 0)
        return bf_err_r(fd, "failed to connect to the daemon");

    r = bf_send(fd, request, &response, NULL);
    if (r < 0)
        return r;

    if (bf_response_status(response) == 0) {
        if (bf_response_data_len(response) != bf_request_data_len(request)) {
            return bf_err_r(
                EINVAL, "bpfilter: response size is %lu, expected %lu",
                bf_response_data_len(response), bf_request_data_len(request));
        }

        memcpy(info, bf_response_data(response),
               bf_response_data_len(response));
    }

    return bf_response_status(response);
}

int bf_ipt_get_entries(struct ipt_get_entries *entries)
{
    _cleanup_close_ int fd = -1;
    _free_bf_request_ struct bf_request *request = NULL;
    _free_bf_response_ struct bf_response *response = NULL;
    int r;

    bf_assert(entries);

    r = bf_request_new(&request, BF_FRONT_IPT, BF_REQ_CUSTOM, entries,
                       bf_ipt_get_entries_size(entries));
    if (r < 0)
        return r;

    bf_request_set_ipt_cmd(request, IPT_SO_GET_ENTRIES);

    fd = bf_connect_to_daemon();
    if (fd < 0)
        return bf_err_r(fd, "failed to connect to the daemon");

    r = bf_send(fd, request, &response, NULL);
    if (r < 0)
        return r;

    if (bf_response_status(response) == 0) {
        if (bf_response_data_len(response) != bf_request_data_len(request)) {
            return bf_err_r(
                EINVAL, "bpfilter: response size is %lu, expected %lu",
                bf_response_data_len(response), bf_request_data_len(request));
        }

        memcpy(entries, bf_response_data(response),
               bf_response_data_len(response));
    }

    return bf_response_status(response);
}
