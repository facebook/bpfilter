/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#pragma once

#include <linux/netlink.h>

#include <bpfilter/shared/request.h>
#include <bpfilter/shared/response.h>
#include <stdint.h>

struct ipt_getinfo;
struct ipt_get_entries;
struct ipt_replace;
struct xt_counters_info;

/**
 * @brief Send a request to the daemon and receive the response.
 *
 * @param request Request to send to the daemon. Caller keep ownership of
 * the request. Can't be NULL.
 * @param response Response received from the daemon. It will be allocated
 * by the function and the caller will be responsible for freeing it. Can't
 * be NULL.
 * @return 0 on success, negative errno value on error.
 */
int bf_send(const struct bf_request *request, struct bf_response **response);

/**
 * @brief Send iptable's ipt_replace data to bpfilter daemon.
 *
 * @param ipt_replace ipt_replace data to send to the daemon. Can't be NULL.
 *  Data returned by the daemon will be stored in the same structure.
 * @return 0 on success, negative errno value on error.
 */
int bf_ipt_replace(struct ipt_replace *ipt_replace);

/**
 * @brief Send iptable's xt_counters_info data to bpfilter daemon.
 *
 * @param counters xt_counters_info data to send to the daemon. Can't be NULL.
 *  Data returned by the daemon will be stored in the same structure.
 * @return 0 on success, negative errno value on error.
 */
int bf_ipt_add_counters(struct xt_counters_info *counters);

/**
 * @brief Send iptable's ipt_getinfo data to bpfilter daemon.
 *
 * @param info ipt_getinfo data to send to the daemon. Can't be NULL.
 *  Data returned by the daemon will be stored in the same structure.
 * @return 0 on success, negative errno value on error.
 */
int bf_ipt_get_info(struct ipt_getinfo *info);

/**
 * @brief Send iptable's ipt_get_entries data to bpfilter daemon.
 *
 * @param entries ipt_get_entries data to send to the daemon. Can't be NULL.
 *  Data returned by the daemon will be stored in the same structure.
 * @return 0 on success, negative errno value on error.
 */
int bf_ipt_get_entries(struct ipt_get_entries *entries);

/**
 * @brief Send nftable's Netlink request to the bpfilter daemon but do not
 *  expect a response.
 *
 * @param data Netlink request to send to the daemon. Caller keep ownership
 *  of the request. Can't be NULL.
 * @param len Length of the request. Can't be 0.
 * @return 0 on success, negative errno value on error. Returns an error if
 *  @p data is NULL or @p len is 0.
 */
int bf_nft_send(const void *data, size_t len);

/**
 * @brief Send nftable's Netlink request to the bpfilter daemon and write the
 *  response back.
 *
 * @p res and @p res_len won't be modified unless the call is successful.
 *
 * @param req Netlink request to send to the daemon. Caller keep ownership
 *  of the request. Can't be NULL.
 * @param req_len Length of the request. Can't be 0.
 * @param res Response received from the daemon. The caller is responsible for
 *  allocating the buffer. Can't be NULL.
 * @param res_len Length of the response buffer. Can't be 0. If the call the
 *  successful, it will be updated with the length of the response.
 * @return 0 on success, negative errno value on error.
 */
int bf_nft_sendrecv(const struct nlmsghdr *req, size_t req_len,
                    struct nlmsghdr *res, size_t *res_len);
