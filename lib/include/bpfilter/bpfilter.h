/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#pragma once

#include <bpfilter/shared/request.h>
#include <bpfilter/shared/response.h>

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
