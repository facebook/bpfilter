/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#pragma once

#include <stdbool.h>
#include <stddef.h>

struct bf_chain;
struct ipt_getinfo;
struct ipt_get_entries;
struct ipt_replace;
struct xt_counters_info;
struct nlmsghdr;

/**
 * Return the version of the library.
 *
 * @return Version of the library, as a string.
 */
const char *bf_version(void);

/**
 * Request the daemon to remove all the chains and rules.
 *
 * @return 0 on success, or a negative errno value on error.
 */
int bf_cli_ruleset_flush(void);

/**
 * Request the daemon to return all the chains and all of
 * the associated rules.
 *
 * @param with_counters If true, the daemon will return the counters.
 * @return 0 on success, or a negative errno value on error.
 */
int bf_cli_ruleset_get(bool with_counters);

/**
 * Send a chain to the daemon.
 *
 * @param chain Chain to send to the daemon. Can't be NULL.
 * @return 0 on success, or a negative errno value on error.
 */
int bf_cli_set_chain(const struct bf_chain *chain);

/**
 * Send iptable's ipt_replace data to bpfilter daemon.
 *
 * @param ipt_replace ipt_replace data to send to the daemon. Can't be NULL.
 *        Data returned by the daemon will be stored in the same structure.
 * @return 0 on success, negative errno value on error.
 */
int bf_ipt_replace(struct ipt_replace *ipt_replace);

/**
 * Send iptable's xt_counters_info data to bpfilter daemon.
 *
 * @param counters xt_counters_info data to send to the daemon. Can't be NULL.
 *        Data returned by the daemon will be stored in the same structure.
 * @return 0 on success, negative errno value on error.
 */
int bf_ipt_add_counters(struct xt_counters_info *counters);

/**
 * Send iptable's ipt_getinfo data to bpfilter daemon.
 *
 * @param info ipt_getinfo data to send to the daemon. Can't be NULL.
 *        Data returned by the daemon will be stored in the same structure.
 * @return 0 on success, negative errno value on error.
 */
int bf_ipt_get_info(struct ipt_getinfo *info);

/**
 * Send iptable's ipt_get_entries data to bpfilter daemon.
 *
 * @param entries ipt_get_entries data to send to the daemon. Can't be NULL.
 *        Data returned by the daemon will be stored in the same structure.
 * @return 0 on success, negative errno value on error.
 */
int bf_ipt_get_entries(struct ipt_get_entries *entries);

/**
 * Send nftable's Netlink request to the bpfilter daemon but do not
 * expect a response.
 *
 * @param data Netlink data to send to the daemon. Can't be NULL.
 * @param len Length of the request. Can't be 0.
 * @return 0 on success, or negative errno value on error. Returns an error if
 *         @p data is NULL or @p len is 0.
 */
int bf_nft_send(const void *data, size_t len);

/**
 * Send nftable's Netlink request to the bpfilter daemon and write the
 * response back.
 *
 * @p res and @p res_len won't be modified unless the call is successful.
 *
 * @param req Netlink request to send to the daemon. The caller retain ownership
 *        of the request. Can't be NULL.
 * @param req_len Length of the request. Can't be 0.
 * @param res Buffer to store the response. Can't be NULL. Must be allocated by
 *        the caller.
 * @param res_len Size of the response buffer. If the call is successful, @p
 *        res_len will be updated to the length of the response. If the data
 *        received from the daemon is larger than the buffer, the function will
 *        return @p -EMSGSIZE and @p res_len will be updated to the size of the
 *        response.
 * @return 0 on success, or negative errno value on error.
 */
int bf_nft_sendrecv(const struct nlmsghdr *req, size_t req_len,
                    struct nlmsghdr *res, size_t *res_len);
