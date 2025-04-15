/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#pragma once

#include <stdbool.h>
#include <stddef.h>

struct bf_response;
struct bf_chain;
struct ipt_getinfo;
struct ipt_get_entries;
struct ipt_replace;
struct xt_counters_info;
struct nlmsghdr;
struct bf_hookopts;

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

#define bf_list void

/**
 * Request the daemon to return all the chains and all of
 * the associated rules.
 *
 * @param chains List of bf_chain type to be filled.
 * @param hookopts List of hook options objects.
 * @param counters List of bf_counter type to be filled.
 * @return 0 on success, or a negative errno value on error.
 */
int bf_cli_ruleset_get(bf_list *chains, bf_list *hookopts, bf_list *counters);

/**
 * Load a complete ruleset.
 *
 * The daemon will flush the whole ruleset for BF_FRONT_CLI and install the
 * chains defined in the provided lists instead.
 *
 * `hookopts` should contain as many elements as `chains`, so they can be
 * mapped 1 to 1. If a chain shouldn't be attached, they the corresponding
 * entry in `hookopts` should be NULL.
 *
 * @param chains List of chains to define. Can't be NULL.
 * @param hookopts List of hook options to attach the chains in `chain`. Can't be
 *        NULL.
 * @return 0 on success, or a negative errno value on error.
 */
int bf_cli_ruleset_set(bf_list *chains, bf_list *hookopts);

/**
 * Set a chain.
 *
 * If a chain with the same name already exist, it is detached and unloaded.
 * The new chain is loaded, and attached if hook options are defined.
 *
 * The serialized data is formatted as:
 * - Main marsh
 *   - Chain marsh: contains `bf_chain` fields.
 *   - Hook marsh: contains `bf_hookopts` fields, or empty is the chain is
 *     not attached
 *
 * @param chain Chain to set. Can't be NULL.
 * @param hookopts Hook options to attach the chain. If NULL, the chain is not
 *        attached.
 * @return 0 on success, or a negative errno value on failure.
 */
int bf_chain_set(struct bf_chain *chain, struct bf_hookopts *hookopts);

/**
 * Get a chain.
 *
 * If a chain with the same name already exist, `-EEXIST` is returned.
 *
 * The serialized data is formatted as:
 * - Main marsh
 *   - Marsh for the chain's name (including `\0`).
 *
 * Expects the following data:
 * - Main mash
 *   - Chain marsh: container `bf_chain` fields.
 *   - Hook options marsh: contains `bf_hookopts` fields, or empty is the chain
 *     is not attached.
 *   - List marsh: contains marshes for the counters
 *     - Counter marsh: contains `bf_counter` fields.
 *     - ...
 *
 * @param name Name of the chain to look for. Can't be NULL.
 * @param chain On success, contains a pointer to the chain. The caller is
 *        responsible for freeing it. Can't be NULL.
 * @param hookopts On success, contains a pointer to the chain's hook options if
 *        the chain is attached, NULL otherwise. The caller is responsible for
 *        freeing it. Can't be NULL.
 * @param counters On success, the list contain the counters for every rule of
 *        the chain, and the policy and error counters. The caller is
 *        responsible for freeing it. Can't be NULL.
 * @return 0 on success, or a negative errno value on failure, including:
 * - `-ENOENT`: no chain found for this name.
 */
int bf_chain_get(const char *name, struct bf_chain **chain,
                 struct bf_hookopts **hookopts, bf_list *counters);

#undef bf_list

/**
 * Load a chain.
 *
 * If a chain with the same name already exist, `-EEXIST` is returned.
 *
 * The serialized data is formatted as:
 * - Main marsh
 *   - Chain marsh: contains `bf_chain` fields.
 *
 * @param chain Chain to load. Can't be NULL.
 * @return 0 on success, or a negative errno value on failure.
 */
int bf_chain_load(struct bf_chain *chain);

/**
 * Attach a chain.
 *
 * If the chain doesn't exist, `-ENOENT` is returned.
 *
 * The serialized data is formatted as:
 * - Main marsh
 *   - Marsh for the chain's name (including `\0`).
 *   - Hook options marsh: contains `bf_hookopts` fields.
 *
 * @param name Name of the chain to attach. Can't be NULL.
 * @param hookopts Hook options to attach the chain. Can't be NULL.
 * @return 0 on success, or a negative errno value on failure, including:
 * - `-ENOENT`: no chain found for this name.
 * - `-EBUSY`: chain is already attached.
 */
int bf_chain_attach(const char *name, const struct bf_hookopts *hookopts);

/**
 * Update an attached chain.
 *
 * The chain to update must exist and be attached to a hook.
 *
 * The serialized data is formatted as:
 * - Main marsh
 *   - Chain marsh: container `bf_chain` fields.
 *
 * @param chain Chain to update. Can't be NULL.
 * @return 0 on success, or a negative errno value on failure, including:
 * - `-ENOENT`: no chain found for this name.
 * - `-ENOLINK`: the chain to update is not attached.
 */
int bf_chain_update(const struct bf_chain *chain);

/**
 * Flush a chain (detach and unload).
 *
 * The serialized data is formatted as:
 * - Main marsh
 *   - Marsh for the chain's name (including `\0`).
 *
 * @param name Name of the chain to flush. Can't be NULL.
 * @return 0 on success, or a negative errno value on failure, including:
 * - `-ENOENT`: no chain found for this name.
 */
int bf_chain_flush(const char *name);

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
