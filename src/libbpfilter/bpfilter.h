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

#define bf_list void

/**
 * @brief Get the ruleset from the daemon.
 *
 * **Request payload format**
 * The request doesn't contain data.
 *
 * **Response payload format**
 * @code{.json}
 * {
 *   "ruleset": {
 *     "chains": [
 *       {  }, // bf_chain object
 *       // ...
 *     ],
 *     "hookopts": [
 *       {  }, // bf_hookopts object or nil
 *       // ...
 *     ],
 *     "counters": [
 *       [
 *         { }, // bf_counter object
 *         // ...
 *       ],
 *       // ...
 *     ],
 *   },
 * }
 * @endcode
 *
 * In the response, "hookopts" and "counters" contains as many entries as
 * "chains". If a chain is not attached, the corresponding "hookopts" entry
 * is `nil`. "counters" contains arrays of `bf_counter` object, is nested
 * array contains as many entries as rules defined in the corresponding chain.
 * Use the chain's rule `.counters` field to check is the corresponding
 * `bf_counter` object contains valid data.
 *
 * @param chains List of `bf_chain` to be filled.
 * @param hookopts List of hook options objects.
 * @param counters List of `bf_counter` to be filled.
 * @return 0 on success, or a negative error value on failure.
 */
int bf_ruleset_get(bf_list *chains, bf_list *hookopts, bf_list *counters);

/**
 * @brief Load a ruleset.
 *
 * The daemon will flush the whole ruleset for BF_FRONT_CLI and install the
 * chains defined in the provided lists instead.
 *
 * `hookopts` should contain as many elements as `chains`, so they can be
 * mapped 1 to 1. If a chain shouldn't be attached, they the corresponding
 * entry in `hookopts` should be NULL.
 *
 * **Request payload format**
 * @code{.json}
 * {
 *   "ruleset": [
 *     {
 *       "chain": { }, // bf_chain object
 *       "hookopts": { }, // bf_hookopts object, or nil
 *     },
 *     // ...
 *   ],
 * }
 * @endcode
 *
 * **Response payload format**
 * The response doesn't contain data.
 *
 * @param chains List of chains to define. Can't be NULL.
 * @param hookopts List of hook options to attach the chains in `chain`. Can't
 *        be NULL.
 * @return 0 on success, or a negative error value on failure.
 */
int bf_ruleset_set(bf_list *chains, bf_list *hookopts);

/**
 * @brief Remove the current ruleset.
 *
 * **Request payload format**
 * The request doesn't contain data.
 *
 * **Response payload format**
 * The response doesn't contain data.
 *
 * @return 0 on success, or a negative error value on failure.
 */
int bf_ruleset_flush(void);

/**
 * @brief Set a chain.
 *
 * If a chain with the same name already exist, it is detached and unloaded.
 * The new chain is loaded, and attached if hook options are defined.
 *
 * **Request payload format**
 * @code{.json}
 * {
 *   "chain": { }, // bf_chain object
 *   "hookopts": { } // bf_hookopts object or nil
 * }
 * @endcode
 *
 * **Response payload format**
 * The response doesn't contain data.
 *
 * @param chain Chain to set. Can't be NULL.
 * @param hookopts Hook options to attach the chain. If NULL, the chain is not
 *        attached.
 * @return 0 on success, or a negative errno value on failure.
 */
int bf_chain_set(struct bf_chain *chain, struct bf_hookopts *hookopts);

/**
 * @brief Get a chain.
 *
 * **Request payload format**
 * @code{.json}
 * {
 *   "name": "",
 * }
 * @endcode
 *
 * **Response payload format**
 * @code{.json}
 * {
 *   "chain": { }, // bf_chain object
 *   "hookopts": { }, // bf_hookopts object or nil
 *   "counters": [
 *     { }, // bf_counter object
 *     // ...
 *   ],
 * }
 * @endcode
 *
 * "counters" is an array of `bf_counter` objects, it contains as many entries
 * as rules defined in the chain. Use the chain's rule `.counters` field to
 * check is the corresponding `bf_counter` object contains valid data.
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
 * @brief Get the file descriptor of a chain's program.
 *
 * **Request payload format**
 * @code{.json}
 * {
 *   "name": "",
 * }
 * @endcode
 *
 * **Response payload format**
 * The response doesn't contain data.
 *
 * @warning Do not use this function. `bf_chain_prog_fd` is designed to simplify
 * end-to-end tests of the generated programs, to validate bytecode generation.
 * It should be considered unstable, and manipulating the BPF program directly
 * could cause issues with bpfilter itself. Eventually, this API will be
 * disabled for non-tests use cases.
 *
 * @pre
 * - `name` is a non-NULL pointer to a C-string.
 *
 * @param name Name of the chain to get the program from.
 * @return File descriptor of the chain's program, or a negative error value
 *         on failure. The caller owns the file descriptor.
 */
int bf_chain_prog_fd(const char *name);

/**
 * @brief Get the file descriptor of a chain's logs buffer.
 *
 * **Request payload format**
 * @code{.json}
 * {
 *   "name": "",
 * }
 * @endcode
 *
 * **Response payload format**
 * The response doesn't contain data.
 *
 * @pre
 * - `name` is a non-NULL pointer to a C-string.
 *
 * @param name Name of the chain to get the log buffer from.
 * @return File descriptor of the chain's logs buffer, or a negative error value
 *         on failure. The caller owns the file descriptor.
 */
int bf_chain_logs_fd(const char *name);

/**
 * @brief Load a chain.
 *
 * If a chain with the same name already exist, `-EEXIST` is returned.
 *
 * **Request payload format**
 * @code{.json}
 * {
 *   "chain": { }, // bf_chain object
 * }
 * @endcode
 *
 * **Response payload format**
 * The response doesn't contain data.
 *
 * @param chain Chain to load. Can't be NULL.
 * @return 0 on success, or a negative errno value on failure.
 */
int bf_chain_load(struct bf_chain *chain);

/**
 * @brief Attach a chain.
 *
 * If the chain doesn't exist, `-ENOENT` is returned.
 *
 * **Request payload format**
 * @code{.json}
 * {
 *   "name": "",
 *   "hookopts": { }, // bf_hookopts object
 * }
 * @endcode
 *
 * **Response payload format**
 * The response doesn't contain data.
 *
 * @param name Name of the chain to attach. Can't be NULL.
 * @param hookopts Hook options to attach the chain. Can't be NULL.
 * @return 0 on success, or a negative errno value on failure, including:
 * - `-ENOENT`: no chain found for this name.
 * - `-EBUSY`: chain is already attached.
 */
int bf_chain_attach(const char *name, const struct bf_hookopts *hookopts);

/**
 * @brief Update an attached chain.
 *
 * The chain to update must exist and be attached to a hook.
 *
 * **Request payload format**
 * @code{.json}
 * {
 *   "chain": { }, // bf_chain object
 * }
 * @endcode
 *
 * **Response payload format**
 * The response doesn't contain data.
 *
 * @param chain Chain to update. Can't be NULL.
 * @return 0 on success, or a negative errno value on failure, including:
 * - `-ENOENT`: no chain found for this name.
 * - `-ENOLINK`: the chain to update is not attached.
 */
int bf_chain_update(const struct bf_chain *chain);

/**
 * @brief Remove a chain.
 *
 * **Request payload format**
 * @code{.json}
 * {
 *   "name": "",
 * }
 * @endcode
 *
 * **Response payload format**
 * The response doesn't contain data.
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
