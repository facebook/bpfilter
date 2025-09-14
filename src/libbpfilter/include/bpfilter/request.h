/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#pragma once

#include <stddef.h>

#include <bpfilter/front.h>
#include <bpfilter/helper.h>
#include <bpfilter/pack.h>

struct bf_dynbuf;
struct bf_ns;

#define _free_bf_request_ __attribute__((cleanup(bf_request_free)))

/**
 * @enum bf_request_cmd
 *
 * Defines a request type, so bpfilter can understand the client-specific
 * data contained in the request, and call the proper handler.
 *
 * @var bf_request_cmd::BF_REQ_CUSTOM
 *  Custom request: only the front this request is targeted to is able to
 *  understand what is the actual command. Allows for fronts to implement
 *  new commands.
 */
enum bf_request_cmd
{
    /* Flush the ruleset: remove all the filtering rules defined for a
     * front-end. */
    BF_REQ_RULESET_FLUSH,
    BF_REQ_RULESET_GET,

    /** Set the current ruleset. Existing chains are flushed for the current
     * front-end and replaced with the chains defined in the request. */
    BF_REQ_RULESET_SET,

    BF_REQ_CHAIN_SET,
    BF_REQ_CHAIN_GET,
    BF_REQ_CHAIN_PROG_FD,
    BF_REQ_CHAIN_LOGS_FD,
    BF_REQ_CHAIN_LOAD,
    BF_REQ_CHAIN_ATTACH,
    BF_REQ_CHAIN_UPDATE,
    BF_REQ_CHAIN_FLUSH,

    BF_REQ_COUNTERS_SET,
    BF_REQ_COUNTERS_GET,
    BF_REQ_CUSTOM,
    _BF_REQ_CMD_MAX,
};

struct bf_request;

/**
 * Allocate and initialise a new request.
 *
 * @param request Pointer to the request to allocate. Must be non-NULL.
 * @param front Front identifier.
 * @param cmd Request command.
 * @param data Client-specific data.
 * @param data_len Length of the client-specific data.
 * @return 0 on success or negative errno code on failure.
 */
int bf_request_new(struct bf_request **request, enum bf_front front,
                   enum bf_request_cmd cmd, const void *data, size_t data_len);

int bf_request_new_from_dynbuf(struct bf_request **request,
                               struct bf_dynbuf *dynbuf);
int bf_request_new_from_pack(struct bf_request **request, enum bf_front front,
                             enum bf_request_cmd cmd, bf_wpack_t *pack);

/**
 * Free a request.
 *
 * If @p request points to a NULL pointer, this function does nothing. Once the
 * function returns, @p request points to a NULL pointer.
 *
 * @param request Request to free. Can't be NULL.
 */
void bf_request_free(struct bf_request **request);

/**
 * Copy a request.
 *
 * @param dest The destination request. It will be allocated during the call.
 *        Can't be NULL.
 * @param src The source request, to copy. Can't be NULL.
 * @return 0 on success, negative error code on failure.
 */
int bf_request_copy(struct bf_request **dest, const struct bf_request *src);

enum bf_front bf_request_front(const struct bf_request *request);
struct bf_ns *bf_request_ns(const struct bf_request *request);
enum bf_request_cmd bf_request_cmd(const struct bf_request *request);
int bf_request_fd(const struct bf_request *request);
int bf_request_ipt_cmd(const struct bf_request *request);
const void *bf_request_data(const struct bf_request *request);
size_t bf_request_data_len(const struct bf_request *request);

void bf_request_set_ns(struct bf_request *request, struct bf_ns *ns);
void bf_request_set_fd(struct bf_request *request, int fd);
void bf_request_set_ipt_cmd(struct bf_request *request, int ipt_cmd);

/**
 * Get the total size of the request: request structure and data.
 *
 * @param request Request to get the size of. Can't be NULL.
 * @return Total size of the request.
 */
size_t bf_request_size(const struct bf_request *request);

/**
 * @brief Convert a `bf_request_cmd` value to a string.
 *
 * @param cmd The request command to convert. Must be a valid command.
 * @return String representation of `cmd`.
 */
const char *bf_request_cmd_to_str(enum bf_request_cmd cmd);
