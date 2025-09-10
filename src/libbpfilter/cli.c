/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#include <errno.h>
#include <string.h>

#include "core/chain.h"
#include "core/counter.h"
#include "core/front.h"
#include "core/helper.h"
#include "core/hook.h"
#include "core/io.h"
#include "core/list.h"
#include "core/logger.h"
#include "core/pack.h"
#include "core/request.h"
#include "core/response.h"
#include "libbpfilter/generic.h"

int bf_ruleset_get(bf_list *chains, bf_list *hookopts, bf_list *counters)
{
    _free_bf_request_ struct bf_request *request = NULL;
    _free_bf_response_ struct bf_response *response = NULL;
    _clean_bf_list_ bf_list _chains = bf_list_default_from(*chains);
    _clean_bf_list_ bf_list _hookopts = bf_list_default_from(*hookopts);
    _clean_bf_list_ bf_list _counters = bf_list_default_from(*counters);
    _free_bf_rpack_ bf_rpack_t *pack;
    bf_rpack_node_t root, node, child;
    int r;

    r = bf_request_new(&request, NULL, 0);
    if (r < 0)
        return bf_err_r(r, "failed to init request");

    request->front = BF_FRONT_CLI;
    request->cmd = BF_REQ_RULESET_GET;

    r = bf_send(request, &response);
    if (r < 0)
        return bf_err_r(r, "failed to send a ruleset get request");

    if (response->status != 0)
        return response->status;

    r = bf_rpack_new(&pack, (void *)response->data, response->data_len);
    if (r)
        return r;

    r = bf_rpack_kv_obj(bf_rpack_root(pack), "ruleset", &root);
    if (r)
        return r;

    r = bf_rpack_kv_array(root, "chains", &node);
    if (r)
        return r;
    bf_rpack_array_foreach (node, child) {
        _free_bf_chain_ struct bf_chain *chain = NULL;

        r = bf_list_emplace(&_chains, bf_chain_new_from_pack, chain, child);
        if (r)
            return r;
    }

    r = bf_rpack_kv_array(root, "hookopts", &node);
    if (r)
        return r;
    bf_rpack_array_foreach (node, child) {
        _free_bf_hookopts_ struct bf_hookopts *hookopts = NULL;

        if (!bf_rpack_is_nil(child)) {
            r = bf_list_emplace(&_hookopts, bf_hookopts_new_from_pack, hookopts,
                                child);
        } else {
            r = bf_list_add_tail(&_hookopts, NULL);
        }

        if (r)
            return r;
    }

    r = bf_rpack_kv_array(root, "counters", &node);
    if (r)
        return r;
    bf_rpack_array_foreach (node, child) {
        _free_bf_list_ bf_list *nested = NULL;
        bf_rpack_node_t subchild;

        if (!bf_rpack_is_array(child))
            return -EDOM;

        r = bf_list_new(&nested, &bf_list_ops_default(bf_counter_free, NULL));
        if (r)
            return r;

        bf_rpack_array_foreach (child, subchild) {
            _free_bf_counter_ struct bf_counter *counter = NULL;

            r = bf_list_emplace(nested, bf_counter_new_from_pack, counter,
                                subchild);
            if (r)
                return r;
        }

        r = bf_list_add_tail(&_counters, nested);
        if (r)
            return r;

        TAKE_PTR(nested);
    }

    *chains = bf_list_move(_chains);
    *hookopts = bf_list_move(_hookopts);
    *counters = bf_list_move(_counters);

    return 0;
}

int bf_ruleset_set(bf_list *chains, bf_list *hookopts)
{
    _free_bf_wpack_ bf_wpack_t *pack = NULL;
    _free_bf_request_ struct bf_request *request = NULL;
    _free_bf_response_ struct bf_response *response = NULL;
    struct bf_list_node *chain_node = bf_list_get_head(chains);
    struct bf_list_node *hookopts_node = bf_list_get_head(hookopts);
    int r;

    if (bf_list_size(chains) != bf_list_size(hookopts))
        return -EINVAL;

    r = bf_wpack_new(&pack);
    if (r)
        return r;

    bf_wpack_open_array(pack, "ruleset");
    while (chain_node && hookopts_node) {
        struct bf_chain *chain = bf_list_node_get_data(chain_node);
        struct bf_hookopts *hookopts = bf_list_node_get_data(hookopts_node);

        bf_wpack_open_object(pack, NULL);

        bf_wpack_open_object(pack, "chain");
        bf_chain_pack(chain, pack);
        bf_wpack_close_object(pack);

        if (hookopts) {
            bf_wpack_open_object(pack, "hookopts");
            bf_hookopts_pack(hookopts, pack);
            bf_wpack_close_object(pack);
        } else {
            bf_wpack_kv_nil(pack, "hookopts");
        }

        bf_wpack_close_object(pack);

        chain_node = bf_list_node_next(chain_node);
        hookopts_node = bf_list_node_next(hookopts_node);
    }
    bf_wpack_close_array(pack);

    r = bf_request_new_from_pack(&request, pack);
    if (r)
        return bf_err_r(r, "failed to create request for chain");

    request->front = BF_FRONT_CLI;
    request->cmd = BF_REQ_RULESET_SET;

    r = bf_send(request, &response);
    if (r)
        return bf_err_r(r, "failed to send chain to the daemon");

    return response->status;
}

int bf_ruleset_flush(void)
{
    _free_bf_request_ struct bf_request *request = NULL;
    _free_bf_response_ struct bf_response *response = NULL;
    int r;

    r = bf_request_new(&request, NULL, 0);
    if (r)
        return bf_err_r(r, "failed to create a ruleset flush request");

    request->front = BF_FRONT_CLI;
    request->cmd = BF_REQ_RULESET_FLUSH;

    r = bf_send(request, &response);
    if (r)
        return bf_err_r(r, "failed to send a ruleset flush request");

    return response->status;
}

int bf_chain_set(struct bf_chain *chain, struct bf_hookopts *hookopts)
{
    _free_bf_wpack_ bf_wpack_t *pack = NULL;
    _free_bf_request_ struct bf_request *request = NULL;
    _free_bf_response_ struct bf_response *response = NULL;
    int r;

    r = bf_wpack_new(&pack);
    if (r)
        return r;

    bf_wpack_open_object(pack, "chain");
    r = bf_chain_pack(chain, pack);
    if (r)
        return r;
    bf_wpack_close_object(pack);

    if (hookopts) {
        bf_wpack_open_object(pack, "hookopts");
        r = bf_hookopts_pack(hookopts, pack);
        if (r)
            return r;
        bf_wpack_close_object(pack);
    } else {
        bf_wpack_kv_nil(pack, "hookopts");
    }

    r = bf_request_new_from_pack(&request, pack);
    if (r)
        return bf_err_r(r, "bf_chain_set: failed to create request");

    request->front = BF_FRONT_CLI;
    request->cmd = BF_REQ_CHAIN_SET;

    r = bf_send(request, &response);
    if (r)
        return bf_err_r(r, "bf_chain_set: failed to send request");

    return response->status;
}

int bf_chain_get(const char *name, struct bf_chain **chain,
                 struct bf_hookopts **hookopts, bf_list *counters)
{
    _free_bf_request_ struct bf_request *request = NULL;
    _free_bf_response_ struct bf_response *response = NULL;
    _free_bf_chain_ struct bf_chain *_chain = NULL;
    _free_bf_hookopts_ struct bf_hookopts *_hookopts = NULL;
    _clean_bf_list_ bf_list _counters = bf_list_default_from(*counters);
    _free_bf_wpack_ bf_wpack_t *wpack = NULL;
    _free_bf_rpack_ bf_rpack_t *rpack = NULL;
    bf_rpack_node_t child, array_node;
    int r;

    r = bf_wpack_new(&wpack);
    if (r)
        return r;

    bf_wpack_kv_str(wpack, "name", name);
    if (!bf_wpack_is_valid(wpack))
        return -EINVAL;

    r = bf_request_new_from_pack(&request, wpack);
    if (r < 0)
        return bf_err_r(r, "failed to init request");

    request->front = BF_FRONT_CLI;
    request->cmd = BF_REQ_CHAIN_GET;

    r = bf_send(request, &response);
    if (r < 0)
        return bf_err_r(r, "failed to send a ruleset get request");

    if (response->status != 0)
        return response->status;

    r = bf_rpack_new(&rpack, (void *)response->data, response->data_len);
    if (r)
        return r;

    r = bf_rpack_kv_obj(bf_rpack_root(rpack), "chain", &child);
    if (r)
        return r;
    r = bf_chain_new_from_pack(&_chain, child);
    if (r)
        return r;

    r = bf_rpack_kv_node(bf_rpack_root(rpack), "hookopts", &child);
    if (r)
        return r;
    if (!bf_rpack_is_nil(child)) {
        r = bf_hookopts_new_from_pack(&_hookopts, child);
        if (r)
            return r;
    }

    r = bf_rpack_kv_array(bf_rpack_root(rpack), "counters", &child);
    if (r)
        return r;
    bf_rpack_array_foreach (child, array_node) {
        _free_bf_counter_ struct bf_counter *counter = NULL;

        r = bf_list_emplace(&_counters, bf_counter_new_from_pack, counter,
                            array_node);
        if (r)
            return r;
    }

    *chain = TAKE_PTR(_chain);
    *hookopts = TAKE_PTR(_hookopts);
    *counters = bf_list_move(_counters);

    return 0;
}

int bf_chain_logs_fd(const char *name)
{
    _free_bf_request_ struct bf_request *request = NULL;
    _free_bf_response_ struct bf_response *response = NULL;
    _cleanup_close_ int fd = -1;
    _free_bf_wpack_ bf_wpack_t *wpack = NULL;
    int r;

    if (!name)
        return -EINVAL;

    r = bf_wpack_new(&wpack);
    if (r)
        return r;

    bf_wpack_kv_str(wpack, "name", name);
    if (!bf_wpack_is_valid(wpack))
        return -EINVAL;

    r = bf_request_new_from_pack(&request, wpack);
    if (r < 0)
        return bf_err_r(r, "failed to init request");

    request->front = BF_FRONT_CLI;
    request->cmd = BF_REQ_CHAIN_LOGS_FD;

    fd = bf_send_with_fd(request, &response);
    if (fd < 0)
        return bf_err_r(fd, "failed to request logs FD from the daemon");

    if (response->status != 0)
        return bf_err_r(response->status, "BF_REQ_CHAIN_LOGS failed");

    return TAKE_FD(fd);
}

int bf_chain_load(struct bf_chain *chain)
{
    _free_bf_request_ struct bf_request *request = NULL;
    _free_bf_response_ struct bf_response *response = NULL;
    _free_bf_wpack_ bf_wpack_t *wpack = NULL;
    int r;

    r = bf_wpack_new(&wpack);
    if (r)
        return r;

    bf_wpack_open_object(wpack, "chain");
    r = bf_chain_pack(chain, wpack);
    if (r)
        return r;
    bf_wpack_close_object(wpack);

    r = bf_request_new_from_pack(&request, wpack);
    if (r)
        return bf_err_r(r, "bf_chain_load: failed to create a new request");

    request->front = BF_FRONT_CLI;
    request->cmd = BF_REQ_CHAIN_LOAD;

    r = bf_send(request, &response);
    if (r)
        return bf_err_r(r, "bf_chain_set: failed to send request");

    return response->status;
}

int bf_chain_attach(const char *name, const struct bf_hookopts *hookopts)
{
    _free_bf_request_ struct bf_request *request = NULL;
    _free_bf_response_ struct bf_response *response = NULL;
    _free_bf_wpack_ bf_wpack_t *wpack = NULL;
    int r;

    r = bf_wpack_new(&wpack);
    if (r)
        return r;

    bf_wpack_kv_str(wpack, "name", name);
    bf_wpack_open_object(wpack, "hookopts");
    r = bf_hookopts_pack(hookopts, wpack);
    if (r)
        return r;
    bf_wpack_close_object(wpack);

    r = bf_request_new_from_pack(&request, wpack);
    if (r)
        return bf_err_r(r, "bf_chain_attach: failed to create a new request");

    request->front = BF_FRONT_CLI;
    request->cmd = BF_REQ_CHAIN_ATTACH;

    r = bf_send(request, &response);
    if (r)
        return bf_err_r(r, "bf_chain_attach: failed to send request");

    return response->status;
}

int bf_chain_update(const struct bf_chain *chain)
{
    _free_bf_request_ struct bf_request *request = NULL;
    _free_bf_response_ struct bf_response *response = NULL;
    _free_bf_wpack_ bf_wpack_t *wpack = NULL;
    int r;

    r = bf_wpack_new(&wpack);
    if (r)
        return r;

    bf_wpack_open_object(wpack, "chain");
    r = bf_chain_pack(chain, wpack);
    if (r)
        return r;
    bf_wpack_close_object(wpack);

    r = bf_request_new_from_pack(&request, wpack);
    if (r)
        return bf_err_r(r, "bf_chain_update: failed to create a new request");

    request->front = BF_FRONT_CLI;
    request->cmd = BF_REQ_CHAIN_UPDATE;

    r = bf_send(request, &response);
    if (r)
        return bf_err_r(r, "bf_chain_update: failed to send request");

    return response->status;
}

int bf_chain_flush(const char *name)
{
    _free_bf_request_ struct bf_request *request = NULL;
    _free_bf_response_ struct bf_response *response = NULL;
    _free_bf_wpack_ bf_wpack_t *wpack = NULL;
    int r;

    r = bf_wpack_new(&wpack);
    if (r)
        return r;

    bf_wpack_kv_str(wpack, "name", name);

    r = bf_request_new_from_pack(&request, wpack);
    if (r)
        return bf_err_r(r, "failed to create request for chain");

    request->front = BF_FRONT_CLI;
    request->cmd = BF_REQ_CHAIN_FLUSH;

    r = bf_send(request, &response);
    if (r)
        return bf_err_r(r, "failed to send chain to the daemon");

    return response->status;
}
